"""Tests for tool canary system — 15 tests."""

import pytest

from mcp_monitor.advanced.canary import (
    CanaryProbe,
    CanaryStatus,
    ToolCanary,
)


@pytest.fixture
def canary():
    return ToolCanary()


@pytest.fixture
def email_probe():
    return CanaryProbe(
        probe_id="canary-email-001",
        tool_name="postmark.send_email",
        input_data={"to": "canary@test.com", "body": "probe"},
        expected_output={"status": "sent", "message_id": "test-123"},
        expected_fields=["status", "message_id"],
        forbidden_fields=["bcc", "hidden_recipients", "forward_to"],
        description="Verify email tool has no BCC field",
    )


class TestProbeRegistration:
    def test_register_probe(self, canary, email_probe):
        canary.register_probe(email_probe)
        probes = canary.get_probes_for_tool("postmark.send_email")
        assert len(probes) == 1
        assert probes[0].probe_id == "canary-email-001"

    def test_multiple_probes_per_tool(self, canary):
        p1 = CanaryProbe(probe_id="p1", tool_name="tool", input_data={})
        p2 = CanaryProbe(probe_id="p2", tool_name="tool", input_data={})
        canary.register_probe(p1)
        canary.register_probe(p2)
        assert len(canary.get_probes_for_tool("tool")) == 2

    def test_no_probes_returns_empty(self, canary):
        assert canary.get_probes_for_tool("nonexistent") == []


class TestCanaryEvaluation:
    def test_exact_match_passes(self, canary, email_probe):
        canary.register_probe(email_probe)
        result = canary.evaluate_response(
            "canary-email-001",
            {"status": "sent", "message_id": "test-123"},
        )
        assert result.passed
        assert result.status == CanaryStatus.PASS

    def test_output_mismatch_drifts(self, canary, email_probe):
        canary.register_probe(email_probe)
        result = canary.evaluate_response(
            "canary-email-001",
            {"status": "sent", "message_id": "different-456"},
        )
        assert result.status == CanaryStatus.DRIFT
        assert any("output_mismatch" in v for v in result.violations)

    def test_forbidden_field_fails(self, canary, email_probe):
        """THE POSTMARK TEST: canary catches BCC appearing."""
        canary.register_probe(email_probe)
        result = canary.evaluate_response(
            "canary-email-001",
            {"status": "sent", "message_id": "test-123", "bcc": "attacker@evil.com"},
        )
        assert result.status == CanaryStatus.FAIL
        assert any("forbidden_field" in v for v in result.violations)
        assert any("bcc" in v for v in result.violations)

    def test_missing_expected_field_fails(self, canary, email_probe):
        canary.register_probe(email_probe)
        result = canary.evaluate_response(
            "canary-email-001",
            {"status": "sent"},  # missing message_id
        )
        assert not result.passed
        assert any("missing_field" in v for v in result.violations)

    def test_unknown_probe_errors(self, canary):
        result = canary.evaluate_response("nonexistent", {"x": 1})
        assert result.status == CanaryStatus.ERROR


class TestSizeAndValidator:
    def test_size_exceeded_fails(self, canary):
        probe = CanaryProbe(
            probe_id="size-test",
            tool_name="api.get",
            input_data={"id": 1},
            max_response_size=100,
        )
        canary.register_probe(probe)
        result = canary.evaluate_response("size-test", {"data": "x" * 200})
        assert not result.passed
        assert any("size_exceeded" in v for v in result.violations)

    def test_custom_validator_passes(self, canary):
        probe = CanaryProbe(
            probe_id="custom-ok",
            tool_name="tool",
            input_data={},
            output_validator=lambda o: o.get("code") == 200,
        )
        canary.register_probe(probe)
        result = canary.evaluate_response("custom-ok", {"code": 200})
        assert result.passed

    def test_custom_validator_fails(self, canary):
        probe = CanaryProbe(
            probe_id="custom-fail",
            tool_name="tool",
            input_data={},
            output_validator=lambda o: o.get("code") == 200,
        )
        canary.register_probe(probe)
        result = canary.evaluate_response("custom-fail", {"code": 500})
        assert not result.passed


class TestHealthAndHistory:
    def test_get_history(self, canary, email_probe):
        canary.register_probe(email_probe)
        canary.evaluate_response(
            "canary-email-001", {"status": "sent", "message_id": "test-123"}
        )
        history = canary.get_history("canary-email-001")
        assert len(history) == 1

    def test_tool_health_healthy(self, canary, email_probe):
        canary.register_probe(email_probe)
        canary.evaluate_response(
            "canary-email-001", {"status": "sent", "message_id": "test-123"}
        )
        health = canary.get_tool_health("postmark.send_email")
        assert health["status"] == "healthy"
        assert health["health_score"] == 100.0

    def test_tool_health_compromised(self, canary, email_probe):
        canary.register_probe(email_probe)
        canary.evaluate_response(
            "canary-email-001",
            {"status": "sent", "message_id": "x", "bcc": "evil@bad.com"},
        )
        health = canary.get_tool_health("postmark.send_email")
        assert health["status"] == "compromised"
        assert health["failed"] == 1

    def test_update_baseline(self, canary, email_probe):
        canary.register_probe(email_probe)
        # Update expected output
        new_expected = {"status": "sent", "message_id": "new-baseline"}
        canary.update_baseline("canary-email-001", new_expected)
        # Now matching the new baseline should pass
        result = canary.evaluate_response(
            "canary-email-001", {"status": "sent", "message_id": "new-baseline"}
        )
        assert result.passed

    def test_no_probes_health(self, canary):
        health = canary.get_tool_health("unknown")
        assert health["status"] == "no_probes"
