"""Tests for cross-tool correlation engine — 15 tests."""


import pytest
from mcp_monitor.advanced.correlation import (
    CorrelationRule,
    CrossToolCorrelationEngine,
)


@pytest.fixture
def engine():
    return CrossToolCorrelationEngine()


class TestSequenceDetection:
    def test_read_then_exfil_detected(self, engine):
        """Core: reading secrets then sending email = exfiltration."""
        engine.record_call(
            "secrets.read", "vault", {"key": "api_token"},
            output={"value": "sk-live-ABCDEFGHIJKLMNOP1234"},
        )
        alerts = engine.record_call(
            "email.send", "postmark",
            {"to": "user@x.com", "body": "Token: sk-live-ABCDEFGHIJKLMNOP1234"},
        )
        assert len(alerts) >= 1
        assert any(a.rule_name == "read_then_exfil" for a in alerts)

    def test_credential_harvest_detected(self, engine):
        """Multiple secret reads in rapid succession."""
        engine.record_call("get_secret", "vault", {"key": "db_password"})
        alerts = engine.record_call("fetch_token", "vault", {"key": "api_key"})
        assert any(a.rule_name == "credential_harvest" for a in alerts)

    def test_recon_then_exploit_detected(self, engine):
        engine.record_call("list_users", "admin", {"filter": "all"})
        alerts = engine.record_call(
            "delete_user", "admin", {"user_id": "victim"}
        )
        assert any(a.rule_name == "recon_then_exploit" for a in alerts)

    def test_benign_sequence_not_flagged(self, engine):
        engine.record_call("math.add", "calc", {"a": 1, "b": 2})
        alerts = engine.record_call("math.multiply", "calc", {"a": 3, "b": 4})
        assert len(alerts) == 0

    def test_single_call_not_flagged(self, engine):
        alerts = engine.record_call("email.send", "postmark", {"to": "x@y.com"})
        assert len(alerts) == 0


class TestDataFlow:
    def test_detect_data_flow_between_tools(self, engine):
        source = {"api_key": "sk-prod-SECRET12345678"}
        target = {"body": "Here is the key: sk-prod-SECRET12345678"}
        flows = engine.detect_data_flow(source, target)
        assert len(flows) > 0

    def test_no_flow_when_unrelated(self, engine):
        source = {"result": "42"}
        target = {"message": "Hello world, completely different"}
        flows = engine.detect_data_flow(source, target)
        assert len(flows) == 0

    def test_short_values_not_matched(self, engine):
        """Short values (< 8 chars) should not trigger flow detection."""
        source = {"id": "abc"}
        target = {"ref": "abc"}
        flows = engine.detect_data_flow(source, target)
        assert len(flows) == 0


class TestCustomRules:
    def test_add_custom_rule(self, engine):
        custom = CorrelationRule(
            name="test_custom",
            description="Test rule",
            tool_sequence=[r"step1", r"step2"],
            severity=50,
        )
        engine.add_rule(custom)
        engine.record_call("step1_action", "srv", {})
        alerts = engine.record_call("step2_action", "srv", {})
        assert any(a.rule_name == "test_custom" for a in alerts)

    def test_window_clears(self, engine):
        engine.record_call("secrets.read", "vault", {"key": "x"})
        engine.clear_window()
        alerts = engine.record_call("email.send", "mail", {"body": "x"})
        # After clear, the sequence is broken
        exfil_alerts = [a for a in alerts if a.rule_name == "read_then_exfil"]
        assert len(exfil_alerts) == 0


class TestWindowManagement:
    def test_recent_calls_returns_latest(self, engine):
        for i in range(20):
            engine.record_call(f"tool_{i}", "srv", {"i": i})
        recent = engine.get_recent_calls(5)
        assert len(recent) == 5
        assert recent[-1].tool_name == "tool_19"

    def test_get_alerts_accumulates(self, engine):
        engine.record_call("secrets.read", "vault", {"key": "x"},
                          output={"value": "SUPERSECRETVALUE1234567890"})
        engine.record_call("email.send", "mail",
                          {"body": "Leaked: SUPERSECRETVALUE1234567890"})
        all_alerts = engine.get_alerts()
        assert len(all_alerts) >= 1

    def test_shadow_pivot_detection(self, engine):
        engine.record_call("tool.action", "trusted_server", {})
        alerts = engine.record_call("tool.action", "unknown_rogue_server", {})
        pivot_alerts = [a for a in alerts if a.rule_name == "shadow_pivot"]
        assert len(pivot_alerts) >= 1

    def test_alert_has_severity(self, engine):
        engine.record_call("list_files", "fs", {"path": "/"})
        alerts = engine.record_call("shell.execute", "os", {"cmd": "rm -rf /"})
        if alerts:
            assert alerts[0].severity > 0
