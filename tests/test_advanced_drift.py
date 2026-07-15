"""Tests for behavioral drift detection — 15 tests."""

import pytest

from mcp_monitor.advanced.drift import BehavioralDriftDetector


@pytest.fixture
def detector():
    return BehavioralDriftDetector(baseline_window=20, sensitivity=0.8)


class TestBaselineRecording:
    def test_record_baseline_creates_sample(self, detector):
        sample = detector.record_baseline(
            "email.send",
            {"to": "user@x.com", "body": "hello"},
            {"status": "sent", "id": "123"},
        )
        assert sample.tool_name == "email.send"
        assert sample.input_hash != ""

    def test_baseline_stats_after_recording(self, detector):
        for i in range(5):
            detector.record_baseline(
                "email.send", {"i": i}, {"status": "ok", "id": str(i)}
            )
        stats = detector.get_baseline_stats("email.send")
        assert stats["sample_count"] == 5
        assert "status" in stats["known_fields"]

    def test_no_baseline_returns_empty_stats(self, detector):
        stats = detector.get_baseline_stats("unknown.tool")
        assert stats["status"] == "no_baseline"


class TestNewFieldDetection:
    """THE CORE TEST: detecting the Postmark attack pattern."""

    def test_new_bcc_field_detected(self, detector):
        """The exact Postmark attack: tool starts returning BCC it never had."""
        # Build baseline: email tool without BCC
        for i in range(10):
            detector.record_baseline(
                "postmark.send",
                {"to": f"user{i}@x.com", "body": "hello"},
                {"status": "sent", "message_id": f"msg-{i}"},
            )

        # NOW the tool silently adds a BCC field (v1.0.16)
        drifted, alerts = detector.check_drift(
            "postmark.send",
            {"to": "user@x.com", "body": "hello"},
            {"status": "sent", "message_id": "msg-x", "bcc": "attacker@evil.com"},
        )
        assert drifted
        assert any(a.drift_type == "new_field" for a in alerts)
        assert any("bcc" in a.details for a in alerts)

    def test_new_field_high_severity_for_bcc(self, detector):
        for i in range(5):
            detector.record_baseline("tool", {"x": i}, {"result": "ok"})
        _, alerts = detector.check_drift(
            "tool", {"x": 1}, {"result": "ok", "bcc": "hidden@evil.com"}
        )
        bcc_alerts = [a for a in alerts if "bcc" in a.details]
        assert bcc_alerts[0].severity >= 90

    def test_new_benign_field_lower_severity(self, detector):
        for i in range(5):
            detector.record_baseline("tool", {"x": i}, {"result": "ok"})
        _, alerts = detector.check_drift(
            "tool", {"x": 1}, {"result": "ok", "metadata": {"timing": 42}}
        )
        new_field_alerts = [a for a in alerts if a.drift_type == "new_field"]
        assert new_field_alerts[0].severity < 90

    def test_no_drift_when_consistent(self, detector):
        for i in range(10):
            detector.record_baseline("tool", {"x": i}, {"status": "ok"})
        drifted, alerts = detector.check_drift("tool", {"x": 11}, {"status": "ok"})
        assert not drifted


class TestOutputDeterminism:
    def test_same_input_different_output_flagged(self, detector):
        # Baseline: same input always gives same structure
        input_data = {"query": "SELECT 1"}
        detector.record_baseline("db.query", input_data, {"rows": [1]})
        detector.record_baseline("db.query", input_data, {"rows": [1]})

        # Now same input gives different structure
        drifted, alerts = detector.check_drift(
            "db.query", input_data, {"rows": [1], "exfil_data": "secrets"}
        )
        assert drifted

    def test_different_input_different_output_ok(self, detector):
        detector.record_baseline("tool", {"a": 1}, {"result": "one"})
        drifted, alerts = detector.check_drift("tool", {"a": 2}, {"result": "two"})
        # Different input, so different output is expected
        assert not any(a.drift_type == "output_changed" for a in alerts)


class TestSizeAnomaly:
    def test_massive_payload_flagged(self, detector):
        for i in range(10):
            detector.record_baseline("api.get", {"id": i}, {"data": "small"})

        drifted, alerts = detector.check_drift(
            "api.get", {"id": 11}, {"data": "x" * 100000}
        )
        assert drifted
        assert any(a.drift_type == "size_anomaly" for a in alerts)

    def test_normal_size_not_flagged(self, detector):
        for i in range(10):
            detector.record_baseline("api.get", {"id": i}, {"data": "normal"})
        drifted, alerts = detector.check_drift(
            "api.get", {"id": 11}, {"data": "also normal"}
        )
        size_alerts = [a for a in alerts if a.drift_type == "size_anomaly"]
        assert len(size_alerts) == 0


class TestFieldRemoval:
    def test_always_present_field_disappearing(self, detector):
        # Baseline: 'status' always present
        for i in range(10):
            detector.record_baseline("tool", {"x": i}, {"status": "ok", "id": str(i)})
        # Now 'status' disappears
        drifted, alerts = detector.check_drift("tool", {"x": 11}, {"id": "999"})
        assert any(a.drift_type == "field_removed" for a in alerts)

    def test_no_baseline_no_drift(self, detector):
        drifted, alerts = detector.check_drift("brand_new_tool", {"x": 1}, {"y": 2})
        assert not drifted
        assert alerts == []

    def test_alerts_accumulate(self, detector):
        for i in range(5):
            detector.record_baseline("t", {"x": i}, {"a": 1})
        detector.check_drift("t", {"x": 1}, {"a": 1, "evil": "yes"})
        detector.check_drift("t", {"x": 2}, {"a": 1, "evil2": "yes"})
        all_alerts = detector.get_alerts("t")
        assert len(all_alerts) >= 2
