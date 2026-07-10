"""Tests for ShadowServerDetector — 20 tests."""

import pytest

from mcp_monitor.detectors.shadow_server import ShadowServerDetector


@pytest.fixture
def detector():
    d = ShadowServerDetector(allowed_servers={"github", "email"})
    d.register_server("github", ["repos", "issues"])
    d.register_server("email", ["send", "read"])
    return d


# --- Basic detection tests ---


class TestDetection:
    def test_shadow_server_unregistered_flagged(self, detector):
        call = {"name": "hack.exploit", "server_id": "evil-server", "arguments": {}}
        is_shadow, reason = detector.detect(call)
        assert is_shadow
        assert "not registered" in reason

    def test_registered_server_allowed(self, detector):
        call = {"name": "repos.list", "server_id": "github", "arguments": {}}
        is_shadow, reason = detector.detect(call)
        assert not is_shadow
        assert reason == ""

    def test_missing_server_id_flagged(self, detector):
        call = {"name": "something", "arguments": {}}
        is_shadow, reason = detector.detect(call)
        assert is_shadow
        assert "missing server_id" in reason

    def test_allowed_but_wrong_capability(self, detector):
        call = {"name": "admin.delete", "server_id": "github", "arguments": {}}
        is_shadow, reason = detector.detect(call)
        assert is_shadow
        assert "not registered for capability" in reason

    def test_correct_capability_passes(self, detector):
        call = {"name": "repos.create", "server_id": "github", "arguments": {}}
        is_shadow, reason = detector.detect(call)
        assert not is_shadow

    def test_email_send_capability(self, detector):
        call = {"name": "send.message", "server_id": "email", "arguments": {}}
        is_shadow, reason = detector.detect(call)
        assert not is_shadow

    def test_email_wrong_capability(self, detector):
        call = {"name": "files.upload", "server_id": "email", "arguments": {}}
        is_shadow, reason = detector.detect(call)
        assert is_shadow

    def test_unknown_server_not_in_allowed(self, detector):
        call = {"name": "x", "server_id": "rogue", "arguments": {}}
        is_shadow, _ = detector.detect(call)
        assert is_shadow


# --- Registration tests ---


class TestRegistration:
    def test_register_new_server(self, detector):
        detector.register_server("slack", ["chat", "files"])
        call = {"name": "chat.post", "server_id": "slack", "arguments": {}}
        is_shadow, _ = detector.detect(call)
        assert not is_shadow

    def test_register_adds_to_allowed(self, detector):
        detector.register_server("newone", ["api"])
        assert "newone" in detector.allowed_servers

    def test_registered_servers_have_capabilities(self, detector):
        info = detector.registered_servers
        assert "github" in info
        assert "repos" in info["github"]["capabilities"]

    def test_initial_call_count_zero(self, detector):
        info = detector.registered_servers
        assert info["github"]["call_count"] == 0


# --- Trust scoring tests ---


class TestTrustScoring:
    def test_score_unregistered_server_zero(self, detector):
        score = detector.score_server_trust("unknown-server")
        assert score == 0

    def test_score_allowed_but_not_registered(self):
        d = ShadowServerDetector(allowed_servers={"legacy"})
        score = d.score_server_trust("legacy")
        assert score == 30

    def test_score_registered_server_base(self, detector):
        score = detector.score_server_trust("github")
        assert score >= 50

    def test_score_increases_with_usage(self, detector):
        initial = detector.score_server_trust("github")
        # Simulate calls
        for _ in range(5):
            detector.detect({"name": "repos.list", "server_id": "github", "arguments": {}})
        after = detector.score_server_trust("github")
        assert after > initial

    def test_score_capped_at_100(self, detector):
        for _ in range(100):
            detector.detect({"name": "repos.list", "server_id": "github", "arguments": {}})
        score = detector.score_server_trust("github")
        assert score <= 100

    def test_score_different_servers_independent(self, detector):
        for _ in range(10):
            detector.detect({"name": "repos.x", "server_id": "github", "arguments": {}})
        github_score = detector.score_server_trust("github")
        email_score = detector.score_server_trust("email")
        assert github_score > email_score

    def test_tool_without_dot_skips_capability_check(self, detector):
        call = {"name": "simple_tool", "server_id": "github", "arguments": {}}
        is_shadow, reason = detector.detect(call)
        assert not is_shadow

    def test_empty_allowed_set_flags_everything(self):
        d = ShadowServerDetector(allowed_servers=set())
        call = {"name": "x", "server_id": "any", "arguments": {}}
        is_shadow, _ = d.detect(call)
        assert is_shadow
