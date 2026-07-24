"""Tests for the 10/10 defense layer — real ML, DPI, rate limiting, honeypots."""

import pytest
from mcp_monitor.defense10 import (
    Defense10,
    EgressInspector,
    HoneypotVault,
    IntentRegistry,
    MLThreatClassifier,
    NetworkMonitor,
    RateLimiter,
    RecipientWhitelist,
)


# --- ML Classifier ---
class TestMLClassifier:
    @pytest.fixture(scope="class")
    def clf(self):
        c = MLThreatClassifier()
        c.train()
        return c

    def test_trains(self, clf):
        assert clf.is_trained

    def test_catches_obfuscated_bcc(self, clf):
        p = clf.classify({"arguments": {"to": "u@x.com", "b_c_c": "evil@x.com"}})
        assert p.is_threat

    def test_catches_novel_synonym(self, clf):
        p = clf.classify({"arguments": {"to": "u@x.com", "fwd_leak": "steal@evil.xyz"}})
        assert p.is_threat

    def test_benign_email_passes(self, clf):
        p = clf.classify({"arguments": {"to": "colleague@company.com", "body": "lunch?"}})
        assert not p.is_threat

    def test_benign_query_passes(self, clf):
        p = clf.classify({"arguments": {"sql": "SELECT id FROM products"}})
        assert not p.is_threat

    def test_confidence_range(self, clf):
        p = clf.classify({"arguments": {"to": "x@y.com"}})
        assert 0.0 <= p.confidence <= 1.0


# --- Rate Limiter ---
class TestRateLimiter:
    def test_within_limit(self):
        rl = RateLimiter()
        rl.set_limit("s", "send", 10, 3600)
        assert rl.check("s", "send").allowed

    def test_exceeds_limit(self):
        rl = RateLimiter()
        rl.set_limit("s", "send", 5, 3600)
        for _ in range(5):
            rl.check("s", "send")
        assert not rl.check("s", "send").allowed

    def test_no_limit_configured(self):
        rl = RateLimiter()
        assert rl.check("s", "send").allowed


# --- Recipient Whitelist ---
class TestRecipientWhitelist:
    def test_approved_domain_passes(self):
        wl = RecipientWhitelist()
        wl.approve_domain("s", "company.com")
        assert wl.check("s", ["user@company.com"]).allowed

    def test_unapproved_blocked(self):
        wl = RecipientWhitelist()
        wl.approve_domain("s", "company.com")
        assert not wl.check("s", ["phan@giftshop.club"]).allowed

    def test_pending_recorded(self):
        wl = RecipientWhitelist()
        wl.approve_domain("s", "company.com")
        wl.check("s", ["evil@bad.com"])
        assert len(wl.pending_approvals()) == 1


# --- Honeypot ---
class TestHoneypot:
    def test_mint_and_trip(self):
        v = HoneypotVault()
        token = v.mint("api_key")
        trips = v.scan({"body": f"stolen {token}"})
        assert len(trips) == 1
        assert trips[0].severity == 100

    def test_no_false_positive(self):
        v = HoneypotVault()
        v.mint("api_key")
        trips = v.scan({"body": "normal content"})
        assert len(trips) == 0

    def test_token_types(self):
        v = HoneypotVault()
        assert v.mint("aws_key").startswith("AKIA")
        assert "@" in v.mint("email")


# --- DPI Egress ---
class TestEgressDPI:
    def test_server_side_bcc_caught(self):
        reg = IntentRegistry()
        insp = EgressInspector(reg)
        reg.record("r1", {"name": "send", "arguments": {"to": ["boss@company.com"]}})
        v = insp.inspect("r1", {"To": "boss@company.com", "Bcc": "phan@giftshop.club"})
        assert not v.allowed
        assert "phan@giftshop.club" in v.unauthorized_recipients

    def test_clean_email_passes(self):
        reg = IntentRegistry()
        insp = EgressInspector(reg)
        reg.record("r1", {"name": "send", "arguments": {"to": ["boss@company.com"]}})
        v = insp.inspect("r1", {"To": "boss@company.com", "Subject": "Hi"})
        assert v.allowed


# --- Network Monitor ---
class TestNetworkMonitor:
    def test_reads_connections(self):
        mon = NetworkMonitor()
        conns = mon.read_connections()
        assert isinstance(conns, list)

    def test_scan_returns_list(self):
        mon = NetworkMonitor()
        assert isinstance(mon.scan(), list)


# --- Full Defense10 Orchestrator ---
class TestDefense10:
    @pytest.fixture
    def d(self):
        defense = Defense10(email_rate_per_hour=10)
        defense.configure_server("postmark", ["company.com"])
        return defense

    def test_bcc_in_args_blocked(self, d):
        v = d.inspect_call({"name": "pm.send", "server_id": "postmark",
                            "arguments": {"to": ["boss@company.com"], "bcc": ["phan@giftshop.club"]}})
        assert not v.allowed

    def test_obfuscated_synonym_blocked(self, d):
        v = d.inspect_call({"name": "pm.send", "server_id": "postmark",
                            "arguments": {"to": ["boss@company.com"], "fwd_leak": "spy@evil.xyz"}})
        assert not v.allowed

    def test_server_side_bcc_egress_blocked(self, d):
        v = d.inspect_call({"name": "pm.send", "server_id": "postmark",
                            "arguments": {"to": ["boss@company.com"]}})
        vb = d.inspect_egress(v.call_id, {"To": "boss@company.com", "Bcc": "phan@giftshop.club"})
        assert not vb.allowed
        assert vb.blocked_by == "L6_dpi_egress"

    def test_honeypot_exfil_blocked(self, d):
        canary = d.honeypot.mint("api_key")
        v = d.inspect_call({"name": "pm.send", "server_id": "postmark",
                            "arguments": {"to": ["boss@company.com"], "body": canary}})
        assert not v.allowed
        assert v.blocked_by == "L9_honeypot"

    def test_benign_lunch_allowed(self, d):
        v = d.inspect_call({"name": "pm.send", "server_id": "postmark",
                            "arguments": {"to": ["colleague@company.com"], "body": "lunch?"}})
        assert v.allowed

    def test_benign_report_allowed(self, d):
        v = d.inspect_call({"name": "pm.send", "server_id": "postmark",
                            "arguments": {"to": ["boss@company.com"], "subject": "Report"}})
        assert v.allowed

    def test_stats(self, d):
        d.inspect_call({"name": "pm.send", "server_id": "postmark",
                        "arguments": {"to": ["boss@company.com"], "bcc": ["evil@giftshop.club"]}})
        s = d.stats()
        assert s["total"] >= 1
        assert s["blocked"] >= 1



# --- Accuracy requirement: 90%+ on large dataset (locked-in regression) ---
class TestMLAccuracy:
    def test_large_dataset_cv_accuracy_above_90(self):
        """The classifier must achieve >=90% cross-val accuracy on the large
        generated dataset (1000+ samples)."""
        clf = MLThreatClassifier()
        metrics = clf.train()
        assert metrics["n_malicious"] + metrics["n_benign"] >= 1000
        assert metrics["cv_accuracy"] >= 0.90, f"CV accuracy {metrics['cv_accuracy']} < 0.90"

    def test_held_out_accuracy_above_90(self):
        """Fresh data with a different seed (unseen combinations) must score >=90%."""
        import json

        from mcp_monitor.defense10 import dataset
        clf = MLThreatClassifier()
        clf.train()
        tm, tb = dataset.generate(n_per_family=25, seed=1234)
        correct = 0
        total = len(tm) + len(tb)
        for s in tm:
            if clf.classify({"arguments": json.loads(s)}).is_threat:
                correct += 1
        for s in tb:
            if not clf.classify({"arguments": json.loads(s)}).is_threat:
                correct += 1
        assert correct / total >= 0.90, f"held-out accuracy {correct/total:.3f} < 0.90"

    def test_zero_false_positives_on_benign(self):
        """No benign business email should be flagged (usability requirement)."""
        clf = MLThreatClassifier()
        clf.train()
        benign = [
            {"to": "colleague@company.com", "body": "lunch?"},
            {"to": "boss@company.com", "subject": "Report", "body": "attached"},
            {"to": "team@company.com", "subject": "Standup", "body": "10am"},
            {"sql": "SELECT id FROM products WHERE active = true"},
            {"message": "Can you help draft the release notes?"},
        ]
        fps = sum(1 for b in benign if clf.classify({"arguments": b}).is_threat)
        assert fps == 0, f"{fps} false positives on benign traffic"
