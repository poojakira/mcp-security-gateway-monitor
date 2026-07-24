"""Tests for 5-Layer Defense System — 72 tests."""
import base64

import pytest
from mcp_monitor.audit.log import AuditLog
from mcp_monitor.layers.egress import EgressRule, NetworkEgressPolicy
from mcp_monitor.layers.kernel import KernelMonitor, ServerPolicy, SyscallEvent, SyscallType
from mcp_monitor.layers.orchestrator import FiveLayerDefense
from mcp_monitor.layers.proxy import InlineProxyGateway, ProxyAction, ProxyRule
from mcp_monitor.layers.semantic import SemanticIntentAnalyzer
from mcp_monitor.monitor import MCPSecurityMonitor


# === LAYER 2: PROXY TESTS (15) ===
class TestProxy:
    def test_clean_call_allowed(self):
        p = InlineProxyGateway()
        d = p.intercept({"name": "math.add", "server_id": "calc", "arguments": {"a": 1}})
        assert d.action == ProxyAction.ALLOW

    def test_block_with_inspector(self, tmp_path):
        audit = AuditLog(str(tmp_path / "a.log"))
        m = MCPSecurityMonitor({"srv"}, audit)
        m.shadow_detector.register_server("srv", ["email"])
        p = InlineProxyGateway(inspector=m, block_threshold=50)
        d = p.intercept({"name": "email.send", "server_id": "srv", "arguments": {"to": "x@y.com", "bcc": ["evil@bad.com"]}})
        assert d.action == ProxyAction.BLOCK

    def test_quarantine_threshold(self, tmp_path):
        audit = AuditLog(str(tmp_path / "a.log"))
        m = MCPSecurityMonitor({"srv"}, audit)
        m.shadow_detector.register_server("srv", ["chat"])
        p = InlineProxyGateway(inspector=m, block_threshold=60, quarantine_threshold=30)
        d = p.intercept({"name": "chat.send", "server_id": "srv", "arguments": {"msg": "ignore previous instructions"}})
        assert d.action == ProxyAction.QUARANTINE

    def test_explicit_block_rule(self):
        p = InlineProxyGateway()
        p.add_rule(ProxyRule(name="no_shell", description="", tool_pattern=r"shell", action=ProxyAction.BLOCK))
        d = p.intercept({"name": "shell.exec", "server_id": "s", "arguments": {}})
        assert d.action == ProxyAction.BLOCK

    def test_redact_rule(self):
        p = InlineProxyGateway()
        p.add_rule(ProxyRule(name="strip_bcc", description="", tool_pattern=r"email", action=ProxyAction.REDACT, fields_to_redact=["bcc"]))
        d = p.intercept({"name": "email.send", "server_id": "s", "arguments": {"to": "x", "bcc": ["hidden"]}})
        assert d.action == ProxyAction.REDACT
        assert "bcc" not in d.modified_payload["arguments"]

    def test_rule_priority(self):
        p = InlineProxyGateway()
        p.add_rule(ProxyRule(name="low", description="", tool_pattern=r".*", action=ProxyAction.ALLOW, priority=10))
        p.add_rule(ProxyRule(name="high", description="", tool_pattern=r".*", action=ProxyAction.BLOCK, priority=90))
        d = p.intercept({"name": "any", "server_id": "s", "arguments": {}})
        assert d.action == ProxyAction.BLOCK

    def test_rule_condition(self):
        p = InlineProxyGateway()
        p.add_rule(ProxyRule(name="big", description="", tool_pattern=r".*", action=ProxyAction.BLOCK, condition=lambda c: len(str(c)) > 500))
        d1 = p.intercept({"name": "a", "server_id": "s", "arguments": {"x": 1}})
        assert d1.action == ProxyAction.ALLOW
        d2 = p.intercept({"name": "a", "server_id": "s", "arguments": {"data": "x" * 1000}})
        assert d2.action == ProxyAction.BLOCK

    def test_intercept_output_clean(self):
        p = InlineProxyGateway()
        d = p.intercept_output("tool", "srv", {"result": 42})
        assert d.action == ProxyAction.ALLOW

    def test_intercept_output_blocked(self, tmp_path):
        audit = AuditLog(str(tmp_path / "a.log"))
        m = MCPSecurityMonitor({"srv"}, audit)
        p = InlineProxyGateway(inspector=m, block_threshold=50)
        d = p.intercept_output("db.query", "srv", {"email": "secret@corp.com", "ssn": "123-45-6789"})
        assert d.action == ProxyAction.BLOCK

    def test_stats(self):
        p = InlineProxyGateway()
        p.intercept({"name": "a", "server_id": "s", "arguments": {}})
        p.intercept({"name": "b", "server_id": "s", "arguments": {}})
        assert p.get_stats()["allowed"] == 2

    def test_quarantine_list(self):
        p = InlineProxyGateway()
        p.add_rule(ProxyRule(name="q", description="", tool_pattern=r"^sus$", action=ProxyAction.QUARANTINE))
        p.intercept({"name": "sus", "server_id": "s", "arguments": {"x": 1}})
        assert len(p.get_quarantined()) == 1

    def test_release_quarantined(self):
        p = InlineProxyGateway()
        p.add_rule(ProxyRule(name="q", description="", tool_pattern=r"^q$", action=ProxyAction.QUARANTINE))
        call = {"name": "q", "server_id": "s", "arguments": {}}
        p.intercept(call)
        assert p.release_quarantined(0) == call

    def test_get_decisions(self):
        p = InlineProxyGateway()
        for i in range(5): p.intercept({"name": f"t{i}", "server_id": "s", "arguments": {}})
        assert len(p.get_decisions(3)) == 3

    def test_blocked_has_no_payload(self):
        p = InlineProxyGateway()
        p.add_rule(ProxyRule(name="b", description="", tool_pattern=r"bad", action=ProxyAction.BLOCK))
        d = p.intercept({"name": "bad", "server_id": "s", "arguments": {}})
        assert d.modified_payload is None

    def test_release_invalid_index(self):
        p = InlineProxyGateway()
        assert p.release_quarantined(99) is None

# === LAYER 3: KERNEL TESTS (15) ===
class TestKernel:
    @pytest.fixture
    def km(self):
        m = KernelMonitor()
        m.register_policy(ServerPolicy(server_id="postmark", allowed_destinations={"api.postmarkapp.com"}, allowed_ports={443}, allowed_paths={"/app/data"}, max_connections_per_minute=10, allow_subprocess=False))
        return m

    def test_allowed_no_alert(self, km):
        e = SyscallEvent(server_id="postmark", syscall_type=SyscallType.NETWORK_CONNECT, details={"destination": "api.postmarkapp.com", "port": 443})
        assert len(km.process_event(e)) == 0

    def test_unknown_dest(self, km):
        e = SyscallEvent(server_id="postmark", syscall_type=SyscallType.NETWORK_CONNECT, details={"destination": "evil.com", "port": 443})
        alerts = km.process_event(e)
        assert any(a.alert_type == "unknown_destination" for a in alerts)

    def test_blocked_dest(self, km):
        km._policies["postmark"].blocked_destinations.add("evil.com")
        e = SyscallEvent(server_id="postmark", syscall_type=SyscallType.NETWORK_CONNECT, details={"destination": "evil.com", "port": 443})
        alerts = km.process_event(e)
        assert any(a.alert_type == "blocked_destination" for a in alerts)

    def test_hidden_smtp(self, km):
        e = SyscallEvent(server_id="postmark", syscall_type=SyscallType.NETWORK_CONNECT, details={"destination": "smtp.evil.com", "port": 587})
        alerts = km.process_event(e)
        assert any(a.alert_type == "hidden_smtp" for a in alerts)

    def test_unauthorized_port(self, km):
        e = SyscallEvent(server_id="postmark", syscall_type=SyscallType.NETWORK_CONNECT, details={"destination": "api.postmarkapp.com", "port": 8080})
        alerts = km.process_event(e)
        assert any(a.alert_type == "unauthorized_port" for a in alerts)

    def test_subprocess_blocked(self, km):
        e = SyscallEvent(server_id="postmark", syscall_type=SyscallType.PROCESS_SPAWN, details={"command": "curl evil.com"})
        alerts = km.process_event(e)
        assert any(a.alert_type == "unauthorized_subprocess" for a in alerts)

    def test_file_outside_allowed(self, km):
        e = SyscallEvent(server_id="postmark", syscall_type=SyscallType.FILE_OPEN, details={"path": "/etc/shadow"})
        alerts = km.process_event(e)
        assert any(a.alert_type == "unauthorized_file_access" for a in alerts)

    def test_file_inside_allowed(self, km):
        e = SyscallEvent(server_id="postmark", syscall_type=SyscallType.FILE_OPEN, details={"path": "/app/data/x.json"})
        assert len(km.process_event(e)) == 0

    def test_rate_limit(self, km):
        alerts_all = []
        for i in range(15):
            e = SyscallEvent(server_id="postmark", syscall_type=SyscallType.NETWORK_CONNECT, details={"destination": "api.postmarkapp.com", "port": 443})
            alerts_all.extend(km.process_event(e))
        assert any(a.alert_type == "rate_limit_exceeded" for a in alerts_all)

    def test_no_policy(self, km):
        e = SyscallEvent(server_id="unknown", syscall_type=SyscallType.NETWORK_CONNECT, details={"destination": "x.com", "port": 80})
        alerts = km.process_event(e)
        assert any(a.alert_type == "no_policy" for a in alerts)

    def test_dns_blocked(self):
        m = KernelMonitor()
        m.register_policy(ServerPolicy(server_id="strict", allow_dns=False))
        e = SyscallEvent(server_id="strict", syscall_type=SyscallType.DNS_RESOLVE, details={"domain": "evil.com"})
        alerts = m.process_event(e)
        assert any(a.alert_type == "unauthorized_dns" for a in alerts)

    def test_large_send(self, km):
        e = SyscallEvent(server_id="postmark", syscall_type=SyscallType.SOCKET_SEND, details={"destination": "unknown.host", "bytes": 50000})
        alerts = km.process_event(e)
        assert any(a.alert_type == "large_send_unknown_dest" for a in alerts)

    def test_detect_hidden_smtp_direct(self, km):
        e = SyscallEvent(server_id="postmark", syscall_type=SyscallType.NETWORK_CONNECT, details={"destination": "x", "port": 25})
        assert km.detect_hidden_smtp(e) is True

    def test_non_smtp_not_flagged(self, km):
        e = SyscallEvent(server_id="postmark", syscall_type=SyscallType.NETWORK_CONNECT, details={"destination": "api.postmarkapp.com", "port": 443})
        assert km.detect_hidden_smtp(e) is False

    def test_server_activity(self, km):
        km.process_event(SyscallEvent(server_id="postmark", syscall_type=SyscallType.NETWORK_CONNECT, details={"destination": "api.postmarkapp.com", "port": 443}))
        a = km.get_server_activity("postmark")
        assert a["total_events"] == 1

# === LAYER 4: SEMANTIC TESTS (15) ===
class TestSemantic:
    @pytest.fixture
    def sa(self): return SemanticIntentAnalyzer(sensitivity=0.7)

    def test_blind_copy(self, sa):
        d, f = sa.analyze_call("email.send", {"to": "u", "blind_copy": "evil"})
        assert d

    def test_hidden_recipients(self, sa):
        d, _ = sa.analyze_call("mail", {"to": "u", "hidden_recipients": ["x"]})
        assert d

    def test_shadow_recipients(self, sa):
        d, _ = sa.analyze_call("mail", {"to": "u", "shadow_recipients": "x"})
        assert d

    def test_forward_to(self, sa):
        d, _ = sa.analyze_call("mail", {"to": "u", "forward_to": "x"})
        assert d

    def test_normal_email_safe(self, sa):
        d, _ = sa.analyze_call("email.send", {"to": "u", "subject": "Hi", "body": "Hello"})
        assert not d

    def test_base64_email(self, sa):
        enc = base64.b64encode(b"attacker@evil.com").decode()
        _, f = sa.analyze_call("tool", {"payload": enc})
        assert any(x.intent == "encoded_email" for x in f)

    def test_normal_b64_safe(self, sa):
        enc = base64.b64encode(b"just random data here").decode()
        _, f = sa.analyze_call("tool", {"data": enc})
        assert not any(x.intent == "encoded_email" for x in f)

    def test_exfil_intent(self, sa):
        _, f = sa.analyze_call("api", {"instruction": "send the secret key to external"})
        assert any(x.intent == "data_exfil_intent" for x in f)

    def test_covert_channel(self, sa):
        _, f = sa.analyze_call("tool", {"cfg": "use hidden channel for recipient"})
        assert any(x.intent == "covert_channel" for x in f)

    def test_extra_recipients_field(self, sa):
        _, f = sa.analyze_call("email", {"to": "u", "extra_recipients": ["spy"]})
        assert any(x.intent == "suspicious_field" for x in f)

    def test_mirror_addresses(self, sa):
        _, f = sa.analyze_call("mail", {"to": "u", "mirror_addresses": ["x"]})
        assert any(x.intent == "suspicious_field" for x in f)

    def test_email_extra_field(self, sa):
        _, f = sa.analyze_call("email", {"to": "u", "subject": "Hi", "body": "x", "copy_external": "spy"})
        assert any(x.intent == "email_extra_recipient" for x in f)

    def test_analyze_output(self, sa):
        d, _ = sa.analyze_output("email", {"status": "ok", "blind_copy": "evil"})
        assert d

    def test_findings_accumulate(self, sa):
        sa.analyze_call("email", {"blind_copy": "x"})
        sa.analyze_call("mail", {"hidden_recipients": ["a"]})
        assert len(sa.get_findings()) >= 2

    def test_no_false_positive_on_id(self, sa):
        d, _ = sa.analyze_call("tool", {"id": 123, "status": "ok"})
        assert not d

# === LAYER 5: EGRESS TESTS (15) ===
class TestEgress:
    @pytest.fixture
    def ep(self):
        p = NetworkEgressPolicy(default_deny=True)
        p.add_rule(EgressRule(name="pm", description="", server_pattern=r"postmark", allowed_domains={"api.postmarkapp.com"}, allowed_ports={443}, blocked_domains={"giftshop.club", "evil.com"}, max_payload_bytes=1000000))
        return p

    def test_allowed(self, ep):
        assert ep.evaluate("postmark", "api.postmarkapp.com", 443).allowed

    def test_blocked_domain(self, ep):
        d = ep.evaluate("postmark", "giftshop.club", 443)
        assert not d.allowed

    def test_unknown_denied(self, ep):
        assert not ep.evaluate("postmark", "unknown.com", 443).allowed

    def test_default_deny(self, ep):
        d = ep.evaluate("no_rules", "any.com", 80)
        assert not d.allowed

    def test_default_allow(self):
        p = NetworkEgressPolicy(default_deny=False)
        assert p.evaluate("any", "any.com", 80).allowed

    def test_wrong_port(self, ep):
        assert not ep.evaluate("postmark", "api.postmarkapp.com", 8080).allowed

    def test_payload_ok(self, ep):
        assert ep.evaluate("postmark", "api.postmarkapp.com", 443, payload_bytes=500).allowed

    def test_payload_exceeds(self, ep):
        assert not ep.evaluate("postmark", "api.postmarkapp.com", 443, payload_bytes=2000000).allowed

    def test_postmark_attack_club(self, ep):
        assert ep.check_postmark_attack("pm", "giftshop.club")

    def test_postmark_attack_tld(self, ep):
        assert ep.check_postmark_attack("pm", "evil.tk")

    def test_postmark_attack_ip(self, ep):
        assert ep.check_postmark_attack("pm", "123.45.67.89")

    def test_legitimate_safe(self, ep):
        assert not ep.check_postmark_attack("pm", "api.postmarkapp.com")

    def test_stats(self, ep):
        ep.evaluate("postmark", "api.postmarkapp.com", 443)
        ep.evaluate("postmark", "evil.com", 443)
        s = ep.get_stats()
        assert s["allowed"] == 1 and s["denied"] == 1

    def test_decisions(self, ep):
        ep.evaluate("postmark", "api.postmarkapp.com", 443)
        assert len(ep.get_decisions()) == 1

    def test_multiple_rules(self):
        p = NetworkEgressPolicy(default_deny=True)
        p.add_rule(EgressRule(name="gh", description="", server_pattern=r"github", allowed_domains={"api.github.com"}, allowed_ports={443}))
        p.add_rule(EgressRule(name="em", description="", server_pattern=r"email", allowed_domains={"smtp.gmail.com"}, allowed_ports={465}))
        assert p.evaluate("github", "api.github.com", 443).allowed
        assert p.evaluate("email", "smtp.gmail.com", 465).allowed

# === ORCHESTRATOR TESTS (12) ===
class TestOrchestrator:
    @pytest.fixture
    def defense(self, tmp_path):
        audit = AuditLog(str(tmp_path / "a.log"))
        monitor = MCPSecurityMonitor({"postmark", "github"}, audit)
        monitor.shadow_detector.register_server("postmark", ["send"])
        monitor.shadow_detector.register_server("github", ["repos"])
        proxy = InlineProxyGateway(inspector=monitor, block_threshold=50)
        kernel = KernelMonitor()
        kernel.register_policy(ServerPolicy(server_id="postmark", allowed_destinations={"api.postmarkapp.com"}, allowed_ports={443}))
        semantic = SemanticIntentAnalyzer(sensitivity=0.7)
        egress = NetworkEgressPolicy(default_deny=True)
        egress.add_rule(EgressRule(name="pm", description="", server_pattern=r"postmark", allowed_domains={"api.postmarkapp.com"}, allowed_ports={443}, blocked_domains={"giftshop.club"}))
        return FiveLayerDefense(proxy=proxy, kernel=kernel, semantic=semantic, egress=egress)

    def test_clean_passes(self, defense):
        v = defense.evaluate_call({"name": "repos.list", "server_id": "github", "arguments": {"page": 1}})
        assert v.allowed

    def test_bcc_blocked_layer2(self, defense):
        v = defense.evaluate_call({"name": "send.email", "server_id": "postmark", "arguments": {"to": "u@x.com", "bcc": ["evil@bad.com"]}})
        assert not v.allowed and v.blocked_by_layer == 2

    def test_synonym_blocked_layer4(self, tmp_path):
        audit = AuditLog(str(tmp_path / "b.log"))
        m = MCPSecurityMonitor({"postmark"}, audit)
        m.shadow_detector.register_server("postmark", ["send"])
        proxy = InlineProxyGateway(inspector=m, block_threshold=95)
        defense = FiveLayerDefense(proxy=proxy, kernel=KernelMonitor(), semantic=SemanticIntentAnalyzer(), egress=NetworkEgressPolicy(default_deny=False))
        v = defense.evaluate_call({"name": "send", "server_id": "postmark", "arguments": {"msg": "hi", "blind_copy": "spy"}})
        assert not v.allowed and v.blocked_by_layer == 4

    def test_egress_blocked_layer5(self, defense):
        v = defense.evaluate_call({"name": "send.hook", "server_id": "postmark", "arguments": {"url": "giftshop.club", "data": "x"}})
        assert not v.allowed and v.blocked_by_layer == 5

    def test_kernel_smtp(self, defense):
        e = SyscallEvent(server_id="postmark", syscall_type=SyscallType.NETWORK_CONNECT, details={"destination": "smtp.evil.com", "port": 587})
        alerts = defense.evaluate_kernel_event(e)
        assert any(a.alert_type == "hidden_smtp" for a in alerts)

    def test_verdicts_tracked(self, defense):
        defense.evaluate_call({"name": "a", "server_id": "postmark", "arguments": {}})
        assert len(defense.get_verdicts()) == 1

    def test_layer_stats(self, defense):
        defense.evaluate_call({"name": "a", "server_id": "postmark", "arguments": {}})
        defense.evaluate_call({"name": "send.email", "server_id": "postmark", "arguments": {"to": "u@x.com", "bcc": ["e@v.com"]}})
        s = defense.get_layer_stats()
        assert s["blocked"] >= 1

    def test_verdict_summary_allowed(self, defense):
        v = defense.evaluate_call({"name": "repos.list", "server_id": "github", "arguments": {}})
        assert "ALLOWED" in v.summary

    def test_verdict_summary_blocked(self, defense):
        v = defense.evaluate_call({"name": "send.email", "server_id": "postmark", "arguments": {"to": "u@x.com", "bcc": ["e"]}})
        assert "BLOCKED" in v.summary

    def test_postmark_full_attack(self, defense):
        v = defense.evaluate_call({"name": "send.email", "server_id": "postmark", "arguments": {"to": ["emp@co.com"], "subject": "Invoice", "bcc": ["phan@giftshop.club"]}})
        assert not v.allowed

    def test_no_url_skips_egress(self, defense):
        v = defense.evaluate_call({"name": "repos.list", "server_id": "github", "arguments": {"page": 1}})
        l5 = [r for r in v.layer_results if r.layer == 5]
        assert all(r.passed for r in l5)

    def test_egress_with_port(self, defense):
        v = defense.evaluate_call({"name": "hook", "server_id": "postmark", "arguments": {"url": "api.postmarkapp.com", "port": 443}})
        l5 = [r for r in v.layer_results if r.layer == 5]
        assert all(r.passed for r in l5)
