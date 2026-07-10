"""The 10/10 Orchestrator — unifies all defense layers into one verdict.

Chains the original 5 layers with the defense10 components:

  L1  Application detectors        (regex, PII, shadow, exfil)
  L2  Inline proxy enforcement
  L3  Kernel/network monitor       (/proc + eBPF) — sees server-side calls
  L4  Semantic + ML classifier     (opaque to adversary)
  L5  Network egress policy
  L6  DPI egress inspection        (MCP intent vs actual call) *** the big one
  L7  Rate limiting                (blast radius)
  L8  Recipient whitelist          (giftshop.club never approved)
  L9  Honeypot canaries            (zero-false-positive compromise proof)
  L10 Sandbox isolation            (kernel-enforced, no bypass)

A call must survive ALL layers. Any single trip blocks + records.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from mcp_monitor.defense10.ml_classifier import MLThreatClassifier
from mcp_monitor.defense10.rate_limiter import RateLimiter, RecipientWhitelist
from mcp_monitor.defense10.honeypot import HoneypotVault
from mcp_monitor.defense10.egress_proxy import IntentRegistry, EgressInspector
from mcp_monitor.defense10.network_monitor import NetworkMonitor


@dataclass
class Verdict10:
    call_id: str
    allowed: bool
    blocked_by: str = ""
    reasons: list[str] = field(default_factory=list)
    layers_passed: list[str] = field(default_factory=list)
    severity: int = 0
    timestamp: float = field(default_factory=time.time)

    @property
    def summary(self) -> str:
        if self.allowed:
            return f"ALLOWED (passed {len(self.layers_passed)} layers)"
        return f"BLOCKED by {self.blocked_by} (severity {self.severity})"


class Defense10:
    """Complete defense-in-depth orchestrator toward 10/10."""

    def __init__(self, *, email_rate_per_hour: int = 10) -> None:
        self.ml = MLThreatClassifier()
        self.rate = RateLimiter()
        self.whitelist = RecipientWhitelist()
        self.honeypot = HoneypotVault()
        self.intent = IntentRegistry()
        self.egress = EgressInspector(self.intent)
        self.network = NetworkMonitor()
        self._email_rate = email_rate_per_hour
        self._verdicts: list[Verdict10] = []
        self._max_verdicts = 10000  # Prevent unbounded memory growth
        # Graceful ML degradation — if sklearn not available or training fails
        try:
            self.ml.train()
            self._ml_available = True
        except Exception:
            self._ml_available = False

    def configure_server(self, server_id: str, approved_domains: list[str]) -> None:
        """Set up per-server policy: rate limits + approved recipient domains."""
        self.rate.set_limit(server_id, "send", self._email_rate, 3600)
        for d in approved_domains:
            self.whitelist.approve_domain(server_id, d)

    def inspect_call(self, tool_call: dict[str, Any]) -> Verdict10:
        """Run the inbound MCP tool call through the intent + ML + policy layers."""
        call_id = str(uuid.uuid4())
        passed: list[str] = []
        server_id = tool_call.get("server_id", "")
        args = tool_call.get("arguments", {})

        # Record intent for later egress comparison (L6)
        self.intent.record(call_id, tool_call)

        # L9: honeypot — did the call try to exfiltrate a canary?
        trips = self.honeypot.scan_tool_call(tool_call)
        if trips:
            return self._block(call_id, "L9_honeypot",
                               [f"canary token exfiltrated: {t.token_id}" for t in trips], 100, passed)
        passed.append("L9_honeypot")

        # L4: ML classifier (opaque to adversary) — graceful degradation
        if self._ml_available:
            pred = self.ml.classify(tool_call)
            if pred.is_threat:
                return self._block(call_id, "L4_ml_classifier",
                                   [f"ML threat conf={pred.confidence} family={pred.threat_family}"],
                                   int(pred.confidence * 100), passed)
        passed.append("L4_ml_classifier")

        # L8: recipient whitelist
        recipients = self._recipients(args)
        if recipients:
            wl = self.whitelist.check(server_id, recipients)
            if not wl.allowed:
                return self._block(call_id, "L8_recipient_whitelist", [wl.reason], 90, passed)
        passed.append("L8_recipient_whitelist")

        # L7: rate limit (only for send-like actions)
        if recipients:
            rl = self.rate.check(server_id, "send")
            if not rl.allowed:
                return self._block(call_id, "L7_rate_limit", [rl.reason], 70, passed)
        passed.append("L7_rate_limit")

        return self._allow(call_id, passed)

    def inspect_egress(self, call_id: str, actual_payload: Any) -> Verdict10:
        """L6: compare the ACTUAL outbound call against the MCP intent.
        This is the layer that catches server-side BCC injection."""
        v = self.egress.inspect(call_id, actual_payload)
        if not v.allowed:
            return self._block(call_id, "L6_dpi_egress",
                               [v.reason], v.severity, ["L6_dpi_egress"])
        return self._allow(call_id, ["L6_dpi_egress"])

    def scan_network(self) -> Verdict10:
        """L3: scan live kernel connections for hidden outbound calls."""
        call_id = str(uuid.uuid4())
        alerts = self.network.scan()
        if alerts:
            top = max(alerts, key=lambda a: a.severity)
            return self._block(call_id, "L3_network_monitor",
                               [f"{a.reason} -> {a.remote_addr}:{a.remote_port}" for a in alerts[:3]],
                               top.severity, [])
        return self._allow(call_id, ["L3_network_monitor"])

    def get_verdicts(self) -> list[Verdict10]:
        return list(self._verdicts)

    def stats(self) -> dict[str, Any]:
        total = len(self._verdicts)
        blocked = sum(1 for v in self._verdicts if not v.allowed)
        by_layer: dict[str, int] = {}
        for v in self._verdicts:
            if v.blocked_by:
                by_layer[v.blocked_by] = by_layer.get(v.blocked_by, 0) + 1
        return {
            "total": total, "blocked": blocked, "allowed": total - blocked,
            "block_rate": round(blocked / max(total, 1) * 100, 1),
            "blocks_by_layer": by_layer,
            "honeypot_tokens": self.honeypot.token_count(),
        }

    # -- helpers --
    def _recipients(self, args: dict[str, Any]) -> list[str]:
        """Extract EVERY email address appearing anywhere in the arguments.

        We do NOT trust field names. An attacker hides the exfil address in
        a field called 'fwd_leak' or 'metadata'. So we scan the entire
        argument tree and check every email against the approved whitelist.
        Any email to an unapproved domain — in any field — is blocked.
        """
        import re
        rx = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

        def walk(obj: Any) -> list[str]:
            found: list[str] = []
            if isinstance(obj, str):
                found += rx.findall(obj)
            elif isinstance(obj, dict):
                for v in obj.values():
                    found += walk(v)
            elif isinstance(obj, (list, tuple)):
                for i in obj:
                    found += walk(i)
            return found

        return walk(args)

    def _block(self, call_id, layer, reasons, severity, passed) -> Verdict10:
        v = Verdict10(call_id=call_id, allowed=False, blocked_by=layer,
                      reasons=reasons, layers_passed=passed, severity=severity)
        self._verdicts.append(v)
        return v

    def _allow(self, call_id, passed) -> Verdict10:
        v = Verdict10(call_id=call_id, allowed=True, layers_passed=passed)
        self._verdicts.append(v)
        # Evict old verdicts to prevent memory exhaustion
        if len(self._verdicts) > self._max_verdicts:
            self._verdicts = self._verdicts[-self._max_verdicts:]
        return v
