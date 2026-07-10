"""Layer 5: Network Egress Policy Engine."""
from __future__ import annotations
import re, time
from dataclasses import dataclass, field
from typing import Any

@dataclass
class EgressRule:
    name: str
    description: str
    server_pattern: str
    allowed_domains: set[str] = field(default_factory=set)
    allowed_ips: set[str] = field(default_factory=set)
    allowed_ports: set[int] = field(default_factory=set)
    blocked_domains: set[str] = field(default_factory=set)
    blocked_ips: set[str] = field(default_factory=set)
    max_payload_bytes: int = 0

@dataclass
class EgressDecision:
    allowed: bool
    server_id: str
    destination: str
    port: int
    rule_name: str = ""
    reason: str = ""
    timestamp: float = field(default_factory=time.time)

class NetworkEgressPolicy:
    def __init__(self, *, default_deny: bool = True) -> None:
        self._default_deny = default_deny
        self._rules: list[EgressRule] = []
        self._decisions: list[EgressDecision] = []

    def add_rule(self, rule: EgressRule) -> None:
        self._rules.append(rule)

    def evaluate(self, server_id: str, destination: str, port: int, payload_bytes: int = 0) -> EgressDecision:
        matching_rules = [r for r in self._rules if re.search(r.server_pattern, server_id, re.IGNORECASE)]
        if not matching_rules:
            decision = EgressDecision(allowed=not self._default_deny, server_id=server_id, destination=destination, port=port, reason="no_matching_rules" + (": default_deny" if self._default_deny else ": default_allow"))
            self._decisions.append(decision)
            return decision
        for rule in matching_rules:
            if destination in rule.blocked_domains or destination in rule.blocked_ips:
                decision = EgressDecision(allowed=False, server_id=server_id, destination=destination, port=port, rule_name=rule.name, reason=f"destination \'{destination}\' is explicitly blocked")
                self._decisions.append(decision)
                return decision
            if rule.max_payload_bytes > 0 and payload_bytes > rule.max_payload_bytes:
                decision = EgressDecision(allowed=False, server_id=server_id, destination=destination, port=port, rule_name=rule.name, reason=f"payload {payload_bytes}B exceeds max {rule.max_payload_bytes}B")
                self._decisions.append(decision)
                return decision
            dest_allowed = destination in rule.allowed_domains or destination in rule.allowed_ips or (not rule.allowed_domains and not rule.allowed_ips)
            port_allowed = port in rule.allowed_ports or not rule.allowed_ports
            if dest_allowed and port_allowed:
                decision = EgressDecision(allowed=True, server_id=server_id, destination=destination, port=port, rule_name=rule.name, reason="matches allow rule")
                self._decisions.append(decision)
                return decision
        decision = EgressDecision(allowed=not self._default_deny, server_id=server_id, destination=destination, port=port, reason="no_allow_rule_matched" + (": default_deny" if self._default_deny else ""))
        self._decisions.append(decision)
        return decision

    def check_postmark_attack(self, server_id: str, destination: str) -> bool:
        suspicious_tlds = {".club", ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz"}
        for tld in suspicious_tlds:
            if destination.endswith(tld):
                return True
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", destination):
            return True
        return False

    def get_decisions(self, last_n: int = 100) -> list[EgressDecision]:
        return self._decisions[-last_n:]

    def get_stats(self) -> dict[str, Any]:
        allowed = sum(1 for d in self._decisions if d.allowed)
        denied = sum(1 for d in self._decisions if not d.allowed)
        return {"total_evaluated": len(self._decisions), "allowed": allowed, "denied": denied, "deny_rate": denied / max(len(self._decisions), 1) * 100, "rules_count": len(self._rules), "default_deny": self._default_deny}
