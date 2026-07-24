"""Layer 2: Inline Proxy Gateway for MCP tool calls."""
from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class ProxyAction(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    REDACT = "redact"

@dataclass
class ProxyDecision:
    call_id: str
    action: ProxyAction
    tool_name: str
    server_id: str
    risk_score: int = 0
    reasons: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    original_payload: dict[str, Any] | None = None
    modified_payload: dict[str, Any] | None = None

@dataclass
class ProxyRule:
    name: str
    description: str
    tool_pattern: str
    action: ProxyAction
    condition: Callable[[dict], bool] | None = None
    priority: int = 50
    fields_to_redact: list[str] = field(default_factory=list)

class InlineProxyGateway:
    def __init__(self, *, inspector: Any = None, block_threshold: int = 50, quarantine_threshold: int = 30, default_action: ProxyAction = ProxyAction.BLOCK) -> None:
        self._inspector = inspector
        self._block_threshold = block_threshold
        self._quarantine_threshold = quarantine_threshold
        self._default_action = default_action
        self._rules: list[ProxyRule] = []
        self._decisions: list[ProxyDecision] = []
        self._blocked_count: int = 0
        self._allowed_count: int = 0
        self._quarantined: list[dict[str, Any]] = []

    def intercept(self, tool_call: dict[str, Any]) -> ProxyDecision:
        call_id = str(uuid.uuid4())
        tool_name = tool_call.get("name", "")
        server_id = tool_call.get("server_id", "")
        reasons: list[str] = []
        risk_score = 0
        rule_decision = self._check_rules(tool_call)
        if rule_decision is not None:
            rule_decision.call_id = call_id
            self._record(rule_decision)
            return rule_decision
        if self._inspector is not None:
            result = self._inspector.inspect_call(tool_call)
            risk_score = result.get("risk_score", 0)
            reasons = result.get("findings", [])
        if risk_score >= self._block_threshold:
            action = ProxyAction.BLOCK
            reasons.append(f"risk_score {risk_score} >= block_threshold {self._block_threshold}")
        elif risk_score >= self._quarantine_threshold:
            action = ProxyAction.QUARANTINE
            reasons.append(f"risk_score {risk_score} >= quarantine_threshold {self._quarantine_threshold}")
        else:
            action = ProxyAction.ALLOW
        decision = ProxyDecision(call_id=call_id, action=action, tool_name=tool_name, server_id=server_id, risk_score=risk_score, reasons=reasons, original_payload=tool_call, modified_payload=tool_call if action == ProxyAction.ALLOW else None)
        self._record(decision)
        return decision

    def intercept_output(self, tool_name: str, server_id: str, output: dict[str, Any]) -> ProxyDecision:
        call_id = str(uuid.uuid4())
        reasons: list[str] = []
        risk_score = 0
        if self._inspector is not None:
            result = self._inspector.inspect_output(tool_name, output)
            risk_score = result.get("risk_score", 0)
            reasons = result.get("findings", [])
        if risk_score >= self._block_threshold:
            action = ProxyAction.BLOCK
        elif risk_score >= self._quarantine_threshold:
            action = ProxyAction.QUARANTINE
        else:
            action = ProxyAction.ALLOW
        decision = ProxyDecision(call_id=call_id, action=action, tool_name=tool_name, server_id=server_id, risk_score=risk_score, reasons=reasons, original_payload=output, modified_payload=output if action == ProxyAction.ALLOW else None)
        self._record(decision)
        return decision

    def add_rule(self, rule: ProxyRule) -> None:
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    def get_stats(self) -> dict[str, Any]:
        return {"total_intercepted": self._blocked_count + self._allowed_count, "blocked": self._blocked_count, "allowed": self._allowed_count, "quarantined": len(self._quarantined), "block_rate": self._blocked_count / max(self._blocked_count + self._allowed_count, 1) * 100}

    def get_quarantined(self) -> list[dict[str, Any]]:
        return list(self._quarantined)

    def release_quarantined(self, index: int) -> dict[str, Any] | None:
        if 0 <= index < len(self._quarantined):
            return self._quarantined.pop(index)
        return None

    def get_decisions(self, last_n: int = 50) -> list[ProxyDecision]:
        return self._decisions[-last_n:]

    def _check_rules(self, tool_call: dict[str, Any]) -> ProxyDecision | None:
        tool_name = tool_call.get("name", "")
        for rule in self._rules:
            if not re.search(rule.tool_pattern, tool_name, re.IGNORECASE):
                continue
            if rule.condition and not rule.condition(tool_call):
                continue
            modified = tool_call
            if rule.action == ProxyAction.REDACT:
                modified = self._redact_fields(tool_call, rule.fields_to_redact)
            return ProxyDecision(call_id="", action=rule.action, tool_name=tool_name, server_id=tool_call.get("server_id", ""), reasons=[f"rule:{rule.name}:{rule.description}"], original_payload=tool_call, modified_payload=modified if rule.action != ProxyAction.BLOCK else None)
        return None

    def _redact_fields(self, payload: dict[str, Any], fields: list[str]) -> dict[str, Any]:
        result = dict(payload)
        args = dict(result.get("arguments", {}))
        for f in fields:
            args.pop(f, None)
        result["arguments"] = args
        return result

    def _record(self, decision: ProxyDecision) -> None:
        self._decisions.append(decision)
        if decision.action == ProxyAction.BLOCK:
            self._blocked_count += 1
        elif decision.action == ProxyAction.ALLOW:
            self._allowed_count += 1
        elif decision.action == ProxyAction.QUARANTINE:
            if decision.original_payload:
                self._quarantined.append(decision.original_payload)
