"""Unified 5-Layer Defense Orchestrator."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from mcp_monitor.layers.egress import NetworkEgressPolicy
from mcp_monitor.layers.kernel import KernelMonitor, SyscallEvent
from mcp_monitor.layers.proxy import InlineProxyGateway, ProxyAction
from mcp_monitor.layers.semantic import SemanticIntentAnalyzer


@dataclass
class LayerResult:
    layer: int
    layer_name: str
    passed: bool
    risk_score: int = 0
    findings: list[str] = field(default_factory=list)
    execution_time_ms: float = 0.0

@dataclass
class DefenseVerdict:
    call_id: str
    allowed: bool
    blocked_by_layer: int | None = None
    layer_results: list[LayerResult] = field(default_factory=list)
    total_risk_score: int = 0
    timestamp: float = field(default_factory=time.time)
    enforcement_action: str = "allow"
    @property
    def summary(self) -> str:
        if self.allowed: return f"ALLOWED (risk={self.total_risk_score})"
        return f"BLOCKED by Layer {self.blocked_by_layer} (risk={self.total_risk_score})"

class FiveLayerDefense:
    def __init__(self, proxy: InlineProxyGateway, kernel: KernelMonitor, semantic: SemanticIntentAnalyzer, egress: NetworkEgressPolicy) -> None:
        self.proxy = proxy
        self.kernel = kernel
        self.semantic = semantic
        self.egress = egress
        self._verdicts: list[DefenseVerdict] = []

    def evaluate_call(self, tool_call: dict[str, Any]) -> DefenseVerdict:
        call_id = str(uuid.uuid4())
        layer_results: list[LayerResult] = []
        total_risk = 0
        # Layer 2: Proxy
        start = time.time()
        pd = self.proxy.intercept(tool_call)
        elapsed = (time.time() - start) * 1000
        l2_passed = pd.action in (ProxyAction.ALLOW, ProxyAction.REDACT)
        layer_results.append(LayerResult(layer=2, layer_name="inline_proxy", passed=l2_passed, risk_score=pd.risk_score, findings=pd.reasons, execution_time_ms=elapsed))
        total_risk = max(total_risk, pd.risk_score)
        if not l2_passed:
            return self._verdict(call_id, False, 2, layer_results, total_risk)
        # Layer 4: Semantic
        start = time.time()
        tool_name = tool_call.get("name", "")
        arguments = tool_call.get("arguments", {})
        dangerous, sf = self.semantic.analyze_call(tool_name, arguments)
        elapsed = (time.time() - start) * 1000
        sem_risk = max((f.severity for f in sf), default=0)
        layer_results.append(LayerResult(layer=4, layer_name="semantic_intent", passed=not dangerous, risk_score=sem_risk, findings=[f.description for f in sf], execution_time_ms=elapsed))
        total_risk = max(total_risk, sem_risk)
        if dangerous:
            return self._verdict(call_id, False, 4, layer_results, total_risk)
        # Layer 5: Egress
        start = time.time()
        dest = arguments.get("url", arguments.get("destination", ""))
        server_id = tool_call.get("server_id", "")
        if dest:
            port = arguments.get("port", 443)
            ed = self.egress.evaluate(server_id, dest, port)
            l5_passed = ed.allowed
            l5_findings = [ed.reason] if not l5_passed else []
        else:
            l5_passed = True
            l5_findings = []
        elapsed = (time.time() - start) * 1000
        layer_results.append(LayerResult(layer=5, layer_name="network_egress", passed=l5_passed, risk_score=0 if l5_passed else 90, findings=l5_findings, execution_time_ms=elapsed))
        if not l5_passed:
            total_risk = max(total_risk, 90)
            return self._verdict(call_id, False, 5, layer_results, total_risk)
        return self._verdict(call_id, True, None, layer_results, total_risk)

    def evaluate_kernel_event(self, event: SyscallEvent) -> list[Any]:
        return self.kernel.process_event(event)

    def get_verdicts(self, last_n: int = 50) -> list[DefenseVerdict]:
        return self._verdicts[-last_n:]

    def get_layer_stats(self) -> dict[str, Any]:
        layer_blocks = {2: 0, 3: 0, 4: 0, 5: 0}
        for v in self._verdicts:
            if v.blocked_by_layer: layer_blocks[v.blocked_by_layer] = layer_blocks.get(v.blocked_by_layer, 0) + 1
        total = len(self._verdicts)
        allowed = sum(1 for v in self._verdicts if v.allowed)
        return {"total_calls": total, "allowed": allowed, "blocked": total - allowed, "block_rate": (total - allowed) / max(total, 1) * 100, "blocks_by_layer": layer_blocks, "proxy_stats": self.proxy.get_stats(), "egress_stats": self.egress.get_stats()}

    def _verdict(self, call_id, allowed, blocked_by, layer_results, total_risk):
        v = DefenseVerdict(call_id=call_id, allowed=allowed, blocked_by_layer=blocked_by, layer_results=layer_results, total_risk_score=total_risk, enforcement_action="allow" if allowed else "block")
        self._verdicts.append(v)
        return v
