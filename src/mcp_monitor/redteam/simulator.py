"""Red Team Attack Simulator — replays real attack patterns in real-time.

Feeds documented attack payloads through all 5 defense layers and reports
which layers caught each attack, which missed, and overall detection rate.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from mcp_monitor.layers.kernel import SyscallEvent, SyscallType
from mcp_monitor.layers.orchestrator import FiveLayerDefense
from mcp_monitor.redteam.payloads import ATTACK_CATALOG


@dataclass
class AttackResult:
    """Result of a single attack simulation."""
    attack_name: str
    category: str
    severity: str
    blocked: bool
    blocked_by_layer: int | None = None
    all_findings: list[str] = field(default_factory=list)
    risk_score: int = 0
    execution_time_ms: float = 0.0
    expected_caught: bool = True
    actually_caught: bool = False


@dataclass
class SimulationReport:
    """Full report from a simulation run."""
    total_attacks: int = 0
    blocked: int = 0
    missed: int = 0
    detection_rate: float = 0.0
    results: list[AttackResult] = field(default_factory=list)
    by_category: dict[str, dict[str, int]] = field(default_factory=dict)
    by_layer: dict[int, int] = field(default_factory=dict)
    execution_time_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)


class AttackSimulator:
    """Replays real-world attack patterns against the 5-layer defense.

    Usage:
        simulator = AttackSimulator(defense_system)
        report = simulator.run_full_catalog()
        print(report.detection_rate)
    """

    def __init__(self, defense: FiveLayerDefense) -> None:
        self._defense = defense
        self._results: list[AttackResult] = []

    def run_full_catalog(self) -> SimulationReport:
        """Run every attack in the catalog and generate a report."""
        start = time.time()
        results: list[AttackResult] = []

        for attack in ATTACK_CATALOG:
            result = self._execute_attack(attack)
            results.append(result)
            self._results.append(result)

        elapsed = (time.time() - start) * 1000
        return self._build_report(results, elapsed)

    def run_category(self, category: str) -> SimulationReport:
        """Run attacks from a specific category."""
        start = time.time()
        results: list[AttackResult] = []

        for attack in ATTACK_CATALOG:
            if attack["category"] == category:
                result = self._execute_attack(attack)
                results.append(result)
                self._results.append(result)

        elapsed = (time.time() - start) * 1000
        return self._build_report(results, elapsed)

    def run_single(self, attack_name: str) -> AttackResult | None:
        """Run a single named attack."""
        for attack in ATTACK_CATALOG:
            if attack["name"] == attack_name:
                result = self._execute_attack(attack)
                self._results.append(result)
                return result
        return None

    def get_all_results(self) -> list[AttackResult]:
        """Get all historical results."""
        return list(self._results)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _execute_attack(self, attack: dict[str, Any]) -> AttackResult:
        """Execute a single attack against the defense system."""
        start = time.time()
        blocked = False
        blocked_by = None
        findings: list[str] = []
        risk_score = 0

        # Execute tool call through layers 2/4/5
        tool_call = attack.get("tool_call")
        if tool_call:
            verdict = self._defense.evaluate_call(tool_call)
            blocked = not verdict.allowed
            blocked_by = verdict.blocked_by_layer
            risk_score = verdict.total_risk_score
            for lr in verdict.layer_results:
                findings.extend(lr.findings)

        # Execute kernel events through layer 3
        kernel_events = attack.get("kernel_events", [])
        for ke in kernel_events:
            syscall_type = SyscallType(ke["syscall_type"])
            event = SyscallEvent(
                server_id=attack.get("tool_call", {}).get("server_id", "unknown") if tool_call else "unknown",
                syscall_type=syscall_type,
                details=ke["details"],
            )
            alerts = self._defense.evaluate_kernel_event(event)
            if alerts:
                blocked = True
                if blocked_by is None:
                    blocked_by = 3
                for a in alerts:
                    findings.append(f"kernel:{a.alert_type}:{a.description}")

        elapsed = (time.time() - start) * 1000
        expected_caught = bool(attack.get("expected_layers"))

        return AttackResult(
            attack_name=attack["name"],
            category=attack["category"],
            severity=attack.get("severity", "UNKNOWN"),
            blocked=blocked,
            blocked_by_layer=blocked_by,
            all_findings=findings,
            risk_score=risk_score,
            execution_time_ms=elapsed,
            expected_caught=expected_caught,
            actually_caught=blocked,
        )

    def _build_report(
        self, results: list[AttackResult], elapsed: float
    ) -> SimulationReport:
        """Build a summary report from results."""
        total = len(results)
        blocked_count = sum(1 for r in results if r.blocked)
        missed = total - blocked_count

        # By category
        by_cat: dict[str, dict[str, int]] = {}
        for r in results:
            if r.category not in by_cat:
                by_cat[r.category] = {"total": 0, "blocked": 0, "missed": 0}
            by_cat[r.category]["total"] += 1
            if r.blocked:
                by_cat[r.category]["blocked"] += 1
            else:
                by_cat[r.category]["missed"] += 1

        # By layer
        by_layer: dict[int, int] = {}
        for r in results:
            if r.blocked_by_layer:
                by_layer[r.blocked_by_layer] = by_layer.get(r.blocked_by_layer, 0) + 1

        detection_rate = blocked_count / max(total, 1) * 100

        return SimulationReport(
            total_attacks=total,
            blocked=blocked_count,
            missed=missed,
            detection_rate=detection_rate,
            results=results,
            by_category=by_cat,
            by_layer=by_layer,
            execution_time_ms=elapsed,
        )
