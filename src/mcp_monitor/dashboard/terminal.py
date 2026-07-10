"""Terminal-based real-time security dashboard.

Displays live attack detection results with color-coded severity,
layer-by-layer breakdown, and overall defense statistics.
"""

from __future__ import annotations

import time
from typing import Any

from mcp_monitor.redteam.simulator import AttackResult, SimulationReport


class TerminalDashboard:
    """Real-time terminal dashboard for MCP security monitoring."""

    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []

    def render_simulation_report(self, report: SimulationReport) -> str:
        """Render a full simulation report as formatted terminal output."""
        lines: list[str] = []
        lines.append("")
        lines.append("=" * 80)
        lines.append("  MCP SECURITY GATEWAY MONITOR — REAL-TIME ATTACK SIMULATION")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"  Timestamp:       {time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"  Total Attacks:   {report.total_attacks}")
        lines.append(f"  Blocked:         {report.blocked}")
        lines.append(f"  Missed:          {report.missed}")
        lines.append(f"  Detection Rate:  {report.detection_rate:.1f}%")
        lines.append(f"  Execution Time:  {report.execution_time_ms:.1f}ms")
        lines.append("")
        lines.append("-" * 80)
        lines.append("  ATTACK RESULTS")
        lines.append("-" * 80)
        lines.append("")

        for i, result in enumerate(report.results, 1):
            status = "BLOCKED" if result.blocked else "MISSED"
            icon = "[X]" if result.blocked else "[ ]"
            severity_tag = f"[{result.severity}]"
            layer_info = f"Layer {result.blocked_by_layer}" if result.blocked_by_layer else "---"

            lines.append(f"  {icon} Attack #{i:02d}: {result.attack_name}")
            lines.append(f"       Category: {result.category} | Severity: {severity_tag}")
            lines.append(f"       Status: {status} | Caught by: {layer_info} | Risk: {result.risk_score}")
            if result.all_findings:
                lines.append(f"       Findings: {', '.join(result.all_findings[:3])}")
            lines.append("")

        # Layer breakdown
        lines.append("-" * 80)
        lines.append("  LAYER BREAKDOWN")
        lines.append("-" * 80)
        lines.append("")

        layer_names = {2: "Inline Proxy", 3: "Kernel Monitor", 4: "Semantic Analyzer", 5: "Egress Policy"}
        for layer_num in [2, 3, 4, 5]:
            count = report.by_layer.get(layer_num, 0)
            bar = "#" * count + "." * (report.total_attacks - count)
            lines.append(f"  Layer {layer_num} ({layer_names[layer_num]:18s}): {count:2d} blocks  [{bar[:20]}]")
        lines.append("")

        # Category breakdown
        lines.append("-" * 80)
        lines.append("  CATEGORY BREAKDOWN")
        lines.append("-" * 80)
        lines.append("")

        for cat, stats in report.by_category.items():
            rate = stats["blocked"] / max(stats["total"], 1) * 100
            lines.append(f"  {cat:25s}: {stats['blocked']}/{stats['total']} blocked ({rate:.0f}%)")
        lines.append("")

        # Final verdict
        lines.append("=" * 80)
        if report.detection_rate >= 90:
            lines.append("  VERDICT: STRONG DEFENSE — {:.1f}% detection rate".format(report.detection_rate))
        elif report.detection_rate >= 70:
            lines.append("  VERDICT: GOOD DEFENSE — {:.1f}% detection rate (gaps exist)".format(report.detection_rate))
        else:
            lines.append("  VERDICT: WEAK DEFENSE — {:.1f}% detection rate (critical gaps!)".format(report.detection_rate))
        lines.append("=" * 80)
        lines.append("")

        return "\n".join(lines)

    def render_live_event(self, result: AttackResult) -> str:
        """Render a single live event as it happens."""
        status = "BLOCKED" if result.blocked else "MISSED!"
        icon = "[BLOCK]" if result.blocked else "[MISS!]"
        return (
            f"  {icon} {result.attack_name} | "
            f"{result.severity} | Layer {result.blocked_by_layer or '-'} | "
            f"Risk={result.risk_score}"
        )
