"""HTML Security Report Generator — deep-level dashboard."""

from __future__ import annotations
import time
from mcp_monitor.redteam.simulator import SimulationReport


class HTMLReportGenerator:
    """Generates an HTML security dashboard from simulation results."""

    def generate(self, report: SimulationReport) -> str:
        """Generate a complete HTML dashboard."""
        rows = ""
        for r in report.results:
            color = "#dc3545" if not r.blocked else "#28a745"
            status = "BLOCKED" if r.blocked else "MISSED"
            layer = str(r.blocked_by_layer) if r.blocked_by_layer else "-"
            rows += f"<tr style='color:{color}'><td>{r.attack_name}</td><td>{r.category}</td><td>{r.severity}</td><td><b>{status}</b></td><td>Layer {layer}</td><td>{r.risk_score}</td></tr>\n"

        by_layer_html = ""
        layer_names = {
            2: "Inline Proxy",
            3: "Kernel Monitor",
            4: "Semantic Analyzer",
            5: "Egress Policy",
        }
        for ln in [2, 3, 4, 5]:
            count = report.by_layer.get(ln, 0)
            pct = count / max(report.total_attacks, 1) * 100
            by_layer_html += f"<div class='layer-bar'><span>Layer {ln}: {layer_names[ln]}</span><div class='bar' style='width:{pct}%'>{count}</div></div>\n"

        by_cat_html = ""
        for cat, stats in report.by_category.items():
            rate = stats["blocked"] / max(stats["total"], 1) * 100
            by_cat_html += f"<tr><td>{cat}</td><td>{stats['total']}</td><td>{stats['blocked']}</td><td>{stats['missed']}</td><td>{rate:.0f}%</td></tr>\n"

        verdict_color = (
            "#28a745"
            if report.detection_rate >= 90
            else "#ffc107"
            if report.detection_rate >= 70
            else "#dc3545"
        )

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>MCP Security Dashboard</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#1a1a2e;color:#eee;margin:0;padding:20px}}
.container{{max-width:1200px;margin:0 auto}}
h1{{color:#00d4ff;border-bottom:2px solid #00d4ff;padding-bottom:10px}}
h2{{color:#8b5cf6;margin-top:30px}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin:20px 0}}
.stat-card{{background:#16213e;border-radius:8px;padding:20px;text-align:center;border:1px solid #0f3460}}
.stat-card .number{{font-size:2.5em;font-weight:bold;color:#00d4ff}}
.stat-card .label{{color:#aaa;margin-top:5px}}
.detection-rate{{font-size:3em;font-weight:bold;color:{verdict_color};text-align:center;margin:20px}}
table{{width:100%;border-collapse:collapse;margin:15px 0}}
th,td{{padding:10px;text-align:left;border-bottom:1px solid #333}}
th{{background:#16213e;color:#00d4ff}}
tr:hover{{background:#16213e}}
.layer-bar{{margin:8px 0}}
.layer-bar span{{display:inline-block;width:200px;color:#aaa}}
.layer-bar .bar{{display:inline-block;background:#8b5cf6;color:#fff;padding:4px 10px;border-radius:4px;min-width:30px;text-align:center}}
.verdict{{text-align:center;padding:20px;margin:20px 0;border-radius:8px;background:#16213e;border:2px solid {verdict_color}}}
</style></head><body>
<div class="container">
<h1>MCP Security Gateway Monitor — Real-Time Dashboard</h1>
<p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} | Execution: {report.execution_time_ms:.1f}ms</p>

<div class="stats">
<div class="stat-card"><div class="number">{report.total_attacks}</div><div class="label">Total Attacks</div></div>
<div class="stat-card"><div class="number" style="color:#28a745">{report.blocked}</div><div class="label">Blocked</div></div>
<div class="stat-card"><div class="number" style="color:#dc3545">{report.missed}</div><div class="label">Missed</div></div>
<div class="stat-card"><div class="number" style="color:{verdict_color}">{report.detection_rate:.1f}%</div><div class="label">Detection Rate</div></div>
</div>

<div class="verdict"><h2 style="color:{verdict_color}">Detection Rate: {report.detection_rate:.1f}%</h2></div>

<h2>Layer Performance</h2>
{by_layer_html}

<h2>Category Breakdown</h2>
<table><tr><th>Category</th><th>Total</th><th>Blocked</th><th>Missed</th><th>Rate</th></tr>{by_cat_html}</table>

<h2>All Attack Results</h2>
<table><tr><th>Attack</th><th>Category</th><th>Severity</th><th>Status</th><th>Caught By</th><th>Risk</th></tr>{rows}</table>
</div></body></html>"""
