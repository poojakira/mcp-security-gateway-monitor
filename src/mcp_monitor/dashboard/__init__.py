"""Security Dashboard — real-time monitoring visualization."""
from mcp_monitor.dashboard.report import HTMLReportGenerator
from mcp_monitor.dashboard.terminal import TerminalDashboard

__all__ = ["TerminalDashboard", "HTMLReportGenerator"]
