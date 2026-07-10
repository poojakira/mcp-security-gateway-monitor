"""Defense10 — the components that push detection toward 10/10.

These are REAL, FUNCTIONAL implementations (not policy stubs):
- ml_classifier: scikit-learn model, opaque to adversaries reading our source
- sandbox: Docker-based network isolation for untrusted MCP servers
- network_monitor: /proc/net/tcp live monitor + eBPF C program for host deploy
- egress_proxy: mitmproxy DPI addon comparing MCP intent vs actual HTTP calls
- rate_limiter: blast-radius limiting with recipient whitelists
- honeypot: canary tokens that trip when exfiltrated
- orchestrator10: unifies everything with the existing 5 layers
"""

from mcp_monitor.defense10.ml_classifier import MLThreatClassifier
from mcp_monitor.defense10.rate_limiter import RateLimiter, RecipientWhitelist
from mcp_monitor.defense10.honeypot import HoneypotVault
from mcp_monitor.defense10.sandbox import DockerSandbox, SandboxConfig
from mcp_monitor.defense10.network_monitor import NetworkMonitor
from mcp_monitor.defense10.egress_proxy import IntentRegistry, EgressInspector
from mcp_monitor.defense10.orchestrator10 import Defense10, Verdict10

__all__ = [
    "MLThreatClassifier",
    "RateLimiter",
    "RecipientWhitelist",
    "HoneypotVault",
    "DockerSandbox",
    "SandboxConfig",
    "NetworkMonitor",
    "IntentRegistry",
    "EgressInspector",
    "Defense10",
    "Verdict10",
]
