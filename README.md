# MCP Security Gateway Monitor

A tool-call firewall for MCP (Model Context Protocol) agents. It sits between an AI assistant and the tools it calls (email, file access, APIs), inspecting each call for signs of prompt injection, data exfiltration, or unauthorized behavior.

It has 5 core defense layers that run on every tool call with zero external dependencies, plus 5 optional layers that add ML classification, sandboxing, and deep packet inspection.

## What problem does this solve?

When AI assistants use external tools, those tool calls can be hijacked. A real-world example: an MCP server silently added a hidden BCC to outgoing emails, forwarding copies to an attacker. This project monitors and blocks that class of attack.

## Honest status

- **Detection rate on the full built-in attack catalog: ~51%.** The 5-layer defense catches about half of the red-team payloads in the bundled simulator. This is not a mature product — it's a working prototype with real detection logic.
- **Line coverage: 77%** (pytest, enforced in CI).
- **ML classifier (Layer 6) is experimental.** Its reported 98% accuracy is measured on its own synthetic training data. That number means nothing for real-world attacks. Use it as a supplementary signal behind layers 1–5.
- **Zero runtime dependencies** for the core 5 layers (stdlib only).

---

## Install

Requires Python 3.10+.

```bash
# Clone and install
git clone https://github.com/poojakira/mcp-security-gateway-monitor.git
cd mcp-security-gateway-monitor
python -m venv .venv

# Activate (pick your shell)
# PowerShell:  .\.venv\Scripts\Activate.ps1
# cmd.exe:     .venv\Scripts\activate.bat
# bash/zsh:    source .venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"
```

On Windows cmd.exe, don't quote `.[dev]` — use `pip install -e .[dev]`.

### Optional extras

- `pip install -e ".[server]"` — FastAPI control plane (real-time dashboard)
- `pip install -e ".[ml]"` — scikit-learn for the ML classifier (Layer 6)
- `pip install -e ".[dpi]"` — mitmproxy for deep packet inspection (Layer 10)

---

## Run

### Run tests

```bash
python -m pytest tests/ -v
python -m pytest tests/ --cov=mcp_monitor --cov-report=term-missing
```

### Run the offline red-team report

```bash
python run_dashboard.py
```

This builds the 5-layer defense, throws the bundled attack catalog at it, prints results to terminal, and writes `security_dashboard.html`. Not a live service — just a one-shot report.

### Run the real-time control plane (port 8000)

```bash
pip install -e ".[dev,server]"
python run_realtime.py
```

Opens at http://localhost:8000 (loopback only). The dashboard is empty until you send traffic to `POST /api/scan`. See RUNBOOK.md for details.

---

## How it works

### The 5 core layers (zero dependencies, run on every call)

| Layer | Name | What it does |
|-------|------|--------------|
| 1 | Audit Log | Records every tool call in a SHA-256 hash-chained log. Tamper-evident. |
| 2 | Inline Proxy | Intercepts tool calls. Applies rules, scores risk, blocks or quarantines suspicious calls. |
| 3 | Process Monitor | Watches syscall-level events: network connections, DNS lookups, file access, process spawning. |
| 4 | Semantic Analyzer | Understands what a tool call is trying to do. Catches hidden BCC fields, encoded emails, exfiltration patterns. |
| 5 | Egress Policy | Controls which destinations each server can reach. Default-deny with explicit allow rules. |

### The 5 optional layers (require extra dependencies)

| Layer | Name | What it does |
|-------|------|--------------|
| 6 | ML Classifier (BETA) | TF-IDF + LogisticRegression trained on synthetic data. Supplementary signal only. |
| 7 | Rate Limiter | Per-minute rate caps and recipient whitelists. Stops mass exfiltration. |
| 8 | Honeypot Vault | Plants canary tokens in tool responses. If one leaks, you know something exfiltrated data. |
| 9 | Docker Sandbox | Isolates untrusted MCP servers in network-restricted containers. |
| 10 | Network DPI | Deep packet inspection comparing declared MCP intent against actual HTTP traffic. |

---

## Usage example

```python
from mcp_monitor.layers import (
    InlineProxyGateway, ProcessBehaviorMonitor,
    SemanticIntentAnalyzer, NetworkEgressPolicy, FiveLayerDefense,
)
from mcp_monitor.redteam import AttackSimulator

proxy = InlineProxyGateway()
kernel = ProcessBehaviorMonitor()
semantic = SemanticIntentAnalyzer()
egress = NetworkEgressPolicy(default_deny=True)

defense = FiveLayerDefense(proxy=proxy, kernel=kernel, semantic=semantic, egress=egress)
simulator = AttackSimulator(defense)
report = simulator.run_full_catalog()

print(f"Detection Rate: {report.detection_rate:.1f}%")
print(f"Blocked: {report.blocked}/{report.total_attacks}")
```

---

## Project structure

```
src/mcp_monitor/
├── monitor.py              # Main orchestrator
├── detectors/              # Prompt injection, PII, exfiltration, shadow server detection
├── audit/                  # Hash-chained log + write-ahead log
├── layers/                 # The 5 core defense layers + orchestrator
├── advanced/               # Manifest signing, drift detection, correlation, canary probes
├── dashboard/              # Terminal dashboard + HTML report generator
├── redteam/                # Attack simulator + payload catalog
└── defense10/              # Layers 6–10 (ML, rate limit, honeypot, sandbox, DPI)
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError: No module named 'mcp_monitor'` | Run `pip install -e ".[dev]"` from project root |
| `ERROR: .[dev] is not a valid requirement` | You're in cmd.exe — drop the quotes: `pip install -e .[dev]` |
| `python3: command not found` (Windows) | Use `python` instead of `python3` |
| `ImportError: cannot import name 'MLThreatClassifier'` | Install ML extra: `pip install -e ".[ml]"` |
| `SyntaxError` on Python 3.9 | Upgrade to Python 3.10+ |

---

## License

MIT
