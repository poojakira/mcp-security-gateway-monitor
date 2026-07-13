# MCP Security Gateway Monitor

A real-time security monitor that protects AI tool calls (MCP protocol) from prompt injection, data exfiltration, hidden BCC attacks, and more. Built entirely on the Python standard library with zero runtime dependencies.

## What This Project Does (Plain English)

When AI assistants use external tools (email, file access, APIs), those tools can be hijacked. In mid-2026, an MCP server silently added a hidden BCC to every outgoing email, forwarding copies to an attacker. This project stops that.

**MCP Security Gateway Monitor** sits between the AI and its tools. Every tool call passes through up to 10 defense layers that inspect, analyze, and block suspicious activity before it reaches the outside world. Think of it as a firewall specifically designed for AI-to-tool communication.

It will:
- Block prompt injection hidden inside tool arguments
- Catch hidden email recipients (the real Postmark BCC attack)
- Detect data exfiltration via encoded payloads or suspicious URLs
- Flag unauthorized network connections and DNS lookups
- Generate a real-time HTML security dashboard showing what was caught

---

## Quick Start

### One-Liner Test (all platforms)

```bash
git clone https://github.com/poojakira/mcp-security-gateway-monitor.git && cd mcp-security-gateway-monitor && pip install -e ".[dev]" && python -m pytest tests/ -v
```

---

### Ubuntu / Linux / macOS

```bash
# 1. Clone the repository
git clone https://github.com/poojakira/mcp-security-gateway-monitor.git
cd mcp-security-gateway-monitor

# 2. Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# 3. Install the package with dev dependencies
python3 -m pip install -e ".[dev]"

# 4. Run all tests
python3 -m pytest tests/ -v

# 5. Run with coverage (must be 100%)
python3 -m pytest tests/ --cov=mcp_monitor --cov-report=term-missing

# 6. Run the security dashboard
python3 run_dashboard.py
```

---

### Windows PowerShell

```powershell
# 1. Clone the repository
git clone https://github.com/poojakira/mcp-security-gateway-monitor.git
cd mcp-security-gateway-monitor

# 2. Create a virtual environment (recommended)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install the package with dev dependencies
python -m pip install -e ".[dev]"

# 4. Run all tests
python -m pytest tests/ -v

# 5. Run with coverage (must be 100%)
python -m pytest tests/ --cov=mcp_monitor --cov-report=term-missing

# 6. Run the security dashboard
python run_dashboard.py
```

---

### Windows Command Prompt (cmd.exe)

```cmd
REM 1. Clone the repository
git clone https://github.com/poojakira/mcp-security-gateway-monitor.git
cd mcp-security-gateway-monitor

REM 2. Create a virtual environment (recommended)
python -m venv .venv
.venv\Scripts\activate.bat

REM 3. Install the package with dev dependencies
REM NOTE: Do NOT quote .[dev] in cmd.exe
python -m pip install -e .[dev]

REM 4. Run all tests
python -m pytest tests/ -v

REM 5. Run with coverage (must be 100%)
python -m pytest tests/ --cov=mcp_monitor --cov-report=term-missing

REM 6. Run the security dashboard
python run_dashboard.py
```

> **Important:** On Windows cmd.exe, do NOT quote `.[dev]`. On PowerShell and bash/zsh, use `".[dev]"`.

---

## How the 10 Defense Layers Work

This project implements a defense-in-depth architecture with 10 layers that work together to catch attacks at multiple points:

| Layer | Name | What It Does |
|-------|------|--------------|
| 1 | **Audit Log** | Records every tool call in a SHA-256 hash-chained immutable log. Tampering is instantly detectable. |
| 2 | **Inline Proxy Gateway** | Intercepts all tool calls. Applies rules, risk scoring, and blocks/quarantines suspicious calls before they execute. |
| 3 | **Kernel Monitor** | Watches syscall-level behavior: network connections, DNS lookups, file access, process spawning. Enforces per-server policies. |
| 4 | **Semantic Intent Analyzer** | Understands what a tool call is trying to do. Detects BCC synonyms, exfiltration patterns, encoded emails, and suspicious fields. |
| 5 | **Network Egress Policy** | Controls what destinations each server can reach. Default-deny with explicit allow rules. Blocks known-bad domains and oversized payloads. |
| 6 | **ML Threat Classifier** *(BETA)* | Experimental scikit-learn model (TF-IDF char n-grams + LogisticRegression) trained on a built-in synthetic corpus. Supplementary signal only — see the BETA note below for measured held-out performance. |
| 7 | **Rate Limiter** | Limits blast radius by enforcing recipient whitelists and per-minute rate caps. Stops mass-exfiltration. |
| 8 | **Honeypot Vault** | Plants canary tokens in tool responses. If a token appears somewhere it should not, an exfiltration path is confirmed. |
| 9 | **Docker Sandbox** | Isolates untrusted MCP servers in network-restricted containers. Even if compromised, they cannot reach the internet. |
| 10 | **Network Monitor + DPI** | Deep packet inspection comparing declared MCP intent against actual HTTP traffic. Catches tools that lie about what they send. |

The first 5 layers run on every tool call with zero external dependencies. Layers 6-10 add ML, sandboxing, and deep inspection for production deployments.

> **⚠️ ML Threat Classifier (Layer 6) is BETA.** Its `train()` reports a
> cross-validation accuracy (~0.98) measured on its own built-in *synthetic*
> corpus. That is a sanity figure, **not** production accuracy. On a real
> external held-out benchmark (Hugging Face `deepset/prompt-injections`) the
> BETA classifier measured **recall ≈ 0.317** with a **false-positive rate
> ≈ 14.3%** on benign text. For reference, the rule-based regex
> prompt-injection detector measured **recall ≈ 0.083 / 0% false positives**
> on the same test. Use Layer 6 as a supplementary signal behind the
> deterministic layers (1-5), not as a standalone defense. The detectors are
> intentionally not tuned to any single benchmark.

---

## Project Structure

```
mcp-security-gateway-monitor/
├── README.md                    <- You are here
├── run_dashboard.py             <- Run this to see the security dashboard
├── pyproject.toml               <- Package config, dependencies
├── CHANGELOG.md                 <- Version history
├── RESEARCH_REPORT.md           <- Technical research background
├── src/
│   └── mcp_monitor/
│       ├── __init__.py          <- Package root
│       ├── monitor.py           <- MCPSecurityMonitor orchestrator
│       ├── detectors/
│       │   ├── prompt_injection.py   <- 12 regex patterns for jailbreak detection
│       │   ├── pii_detector.py       <- 9 PII types with redaction
│       │   ├── shadow_server.py      <- Unregistered server detection
│       │   └── exfiltration.py       <- BCC injection, payload size, base64, URLs
│       ├── audit/
│       │   ├── log.py                <- SHA-256 hash-chained audit log
│       │   └── wal.py                <- Write-ahead log for crash recovery
│       ├── advanced/
│       │   ├── manifest.py           <- Cryptographic tool manifest signing
│       │   ├── drift.py              <- Behavioral drift detection
│       │   ├── correlation.py        <- Multi-step attack correlation
│       │   ├── invariants.py         <- Declarative security policies
│       │   └── canary.py             <- Active behavioral probes
│       ├── layers/
│       │   ├── proxy.py              <- Layer 2: Inline Proxy Gateway
│       │   ├── kernel.py             <- Layer 3: Kernel Monitor
│       │   ├── semantic.py           <- Layer 4: Semantic Intent Analyzer
│       │   ├── egress.py             <- Layer 5: Network Egress Policy
│       │   └── orchestrator.py       <- FiveLayerDefense orchestrator
│       ├── dashboard/
│       │   ├── terminal.py           <- Terminal-based live dashboard
│       │   └── report.py             <- HTML report generator
│       ├── redteam/
│       │   ├── simulator.py          <- Attack simulation engine
│       │   └── payloads.py           <- Real-world attack catalog
│       └── defense10/
│           ├── ml_classifier.py      <- ML threat classifier
│           ├── rate_limiter.py       <- Rate limiting + recipient whitelist
│           ├── honeypot.py           <- Canary token vault
│           ├── sandbox.py            <- Docker sandbox isolation
│           ├── network_monitor.py    <- /proc/net/tcp + eBPF monitor
│           ├── egress_proxy.py       <- DPI egress inspection
│           └── orchestrator10.py     <- Full 10-layer orchestrator
└── tests/
    ├── test_prompt_injection.py
    ├── test_pii_detector.py
    ├── test_shadow_server.py
    ├── test_exfiltration.py
    ├── test_audit_log.py
    ├── test_advanced_*.py
    ├── test_cross_platform.py
    └── test_coverage_100.py
```

---

## Running the Dashboard

```bash
python run_dashboard.py
```

This script:
1. Sets up a 5-layer defense with InlineProxyGateway, KernelMonitor, SemanticIntentAnalyzer, and NetworkEgressPolicy
2. Runs the full red-team attack catalog (all known attack patterns)
3. Prints a color-coded terminal report showing each attack and whether it was blocked
4. Saves an interactive HTML dashboard to `security_dashboard.html`
5. Opens the dashboard in your default browser

---

## Example Output

```python
from mcp_monitor.layers import (
    InlineProxyGateway, KernelMonitor,
    SemanticIntentAnalyzer, NetworkEgressPolicy, FiveLayerDefense,
)
from mcp_monitor.redteam import AttackSimulator
from mcp_monitor.dashboard import TerminalDashboard

proxy = InlineProxyGateway()
kernel = KernelMonitor()
semantic = SemanticIntentAnalyzer()
egress = NetworkEgressPolicy(default_deny=True)

defense = FiveLayerDefense(proxy=proxy, kernel=kernel, semantic=semantic, egress=egress)
simulator = AttackSimulator(defense)
report = simulator.run_full_catalog()

print(f"Detection Rate: {report.detection_rate:.1f}%")
print(f"Blocked: {report.blocked}/{report.total_attacks}")
```

---

## Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| `ModuleNotFoundError: No module named 'mcp_monitor'` | Package not installed | Run `pip install -e ".[dev]"` from the project root |
| `No module named 'pytest'` | Dev dependencies missing | Run `pip install -e ".[dev]"` (includes pytest) |
| `ERROR: .[dev] is not a valid requirement` | Using cmd.exe with quotes | Remove quotes: `pip install -e .[dev]` |
| `python3: command not found` (Windows) | Windows uses `python` not `python3` | Use `python` instead of `python3` |
| `Permission denied` on Linux/macOS | Need write access to install | Use a virtual environment: `python3 -m venv .venv && source .venv/bin/activate` |
| `SyntaxError` on Python 3.8 or older | Project requires Python 3.9+ | Upgrade Python to 3.9 or later |
| `ImportError: cannot import name 'MLThreatClassifier'` | scikit-learn not installed | Run `pip install -e ".[ml]"` for ML features |
| Tests show `0% coverage` | Running pytest from wrong directory | Make sure you are in the project root directory |
| `webbrowser.open` does nothing | No GUI browser in headless environment | Open `security_dashboard.html` manually in a browser |
| HTML dashboard is blank | Script did not finish | Check terminal output for errors; re-run `python run_dashboard.py` |

---

## Test Results

```
963 statements | 0 missed | 100% code coverage
234 tests | 0 failures | ~0.5s runtime
Verified on: Python 3.9, 3.10, 3.11, 3.12, 3.13
Platforms:   Ubuntu Linux, Windows, macOS
```

---

## Zero Runtime Dependencies

The core monitor and all 5 defense layers use only the Python standard library:

```toml
[project]
dependencies = []  # Zero runtime deps
```

Optional extras for advanced features:
- `pip install -e ".[dev]"` -- pytest and coverage
- `pip install -e ".[ml]"` -- scikit-learn for the ML classifier (Layer 6)
- `pip install -e ".[dpi]"` -- mitmproxy for deep packet inspection (Layer 10)

---

## License

MIT
