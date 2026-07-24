# mcp-security-gateway-monitor

[![CI](https://github.com/poojakira/mcp-security-gateway-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/mcp-security-gateway-monitor/actions/workflows/ci.yml)
[![Python >=3.10](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Project Status

**Maturity**: Beta — Core 5 layers are stable; Defense10 (Layer 6+) is experimental.

This repository provides an MCP tool-call security monitor with 5 deterministic rule-based detection layers and an experimental Defense10 extension (Layer 6+).

## Core Layers (Stable)

1. **Proxy Layer** — Schema validation, request/response inspection
2. **Kernel Layer** — System call monitoring, process execution tracking
3. **Semantic Layer** — Prompt injection, PII detection, exfiltration intent
4. **Shadow Layer** — Unregistered server detection, capability drift
5. **Egress Layer** — Network egress monitoring, BCC injection detection, payload size limits

## Defense10 — Experimental Layer 6+ (Beta)

These are functional implementations that supplement the core 5 layers. They run behind the deterministic layers and provide supplementary signals. **Do not rely on them as a standalone defense.**

| Component | File | Description | Maturity |
|-----------|------|-------------|----------|
| **ML Threat Classifier** | `src/mcp_monitor/defense10/ml_classifier.py` | TF-IDF char n-grams + structural features -> LogisticRegression. Trains on synthetic corpus + red-team loop. | BETA |
| **Docker Sandbox** | `src/mcp_monitor/defense10/sandbox.py` | Docker-based network isolation for untrusted MCP servers. | BETA |
| **Network Monitor** | `src/mcp_monitor/defense10/network_monitor.py` | `/proc/net/tcp` live monitor + optional eBPF C program for host deployments. | BETA |
| **Egress Proxy** | `src/mcp_monitor/defense10/egress_proxy.py` | mitmproxy DPI addon comparing MCP intent vs actual HTTP calls (BCC, destinations, payload size). | BETA |
| **Rate Limiter** | `src/mcp_monitor/defense10/rate_limiter.py` | Blast-radius limiting with recipient whitelists. | Stable |
| **Honeypot** | `src/mcp_monitor/defense10/honeypot.py` | Canary tokens that trigger when exfiltrated. | Stable |
| **Orchestrator10** | `src/mcp_monitor/defense10/orchestrator10.py` | Unifies Layers 1-5 + Defense10 with unified `Verdict10`. | BETA |

## Installation

```bash
pip install -e .[defense10]
```

Required for Defense10:
- Docker (for sandbox)
- mitmproxy (for egress proxy)
- Linux with eBPF support (for network monitor kernel module, optional)

## Honest Performance Claims

| Component | Synthetic Benchmark | Real-World (Held-out) | Status |
|-----------|---------------------|----------------------|--------|
| ML Classifier | CV accuracy ~0.98 | Recall ~0.317, FP ~14% | BETA |
| Sandbox | N/A | Requires Docker, not a kernel boundary | BETA |
| Network Monitor | N/A | Polling-based; eBPF needs root | BETA |
| Egress Proxy | N/A | mitmproxy addon; no TLS inspection | BETA |

**Do not use Defense10 as a standalone defense.** It supplements the deterministic Layers 1-5.

## Quick Start

```python
from mcp_monitor.defense10 import Defense10, MLThreatClassifier, DockerSandbox

# ML Classifier (BETA)
clf = MLThreatClassifier(threshold=0.6)
metrics = clf.train()  # trains on synthetic corpus + red-team samples
print(f"CV accuracy: {metrics['cv_accuracy']:.3f}")  # ~0.98 on synthetic corpus

# NOTE: On held-out deepset/prompt-injections benchmark:
# Recall ≈ 0.317, FP rate ≈ 14% on benign text
# Use as SUPPLEMENTARY signal only.

# Sandbox (BETA)
sandbox = DockerSandbox(SandboxConfig(memory="512m", cpus="0.5", network="none"))
result = sandbox.run("untrusted_server.py", args=["--port", "8080"])
```

## MITRE ATT&CK v19 Coverage

[... existing ATT&CK content preserved ...]