# Defense10 — MCP Security Layer 6+

**Status**: BETA — Experimental components that supplement the core 5 deterministic layers.

These are *functional implementations* (not policy stubs) designed to push detection toward 10/10. They run behind the deterministic rule-based layers (1–5) and provide supplementary signals. **Do not rely on them as a standalone defense.**

---

## Components

| Component | File | Description | Maturity |
|-----------|------|-------------|----------|
| **ML Threat Classifier** | `ml_classifier.py` | TF-IDF char n-grams + structural features → LogisticRegression. Trains on synthetic corpus + red-team loop. | BETA |
| **Docker Sandbox** | `sandbox.py` | Docker-based network isolation for untrusted MCP servers. Runs tool calls in isolated containers. | BETA |
| **Network Monitor** | `network_monitor.py` | `/proc/net/tcp` live monitor + optional eBPF C program for host deployments. | BETA |
| **Egress Proxy** | `egress_proxy.py` | mitmproxy DPI addon comparing MCP intent vs actual HTTP calls (BCC, destinations, payload size). | BETA |
| **Rate Limiter** | `rate_limiter.py` | Blast-radius limiting with recipient whitelists. | Stable |
| **Honeypot** | `honeypot.py` | Canary tokens that trigger when exfiltrated. | Stable |
| **Orchestrator10** | `orchestrator10.py` | Unifies Layers 1–5 + Defense10 with unified `Verdict10`. | BETA |

---

## Installation

```bash
pip install -e .[defense10]
```

Required for Defense10:
- Docker (for sandbox)
- mitmproxy (for egress proxy)
- Linux with eBPF support (for network monitor kernel module, optional)

---

## Quick Start

```python
from mcp_monitor.defense10 import Defense10, MLThreatClassifier, DockerSandbox

# ML Classifier (BETA)
clf = MLThreatClassifier(threshold=0.6)
metrics = clf.train()  # trains on synthetic corpus + red-team generated samples
print(f"CV accuracy: {metrics['cv_accuracy']:.3f}")  # ~0.98 on synthetic corpus

# NOTE: On held-out deepset/prompt-injections benchmark:
# Recall ≈ 0.317, FP rate ≈ 14.3% on benign text
# Use as SUPPLEMENTARY signal only.

# Sandbox (BETA)
sandbox = DockerSandbox(SandboxConfig(memory="512m", cpus="0.5", network="none"))
result = sandbox.run("untrusted_server.py", args=["--port", "8080"])

# Orchestrator (BETA)
from mcp_monitor import MCPSecurityMonitor
from mcp_monitor.defense10 import Defense10

monitor = MCPSecurityMonitor(allowed_servers={"github", "email"})
defense10 = Defense10(allowed_servers={"github", "email"})
verdict = defense10.inspect_call(tool_call_dict)
```

---

## ML Classifier — Honest Performance

| Metric | Synthetic Corpus (CV) | Held-out `deepset/prompt-injections` |
|--------|----------------------|--------------------------------------|
| Recall | ~0.98 | **0.317** |
| False Positive Rate | ~0.02 | **0.143** |
| Precision | ~0.98 | ~0.44 |

**Why the gap?** The synthetic corpus covers known obfuscation patterns. Real jailbreaks use novel compositions. The classifier is a *supplementary signal*, not a standalone defense.

### Training

```python
from mcp_monitor.defense10.ml_classifier import MLThreatClassifier

clf = MLThreatClassifier(threshold=0.6)
metrics = clf.train(
    malicious=custom_malicious_samples,  # optional
    benign=custom_benign_samples,        # optional
)
# Returns: {"trained": True, "cv_accuracy": 0.98, "n_malicious": ..., "n_benign": ...}
```

### Checkpoint Integrity

Models are saved with SHA-256 integrity checks:

```python
clf.save("model.joblib")           # writes model.joblib + model.joblib.sha256
clf.load("model.joblib")           # verifies SHA-256 before loading
```

---

## Sandbox (BETA)

```python
from mcp_monitor.defense10.sandbox import DockerSandbox, SandboxConfig

config = SandboxConfig(
    memory="512m",
    cpus="0.5",
    network="none",        # "none" | "bridge" | "host"
    timeout=30,
    read_only=True,
)

sandbox = DockerSandbox(config)
result = sandbox.run("untrusted_mcp_server.py", args=["--port", "8080"])
# Returns: {"stdout": "...", "stderr": "...", "exit_code": 0, "timed_out": False}
```

**Limitations**: Requires Docker daemon. Not a security boundary for kernel exploits.

---

## Egress Proxy (BETA)

```python
from mcp_monitor.defense10.egress_proxy import EgressInspector, IntentRegistry

registry = IntentRegistry()
registry.allow("postmark.send_email", ["api.postmarkapp.com"])
registry.allow("slack.send", ["hooks.slack.com"])

inspector = EgressInspector(registry)
result = inspector.inspect(
    tool_name="postmark.send_email",
    arguments={"to": "user@example.com", "bcc": "attacker@evil.com"},
    http_response=mock_response,
)
# Returns list of findings: ["hidden BCC recipient detected", ...]
```

---

## Network Monitor (BETA)

```python
from mcp_monitor.defense10.network_monitor import NetworkMonitor

monitor = NetworkMonitor()
alerts = monitor.check_connections()
# Checks: unauthorized outbound connections, unexpected ports, known C2 IPs
```

**Linux eBPF**: For production, compile and load the eBPF C program in `network_monitor/ebpf/` for kernel-level visibility without polling overhead.

---

## Honeypot (Stable)

```python
from mcp_monitor.defense10.honeypot import HoneypotVault

vault = HoneypotVault()
token = vault.mint("github.token", metadata={"repo": "private"})
# Embed token in fake config file or environment
# If token appears in any tool output → immediate alert
```

---

## Rate Limiter (Stable)

```python
from mcp_monitor.defense10.rate_limiter import RateLimiter, RecipientWhitelist

whitelist = RecipientWhitelist(["trusted@company.com"])
limiter = RateLimiter(max_per_minute=60, whitelist=whitelist)

allowed = limiter.check("email.send", {"to": "user@company.com"})
```

---

## Orchestrator10 (BETA)

```python
from mcp_monitor.defense10.orchestrator10 import Defense10, Verdict10

defense10 = Defense10(allowed_servers={"github", "email", "slack"})
verdict = defense10.inspect_call(tool_call_dict)
# verdict: Verdict10(allowed=bool, risk_score=float, findings=list, layer_breakdown=dict)
```

---

## Testing

```bash
pip install -e .[dev]
pytest tests/test_defense10.py -v
```

---

## Known Limitations

| Component | Limitation |
|-----------|------------|
| ML Classifier | Low recall on novel jailbreaks (~0.32). High FP on obfuscated benign text. |
| Sandbox | Requires Docker; not a kernel security boundary. |
| Network Monitor | Polling-based on Linux; eBPF requires kernel headers and root. |
| Egress Proxy | mitmproxy addon; cannot inspect TLS without MITM cert. |
| ML Classifier | Trained on synthetic data; real-world recall ~0.32. |

---

## Architecture

```
Layer 1: Proxy (schema, schema validation)
Layer 2: Kernel (syscall, process, file)
Layer 3: Semantic (injection, PII, exfiltration intent)
Layer 4: Shadow (unknown server, capability drift)
Layer 5: Egress (BCC, data size, destination)
─────────────────────────────────────────────
Layer 6+: Defense10 (ML, Sandbox, Network, Proxy, Honeypot, Rate Limit)
```

All Defense10 findings are tagged with `layer >= 6` and lower default weights in the final risk score.

---

## Contributing

Defense10 is BETA. Contributions welcome:

1. Add attack samples to `ml_classifier.py:_MALICIOUS_SAMPLES`
2. Add benign samples to `ml_classifier.py:_BENIGN_SAMPLES_EXT`
3. Improve eBPF program in `network_monitor/ebpf/`
4. Add new threat families to `ml_classifier.py:_THREAT_FAMILIES`

---

## License

MIT — see [LICENSE](../LICENSE)