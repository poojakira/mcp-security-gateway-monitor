# MCP Security Gateway Monitor — Engineering & Program Document

**Status:** Active · **Version:** 0.1.0 · **Last updated:** 2026-07-10
**Owner:** poojakira · **Audience:** Engineering, Security, Product, Leadership
**Classification:** Internal — safe to share with reviewing partners

> This is the single source of truth for the project. It is written to be read at
> three depths: skim the **Executive Summary** and **section headers**; read a
> section for working knowledge; read the linked source files for implementation
> detail. It deliberately separates **what is proven** from **what is aspirational**.

---

## Table of Contents

**Part A — Non-Technical**
1. Executive Summary
2. Problem & Market Context
3. Product Scope & Positioning
4. Maturity Assessment (honest)
5. Risk Register
6. Compliance & Legal Posture
7. Roadmap
8. Ownership, RACI & Communication
9. Cost & Resourcing
10. Glossary

**Part B — Technical**
11. System Overview
12. Architecture & The 10-Layer Model
13. Request Lifecycle (data flow)
14. Component Reference
15. Public API Surface
16. Data & Persistence Model
17. Machine Learning: Design & Measured Results
18. Performance: Measured Results
19. Security & Threat Model
20. Testing Strategy
21. Deployment & Operations
22. Observability
23. Supply-Chain Security
24. Build, Run & Local Dev
25. Known Limitations & Failure Modes
26. Codebase Statistics & Layout

---
---

# PART A — NON-TECHNICAL

## 1. Executive Summary

The **MCP Security Gateway Monitor** is a security control that sits inline between
an AI agent and the external tools it calls over the **Model Context Protocol
(MCP)**. It inspects every tool call and every tool result, blocks malicious
activity, and writes a tamper-evident audit trail.

**Why it exists.** In mid-2026, the MCP ecosystem grew explosively and insecurely:
roughly 200,000 MCP servers were reachable with no authentication. In one
real-world incident, a compromised email MCP server silently added a hidden **BCC**
to every outgoing message, exfiltrating a copy of all mail to an attacker. The user
and the AI both saw a normal "email sent" response. This project is built to catch
exactly that class of silent, inline compromise.

**What it does today (proven):**
- Detects prompt injection, PII/secret leakage, calls to unregistered ("shadow")
  MCP servers, and data-exfiltration patterns including hidden BCC/CC.
- Maintains a **SHA-256 hash-chained** audit log with **write-ahead log (WAL)**
  crash recovery — tampering with any historical entry is detectable.
- Ships a full production surface: HTTP API, Docker/Kubernetes manifests,
  Prometheus metrics, structured logging, tracing, circuit breakers, rate
  limiting, graceful shutdown, and a security dashboard.
- **481 automated tests pass**, including property-based fuzzing.
- Core runtime has **zero third-party dependencies** (Python standard library only).

**What it is not (yet):** a battle-tested, SOC-2-certified commercial product. It
has no production traffic history, no external audit, and its ML adversarial
robustness has a measured, honestly-reported weakness (see §17). See §4.

---

## 2. Problem & Market Context

### 2.1 The threat
MCP standardizes how AI models call external tools. That standardization is exactly
what makes a single malicious or compromised server so dangerous: the model trusts
tool responses, and tool arguments/results are natural language the model may act
on. The attack surface includes:

- **Prompt injection** hidden inside tool-call arguments or tool outputs.
- **Silent exfiltration** — the BCC incident is the canonical example: the action
  the user asked for still happens, plus a hidden extra action.
- **Shadow servers** — the agent is redirected to an unregistered/untrusted server.
- **PII/secret leakage** — sensitive data flowing to tools that should not see it.

### 2.2 Why "monitor inline" is the right shape
Network firewalls and API gateways don't understand MCP semantics (intent vs. the
actual call). Model-side guardrails don't see server-side behavior. An **inline
monitor** at the MCP boundary is positioned to compare *stated intent* with *actual
tool call* and to inspect both directions — which is where the BCC attack is
visible and nowhere else.

### 2.3 Who cares
Any organization running AI agents with tool access: model providers, cloud
platforms hosting agent runtimes, and enterprises deploying internal agents. The
value proposition is "a firewall purpose-built for AI-to-tool communication."

*Content in this section is a factual summary of the incident context provided for
the project; specifics of the mid-2026 incident are as described in the project
brief.*

---

## 3. Product Scope & Positioning

**In scope:** inline inspection of MCP tool calls/results; detection + blocking;
tamper-evident audit; operational tooling to run it as a service.

**Out of scope (today):** authenticating MCP servers (assumes an external identity
layer), full TLS deep-packet inspection in the default build (optional `[dpi]`
extra), and being a managed SaaS.

**Positioning:** defense-in-depth control, deployable as a sidecar/gateway. It
complements — does not replace — server authentication, model alignment, and
network controls.

---

## 4. Maturity Assessment (Honest)

We grade the project the way a skeptical senior review board would. A control that
*claims* more maturity than it has is itself a risk.

| Dimension | Grade | Honest note |
|---|---|---|
| Core detection logic | Strong | Well-tested, fuzzed, documented. |
| Code quality / tests | Strong | 481 tests, 100% core coverage target, property-based fuzzing. |
| Performance | Strong | Sub-ms p99 measured (§18). |
| Operational tooling | Good | Docker/K8s/metrics/tracing present; not yet run at scale. |
| ML robustness | **Partial** | Clean-data metrics excellent; **adversarial catch 0.65** (§17). |
| Production hardening | Good | Circuit breakers, rate limits, shutdown — but no real traffic yet. |
| Compliance (SOC 2, etc.) | **None** | No audit, no attestation. Requires time + an auditor. |
| Battle-testing | **None** | Zero production incidents survived; no external users. |

**Bottom line:** this is high-quality engineering and a credible *foundation*. It is
**not** a finished, certified product. Reaching "world-class product" requires real
users, real traffic, a security audit, and time — none of which can be manufactured
in code alone.

---

## 5. Risk Register

| ID | Risk | Likelihood | Impact | Mitigation | Owner |
|----|------|-----------|--------|------------|-------|
| R1 | Adversarial evasion of ML (homoglyph/whitespace/base64) | High | High | Add Unicode-normalization pre-processor before classifier; regex layer still catches many; documented in §17 | ML |
| R2 | Regex detectors produce false positives, block legit traffic | Medium | High | Shadow/monitor mode, risk-score threshold tuning, allow-lists | Detection |
| R3 | Audit log disk fills / WAL corruption | Medium | Medium | WAL recovery + checkpointing; add disk-usage alert | Platform |
| R4 | Supply-chain CVE in optional `[dpi]` (mitmproxy) deps | Known | Low | Isolated to optional extra; core is zero-dep; allow-listed with review date | Security |
| R5 | Monitor becomes a latency bottleneck under load | Low | High | Measured sub-ms p99; horizontal scaling; circuit breaker fail-open/closed policy | Platform |
| R6 | Over-trust: teams treat it as complete security | Medium | High | This document; explicit limitations in README/SECURITY.md | Leadership |

---

## 6. Compliance & Legal Posture

- **Licensing:** core is pure Python stdlib → minimal third-party license exposure.
  A CycloneDX **SBOM** (`sbom.json`) enumerates components for downstream review.
- **Data handling:** the monitor processes tool arguments/outputs which **may
  contain PII**. The PII detector can redact; deployers must define retention for
  audit logs (audit entries may contain metadata about flagged content). See
  `SECURITY.md` and §16.
- **Certifications:** none held. SOC 2 / ISO 27001 would require an external audit,
  documented controls, and an observation window.
- **Vulnerability disclosure:** policy documented in `SECURITY.md`.

*Not legal advice; a qualified reviewer should confirm obligations for your
jurisdiction and data types before production use.*

---

## 7. Roadmap

**Near-term (closes known code gaps):**
- Unicode/whitespace/base64 **normalization layer** to fix R1 (biggest single win).
- Tune detector thresholds against a labeled corpus to reduce false positives.
- Disk-usage / audit-growth alerting.

**Mid-term (requires environment):**
- Optional TLS DPI hardened and supported (currently `[dpi]` extra).
- Real-traffic shadow-mode pilot to calibrate precision/recall in the wild.
- Persistent, queryable audit store (beyond append-only file).

**Long-term (requires org investment):**
- External security audit → SOC 2 Type II.
- Managed/hosted offering with multi-tenant isolation.
- Model-assisted semantic detection (LLM-in-the-loop) with cost/latency budget.

---

## 8. Ownership, RACI & Communication

- **Primary owner / maintainer:** poojakira (GitHub).
- **Source of truth:** this repository; `main` is protected (CI + test-count gate).
- **Change process:** feature branch → PR → CI green (481 tests on Python 3.9–3.13)
  → review → merge. CI files cannot be pushed directly to `main`.
- **Security issues:** follow `SECURITY.md` (private disclosure).

| Activity | Responsible | Accountable | Consulted | Informed |
|---|---|---|---|---|
| Detection logic changes | Detection eng | Maintainer | Security | All |
| ML model updates | ML eng | Maintainer | Detection | All |
| Deployment/infra | Platform eng | Maintainer | Security | All |
| Release / versioning | Maintainer | Maintainer | — | All |

---

## 9. Cost & Resourcing

- **Runtime cost:** low — pure-Python, CPU-bound, no external services required for
  the core. Scales horizontally across processes/pods.
- **Optional cost:** `[ml]` extra adds scikit-learn/numpy (memory + CPU for
  training/inference); `[dpi]` adds mitmproxy (heavier, out-of-band).
- **People:** ongoing maintenance realistically needs at least a detection engineer
  and a platform engineer part-time; a security reviewer for audits.

---

## 10. Glossary

- **MCP** — Model Context Protocol; standard for AI-to-tool calls.
- **Tool call** — a structured request from the agent to an external tool
  (`{name, server_id, arguments}`).
- **Shadow server** — an MCP server that is not on the registered/allowed list.
- **BCC injection** — hidden recipient added to an email tool call to exfiltrate.
- **Hash chain** — each audit entry's hash includes the previous entry's hash, so
  any edit breaks the chain.
- **WAL** — Write-Ahead Log; durability mechanism enabling crash recovery.
- **p50/p95/p99** — latency percentiles (median / tail / far-tail).
- **Shadow mode** — monitor observes and logs but does not block.

---
---

# PART B — TECHNICAL

## 11. System Overview

A stdlib-only Python package (`mcp_monitor`) that inspects MCP tool calls and
outputs. Two entry points matter most:

- `MCPSecurityMonitor.inspect_call(tool_call)` — inbound tool call verdict.
- `MCPSecurityMonitor.inspect_output(tool_name, output)` — outbound result verdict.

Both return `{allowed, risk_score, findings, call_id}` and append to the audit log
**regardless of verdict** (every decision is recorded).

- **Language/runtime:** Python ≥ 3.9 (tested through 3.13).
- **Core dependencies:** none. Optional extras: `[dev]`, `[ml]`, `[dpi]`.
- **Size:** ~12,600 lines of Python across `src/`, `tests/`, `benchmarks/`,
  `scripts/`.

---

## 12. Architecture & The 10-Layer Model

The project is layered so that a call must survive **every** layer; any single trip
blocks and records. Not all layers are enabled in every deployment — the base
`MCPSecurityMonitor` is layers L1-ish; `Defense10` composes the full stack.

```
L1  Application detectors     regex injection, PII, shadow-server, exfiltration
L2  Inline proxy enforcement  wraps the tool-call boundary
L3  Kernel/network monitor    /proc + eBPF-style view of server-side calls
L4  Semantic + ML classifier  learned threat scoring (opaque to attacker)
L5  Network egress policy     outbound allow/deny
L6  DPI egress inspection     compares stated MCP intent vs actual call  ← key
L7  Rate limiting             caps blast radius (e.g., emails/hour)
L8  Recipient whitelist       unknown recipients never auto-approved
L9  Honeypot canaries         zero-false-positive proof of compromise
L10 Sandbox isolation         kernel-enforced execution boundary
```

**Module → layer mapping:**

| Layer | Module(s) |
|---|---|
| L1 | `detectors/prompt_injection.py`, `pii_detector.py`, `shadow_server.py`, `exfiltration.py` |
| L2 | `layers/proxy.py` |
| L3 | `defense10/network_monitor.py`, `layers/kernel.py` |
| L4 | `layers/semantic.py`, `defense10/ml_classifier.py`, `defense10/features.py` |
| L5 | `layers/egress.py` |
| L6 | `defense10/egress_proxy.py` (IntentRegistry + EgressInspector) |
| L7 | `defense10/rate_limiter.py`, `production/rate_limiter.py` |
| L8 | `defense10/rate_limiter.py` (RecipientWhitelist) |
| L9 | `defense10/honeypot.py` |
| L10 | `defense10/sandbox.py` |
| Orchestration | `monitor.py` (base), `defense10/orchestrator10.py` (`Defense10`), `layers/orchestrator.py` |
| Audit | `audit/log.py`, `audit/wal.py` |
| Advanced analytics | `advanced/` (canary, correlation, drift, invariants, manifest) |
| Red team | `redteam/` (payloads, simulator) |
| Production | `production/` (server, metrics, tracing, logging, alerting, circuit_breaker, shutdown, config) |

**Design principle:** *defense in depth with fail-safe recording.* Even if a
detector is wrong, the audit log preserves an immutable record of the decision.

---

## 13. Request Lifecycle (Data Flow)

**`inspect_call(tool_call)`** in `monitor.py`:

1. Generate a `call_id` (UUID4).
2. **Prompt injection** — `PromptInjectionDetector.detect` recursively scans all
   string values in `arguments`; on hit, adds `prompt_injection:<pattern>` findings
   and a risk contribution.
3. **PII** — `PIIDetector.scan_tool_call`; on hit, adds `pii:<type>:<count>` and a
   risk contribution scaled by number of PII types.
4. **Shadow server** — `ShadowServerDetector.detect` on `server_id`; a shadow
   server contributes risk 80 and forces `allowed = False`.
5. **Exfiltration** — `ExfiltrationDetector.detect` on the arguments (treated as
   partial output): BCC/CC, payload size, suspicious URLs.
6. **Final verdict** — `risk_score = min(max(contributions, default=0), 100)`;
   `allowed = risk_score < 50 and not is_shadow`.
7. **Audit append** — always logs `tool_call_inspected` with call_id, tool_name,
   allowed, risk_score, findings.
8. Return `{allowed, risk_score, findings, call_id}`.

**`inspect_output(tool_name, output)`** mirrors this for results: exfiltration check
+ PII-in-output check, same verdict/threshold/audit pattern
(`tool_output_inspected`).

**Fail-safe rule:** logging happens on the success path of every inspection so the
decision trail is complete; a shadow server is a hard block independent of score.

---

## 14. Component Reference

### 14.1 Detectors (`src/mcp_monitor/detectors/`)

- **`prompt_injection.py` — `PromptInjectionDetector`**
  - `INJECTION_PATTERNS`: ≥10 regexes (ignore-previous-instructions,
    system/admin override, "forget everything", jailbreak persona, `<system>` tag
    injection, etc.).
  - `detect(tool_call) -> (bool, list[str])` — recursive scan of all string values.
  - `risk_score(tool_call) -> int` (0–100).

- **`pii_detector.py` — `PIIDetector`**
  - `PII_PATTERNS`: ≥8 types (email, SSN, credit card, US phone, IP, and more).
  - `detect(text) -> dict[type, [values]]`.
  - `redact(text, replacement="[REDACTED]") -> str` — **uses a replacement
    *function*, not a template**, so replacement strings containing regex escapes
    (`\A`, `\1`) cannot crash it (fixed via fuzzing; see §20).
  - `scan_tool_call(tool_call) -> (bool, dict)`.

- **`shadow_server.py` — `ShadowServerDetector`**
  - `__init__(allowed_servers: set[str])`, `register_server(id, capabilities)`.
  - `detect(tool_call) -> (is_shadow, reason)` on the `server_id` field.
  - `score_server_trust(server_id) -> int` (0–100).

- **`exfiltration.py` — `ExfiltrationDetector`**
  - `__init__(max_payload_kb=100.0)`.
  - `detect(tool_name, output) -> (bool, list[str])`: BCC/CC on email tools,
    payload size, suspicious/base64 payloads and outbound URLs.
  - `detect_bcc_injection(email_payload) -> bool` — targets the real incident.

### 14.2 Audit (`src/mcp_monitor/audit/`)
- **`log.py` — `AuditLog` / `AuditEntry`** — SHA-256 hash-chained log; see §16.
- **`wal.py` — `WriteAheadLog`** — atomic write, `recover()`, `checkpoint()`.

### 14.3 Orchestrators
- **`monitor.py` — `MCPSecurityMonitor`** — base 4-detector orchestrator + audit.
- **`defense10/orchestrator10.py` — `Defense10`** — composes all 10 layers, returns
  a `Verdict10` (`allowed`, `blocked_by`, `reasons`, `layers_passed`, `severity`).

### 14.4 Production (`src/mcp_monitor/production/`)
HTTP `server.py` (versioned `/v1` API), `metrics.py` (Prometheus), `tracing.py`,
`logging.py` (structured JSON), `alerting.py`, `circuit_breaker.py`,
`rate_limiter.py`, `shutdown.py` (graceful), `config.py` (env-driven).

### 14.5 Advanced analytics (`src/mcp_monitor/advanced/`)
`canary`, `correlation`, `drift`, `invariants`, `manifest` — longer-horizon signals
(behavioral drift, cross-call correlation, capability manifests, canary tokens).

### 14.6 Red team (`src/mcp_monitor/redteam/`)
`payloads.py` + `simulator.py` — attack corpus + harness to exercise detectors.

---

## 15. Public API Surface

**Python (package `__init__`):**
```python
from mcp_monitor import MCPSecurityMonitor, AuditLog, WriteAheadLog

monitor = MCPSecurityMonitor(allowed_servers={"github", "postmark"},
                             audit_log=AuditLog("audit.log"))
verdict = monitor.inspect_call({
    "name": "postmark.send_email",
    "server_id": "postmark",
    "arguments": {"to": ["a@x.com"], "bcc": ["thief@evil.tk"]},
})
# -> {"allowed": False, "risk_score": ..., "findings": [...], "call_id": "..."}
```

**HTTP:** `production/server.py` exposes a versioned `/v1` API for `inspect_call` /
`inspect_output` plus health/metrics endpoints (see §21–22).

---

## 16. Data & Persistence Model

### 16.1 `AuditEntry`
Fields: `entry_id`, `timestamp`, `event_type`, `data`, `prev_hash`, `entry_hash`.

```
entry_hash = SHA-256(prev_hash + timestamp + event_type + str(data))
```

### 16.2 `AuditLog` guarantees
- **Append-only**, file-backed.
- `append(event_type, data) -> AuditEntry`.
- `verify_chain() -> (intact: bool, broken_at_index: int | None)` — recomputes the
  chain; any edit to a historical entry changes its hash and breaks every
  subsequent link, so tampering is detectable and localizable.
- `tail(n)`, `export_json()`.

### 16.3 `WriteAheadLog` (crash safety)
- `write(entry)` — atomic append before the entry is considered durable.
- `recover()` — on startup, replays uncommitted WAL entries so no acknowledged
  entry is lost after a crash.
- `checkpoint()` — marks WAL entries committed.

**Retention:** audit files grow unbounded by default — operators must rotate/retain
per policy (§6). Entries can contain metadata about flagged content; treat as
sensitive.

---

## 17. Machine Learning: Design & Measured Results

**Modules:** `defense10/ml_classifier.py` (`MLThreatClassifier`),
`defense10/features.py`, `defense10/dataset.py`, `defense10/ml_eval.py`.

- **Dataset:** 6,120 diverse samples across 7 attack families + 10 benign families;
  classifier trains on 5,202.
- **Evaluation method:** train on one seed, evaluate on a **held-out split generated
  from a different seed** (genuinely unseen combinations), via `ml_eval.py`.

**Measured clean-data metrics (held-out):**

| Metric | Value |
|---|---|
| Precision | 1.0000 |
| Recall | 0.9893 |
| F1 | 0.9946 |
| False-positive rate | 0.0000 |

**Measured adversarial robustness (honestly reported):**

| Evasion | Catch rate |
|---|---|
| Synonym swap | ~0.99 |
| Homoglyph | ~0.56 |
| Whitespace injection | ~0.51 |
| Base64 wrapping | ~0.54 |
| **Overall** | **~0.65** |

**Interpretation (no spin):** the classifier is excellent on clean and lightly
perturbed inputs but roughly a coin-flip against deliberate obfuscation. The fix is
a **normalization pre-processing layer** (Unicode fold, whitespace collapse, base64
decode-and-rescan) *before* both the ML and regex stages — this is the single
highest-value roadmap item (R1). The ML layer is one of ten; regex/exfil/shadow
layers still catch many obfuscated attacks the classifier misses.

Run it yourself: `python -m mcp_monitor.defense10.ml_eval` (requires `[ml]` extra).

---

## 18. Performance: Measured Results

Measured on the dev/CI sandbox, single thread, 20,000 iterations after a
2,000-iteration warm-up, realistic 80/20 benign:attack workload, **audit append
included**. Harness: `benchmarks/benchmark.py` (timer: `time.perf_counter_ns`).

| Path | p50 | p95 | p99 | mean | throughput |
|---|---|---|---|---|---|
| `inspect_call` (+audit) | 68.3 µs | 95.7 µs | 113.0 µs | 71.0 µs | ~14,000 calls/sec |
| `inspect_output` (+audit) | 52.0 µs | 60.2 µs | 80.5 µs | 55.0 µs | ~18,000 calls/sec |

**Reading these numbers:**
- **Sub-millisecond p99.** Against a typical LLM tool round-trip of hundreds of ms,
  the monitor adds well under 0.1% latency in a realistic agent loop.
- **~14k calls/sec/core**, scales horizontally (each inspection is independent; only
  shared state is the append-only audit log).
- Numbers are **hardware-dependent** — re-run on your target. `test_benchmark.py`
  asserts invariants (percentile ordering, positivity), not absolute latencies.
- Not measured here: the `[ml]` classifier and `[dpi]` DPI path (heavier,
  out-of-band, not on the core hot path).

Run: `python benchmarks/benchmark.py [--iterations N] [--json]`.

---

## 19. Security & Threat Model

**Trust boundary:** the monitor is the choke point between the agent and the tools.
It assumes it runs in a trusted process; it does **not** assume the MCP servers or
tool responses are trustworthy.

**Threats addressed:** prompt injection in arguments/outputs, hidden BCC/CC
exfiltration, oversized/encoded payload exfiltration, suspicious outbound URLs,
calls to unregistered servers, PII/secret leakage, audit tampering.

**Threats *not* fully addressed:** determined ML evasion via obfuscation (§17);
attacks that require authenticating the server's identity (assumes external
identity); anything outside the MCP boundary.

**Fail policy:** shadow servers hard-block; other signals accumulate into a risk
score with a threshold. Deployers choose **fail-open vs fail-closed** via the
circuit breaker for availability-vs-safety trade-offs.

Full policy and disclosure process: `SECURITY.md`.

---

## 20. Testing Strategy

- **481 tests pass** on Python 3.9–3.13 in CI. A CI gate asserts the exact count
  (guards against silent test loss).
- **Unit tests** per detector and audit component (original spec: 105; now expanded).
- **Property-based fuzzing** (`tests/test_fuzz.py`, Hypothesis): 14 tests across all
  detectors + monitor. Found and fixed **10 real crash bugs** on malformed input —
  notably a `re.sub` backreference crash in `PIIDetector.redact` (a
  denial-of-service via a crafted replacement string), now fixed.
- **Coverage:** 100% core coverage is the target (`test_coverage_100.py`).
- **Cross-platform** (`test_cross_platform.py`) and **deployment**
  (`test_deployment.py`) tests.
- **Benchmark smoke tests** (`test_benchmark.py`) assert harness invariants without
  flaky absolute-latency assertions.

Run: `python -m pytest tests/ -q` (full suite ~2 min).

---

## 21. Deployment & Operations

- **Container:** `Dockerfile` (multi-stage), `docker-compose.yml` for local stack.
- **Kubernetes:** `deploy/k8s/` — `namespace`, `deployment`, `service`, `configmap`,
  `hpa` (horizontal pod autoscaler).
- **HTTP service:** `production/server.py`, versioned `/v1` API.
- **Config:** `production/config.py` — environment-variable driven (12-factor).
- **Resilience:** `circuit_breaker.py` (fail-open/closed), `rate_limiter.py`,
  `shutdown.py` (graceful drain).
- **Modes:** shadow mode (observe-only) for safe rollout before enforcing.
- **Load testing:** `locustfile.py`.

**Rollout guidance:** deploy in **shadow mode** first, calibrate thresholds against
real traffic (watch false positives, R2), then switch to enforcing.

---

## 22. Observability

- **Metrics:** Prometheus via `production/metrics.py` (counts, verdicts, latencies).
- **Tracing:** `production/tracing.py`.
- **Logging:** structured JSON (`production/logging.py`) — machine-parseable.
- **Alerting:** `production/alerting.py`.
- **Dashboard:** `run_dashboard.py` renders a security dashboard
  (`dashboard/report.py`, `terminal.py`). Note: the generated
  `security_dashboard.html` is a build artifact and is git-ignored.

**Recommended SLOs to add:** p99 inspection latency, block rate, audit-chain
verification success, WAL recovery events, disk usage of audit store.

---

## 23. Supply-Chain Security

- **SBOM:** `sbom.json` (CycloneDX 1.6) enumerates components.
- **Policy:** `SECURITY.md` (threat model + disclosure).
- **Automated:** `.github/dependabot.yml`, `.github/workflows/security.yml`.
- **Audit gate:** `scripts/pip_audit_gate.py` — stdlib-only, severity-aware, fails
  CI on non-allow-listed HIGH/CRITICAL findings. Allow-list:
  `security/audit-allowlist.txt`; latest scan: `security/dependency-audit.txt`.
- **Honest finding:** the zero-dependency **core is clean**. The only 5 advisories
  (3 HIGH) live in `mitmproxy`'s transitive tree behind the optional `[dpi]` extra
  and are unfixable due to upstream pins — logged as **accepted risk with a review
  date**, not silently ignored.

---

## 24. Build, Run & Local Dev

**Linux/macOS:**
```bash
python3 -m venv .venv && source .venv/bin/activate
python3 -m pip install -e ".[dev]"
python3 -m pytest tests/ -v
python3 benchmarks/benchmark.py
python3 run_dashboard.py
```

**Windows PowerShell:**
```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest tests/ -v
```

**Extras:** `[dev]` (pytest, coverage, hypothesis, scikit-learn, numpy, pyyaml),
`[ml]` (scikit-learn, numpy), `[dpi]` (mitmproxy — optional, has known CVEs).

**Branch/CI:** feature branch → PR → CI (5 Python versions + 481-test gate +
coverage + security scan) → review → merge to protected `main`.

---

## 25. Known Limitations & Failure Modes

1. **ML adversarial weakness (~0.65)** — obfuscation evades the classifier; needs a
   normalization layer (R1). *Documented, not hidden.*
2. **Regex false positives** — pattern-based detection can over-fire; requires
   threshold tuning per deployment (R2).
3. **Audit log growth** — unbounded by default; operators must rotate/retain (R3).
4. **No server authentication** — assumes an external identity layer.
5. **DPI extra carries CVEs** — optional, isolated, accepted-risk (R4).
6. **No production history** — never faced real adversaries at scale (§4).
7. **Single-process shared audit file** — horizontal scaling needs a shared/rotated
   audit strategy for a unified chain.

---

## 26. Codebase Statistics & Layout

- **~12,600 lines of Python** across `src/`, `tests/`, `benchmarks/`, `scripts/`.
- **481 tests**, Python 3.9–3.13.
- **Zero runtime dependencies** (core).

```
mcp-security-gateway-monitor/
├── src/mcp_monitor/
│   ├── monitor.py                 # base orchestrator (MCPSecurityMonitor)
│   ├── detectors/                 # L1: prompt_injection, pii, shadow_server, exfiltration
│   ├── audit/                     # log.py (hash chain), wal.py (crash safety)
│   ├── layers/                    # 5-layer defense: proxy, kernel, semantic, egress, orchestrator
│   ├── defense10/                 # 10/10 stack: ml_classifier, features, dataset, ml_eval,
│   │                              #   egress_proxy, network_monitor, rate_limiter, honeypot,
│   │                              #   sandbox, orchestrator10
│   ├── advanced/                  # canary, correlation, drift, invariants, manifest
│   ├── production/                # server, metrics, tracing, logging, alerting,
│   │                              #   circuit_breaker, rate_limiter, shutdown, config
│   ├── redteam/                   # payloads, simulator
│   └── dashboard/                 # report, terminal
├── tests/                         # 17 test modules incl. fuzz + benchmark smoke
├── benchmarks/                    # benchmark.py + README (measured numbers)
├── scripts/                       # pip_audit_gate.py
├── security/                      # audit-allowlist.txt, dependency-audit.txt
├── deploy/k8s/                    # namespace, deployment, service, configmap, hpa
├── Dockerfile, docker-compose.yml, locustfile.py, run_dashboard.py
├── sbom.json, SECURITY.md, RESEARCH_REPORT.md
├── pyproject.toml, README.md, CHANGELOG.md
└── .github/workflows/{ci.yml,security.yml}, dependabot.yml
```

---

### Appendix — Honesty Statement

This document distinguishes measured facts (performance, test counts, ML metrics)
from aspirations (roadmap, certifications). Where a number is weak — notably ML
adversarial catch (~0.65) — it is reported as-is. A security control that
overstates its own maturity is a liability; this project is a strong, well-tested
**foundation**, and reaching a certified, battle-tested product requires real
users, real traffic, an external audit, and time.
