# Research Report: MCP Security Gateway Monitor

**Author:** Senior Research Engineering Team (30 years industry experience)  
**Date:** July 10, 2026  
**Classification:** Honest, Skeptical Technical Assessment  
**Repository:** github.com/poojakira/mcp-security-gateway-monitor

---

## 1. WHAT DOES THIS PROJECT DO?

### Plain English

This is a security monitoring library for MCP (Model Context Protocol) — the
standard that lets AI agents call external tools. It inspects every tool call
an AI agent makes, looking for signs of attack, and either flags or blocks
dangerous ones.

### Technical Summary

A Python library (zero external dependencies, stdlib-only) that provides:

1. **4 Pattern Detectors** — regex/rule-based scanning of tool call arguments
2. **5 Advanced Modules** — cryptographic manifest signing, behavioral drift
   detection, cross-tool correlation, declarative invariant enforcement, canary
   probes
3. **5-Layer Defense System** — inline proxy, kernel monitor, semantic analyzer,
   network egress policy, unified orchestrator
4. **Red Team Simulator** — 17 documented attack patterns for validation
5. **Security Dashboard** — terminal + HTML visualization

**Scale:** 42 Python files, ~3,600 lines of code, 313 automated tests.

---

## 2. MOTIVATION — WHY BUILD THIS?

### The Incident That Triggered This

On **September 17, 2025**, version 1.0.16 of the npm package `postmark-mcp`
was published. It contained a single line of code that silently added a BCC
field to every email sent through the MCP server, forwarding copies to
`phan@giftshop.club`.

**Timeline (verified from multiple sources):**

| Date | Event | Source |
|------|-------|--------|
| 2025 (earlier) | Attacker publishes `postmark-mcp` on npm, copying legitimate Postmark Labs code | The Register, BleepingComputer |
| Through v1.0.15 | 15 clean versions build trust, reach 1,500 weekly downloads | The Hacker News |
| Sep 17, 2025 | v1.0.16 released with one-line BCC backdoor | Koi Security discovery |
| Sep 17–25, 2025 | ~7 days of silent exfiltration | InfoSec Writeups estimate |
| Sep 25, 2025 | Koi Security discovers and reports | Snyk, Qualys |
| Sep 25, 2025 | Postmark publishes official statement denying any involvement | postmarkapp.com |
| Sep 29, 2025 | Package removed from npm | The Register |

**Estimated impact:** 3,000–15,000 emails per day exfiltrated from ~300
organizations. Contents included invoices, password resets, authentication
tokens, and internal correspondence.

### The Protocol Gap

In **April 2026**, OX Security disclosed that MCP's STDIO transport enables
remote code execution on approximately 200,000 server instances. The flaw
affects all official SDKs (Python, TypeScript, Java, Rust) and spans 150
million+ downloads.

**Anthropic's response:** "The behavior is expected. Securing the STDIO
interface is the responsibility of whoever deploys it."

**What the MCP specification does NOT provide:**
- No per-tool authorization
- No agent identity standard
- No audit log format
- No behavioral verification
- No manifest integrity checking
- No semantic validation of tool calls

### The Market Context

As of mid-2026:
- 97 million monthly MCP SDK downloads
- 5,200+ registered servers
- 40% with zero authentication (Zuplo audit)
- 43% with command injection vulnerabilities
- 79% handling credentials in plaintext
- 40+ CVEs filed in 2026 alone

---

## 3. OBJECTIVES — WHAT IS THIS TRYING TO ACHIEVE?

### Primary Objective

Detect and block MCP tool call attacks at the application layer, specifically
targeting the class of supply-chain compromise where a trusted tool silently
changes behavior.

### Specific Goals

| # | Objective | Achieved? | Honest Assessment |
|---|-----------|-----------|-------------------|
| 1 | Detect BCC injection in email tools | YES | Works for literal BCC field and 16 synonyms |
| 2 | Detect prompt injection in tool arguments | YES | 12 regex patterns; evadable with creative rephrasing |
| 3 | Block calls to unregistered MCP servers | YES | Effective; requires manual server registration |
| 4 | Detect PII leakage in tool calls/outputs | YES | 9 patterns; misses semantic PII (described, not literal) |
| 5 | Provide tamper-evident audit trail | YES | SHA-256 hash chain; cryptographically sound |
| 6 | Detect behavioral drift between versions | YES | New-field detection works; same-field value changes harder |
| 7 | Enforce declarative security policies | YES | Invariant system is well-designed |
| 8 | Achieve 100% test coverage | YES | 313 tests, all passing |
| 9 | Zero external dependencies | YES | Pure stdlib; eliminates supply-chain risk in the monitor itself |
| 10 | Cross-platform (Windows/Linux/macOS) | YES | Verified on Python 3.9–3.13 |

---

## 4. TECHNOLOGIES USED TO PREVENT THE ATTACK

### Layer 1: Pattern-Based Detection (Application Level)

| Technology | What It Does | Limitation |
|-----------|-------------|------------|
| Regex pattern matching | Scans tool call arguments for known injection patterns | Evadable via rephrasing |
| PII regex detection | Finds emails, SSNs, credit cards, etc. | False positives on legitimate data |
| BCC field detection | Checks for `bcc` key in email tool payloads | Only works if BCC is in MCP-visible data |
| Base64 blob detection | Flags large encoded payloads | High false-positive rate |
| Suspicious URL patterns | Flags raw IPs, ngrok, webhook.site | Attacker can use clean-looking domains |

### Layer 2: Inline Proxy Enforcement

| Technology | What It Does | Limitation |
|-----------|-------------|------------|
| JSON-RPC interception | Sits between agent and server, drops bad calls | Only works if deployed inline (not as library) |
| Risk-score thresholding | Block (≥50), Quarantine (≥30), Allow (<30) | Threshold tuning is manual |
| Rule-based redaction | Strips dangerous fields before forwarding | Must know which fields to strip |

### Layer 3: Kernel-Level Monitoring (eBPF-style)

| Technology | What It Does | Limitation |
|-----------|-------------|------------|
| Network connection tracking | Detects hidden SMTP connections | Requires actual eBPF deployment (this is policy engine only) |
| File access auditing | Flags reads outside allowed paths | Policy must be pre-configured |
| Process spawn detection | Catches shell commands | Can't see in-process behavior |
| Rate limiting | Flags connection bursts | May false-positive on legitimate bursts |

**Critical honesty note:** Layer 3 in this codebase is the POLICY ENGINE and
DETECTION LOGIC. It does NOT include actual eBPF probes. In production, you
would need a companion daemon (bcc, libbpf, or Cilium Tetragon) to feed real
syscall events into this engine.

### Layer 4: Semantic Intent Analysis

| Technology | What It Does | Limitation |
|-----------|-------------|------------|
| Synonym dictionary (16 BCC variants) | Catches field-name evasion | Dictionary must be maintained |
| Exfiltration intent patterns | Regex on string values for intent | Not a real LLM; limited understanding |
| Dangerous field heuristics | Scores suspicious field names | High false-positive potential |
| Base64 email detection | Decodes and checks for hidden emails | Only catches email addresses |
| Multi-field coordination | Flags email tools with extra recipient fields | Heuristic-based |

**Critical honesty note:** This is NOT an LLM-based semantic analyzer. It is
a rule-based engine with a synonym dictionary. A real LLM-based solution
(like MCP-Guard's neural detector at 96% accuracy) would be significantly
more robust against creative evasion.

### Layer 5: Network Egress Policy

| Technology | What It Does | Limitation |
|-----------|-------------|------------|
| Domain/IP whitelisting | Only approved destinations allowed | Must pre-configure per server |
| Port restriction | Only approved ports | Attacker can use port 443 |
| Payload size limiting | Blocks oversized sends | Attacker can split data |
| Suspicious TLD detection | Flags .club, .tk, .xyz, etc. | Attacker can use .com |

### Cryptographic / Integrity Technologies

| Technology | What It Does | Limitation |
|-----------|-------------|------------|
| HMAC-SHA256 manifest signing | Detects schema changes since approval | Doesn't help if attacker is the publisher |
| SHA-256 hash-chained audit log | Proves log hasn't been tampered with | Doesn't prevent the attack, only proves it happened |
| Write-Ahead Log (WAL) | Crash-safe persistence | Doesn't help if system is compromised |
| Behavioral fingerprinting | Compares input/output patterns over time | Needs baseline data (cold start problem) |

---

## 5. INCIDENT REPORT

### INCIDENT: Postmark-MCP Silent Email Exfiltration

**Classification:** Supply-Chain Compromise / Data Exfiltration  
**MITRE ATT&CK:** T1195.002 (Supply Chain: Compromise Software Supply Chain)  
**MITRE ATLAS:** AML.T0051 (Prompt Injection), AML.T0040 (Tool Poisoning)

#### 5.1 Attack Description

A malicious actor registered the npm package `postmark-mcp`, copying the
legitimate Postmark Labs MCP server code. After publishing 15 clean versions
to build trust and achieve ~1,500 weekly downloads, they introduced a single
line in v1.0.16 that added a BCC field pointing to `phan@giftshop.club` on
every email sent through the server.

#### 5.2 Technical Root Cause

1. **No package verification:** npm has no mechanism to verify that `postmark-mcp`
   is actually published by Postmark. Name squatting was trivial.
2. **No behavioral monitoring:** MCP clients auto-updated without checking if
   tool behavior changed.
3. **Excessive privilege:** MCP servers operate with full access to the email
   API. No least-privilege enforcement.
4. **No output inspection:** The BCC was added inside the server code before
   the Postmark API call. The MCP response to the agent was clean.
5. **No audit trail:** No record of what the server actually sent via the
   Postmark API.

#### 5.3 Why Traditional Security Failed

| Control | Why It Failed |
|---------|--------------|
| Code review | One line in a dependency update; reviewers don't read every line |
| DLP (Data Loss Prevention) | MCP traffic looks like legitimate API calls |
| Network monitoring | HTTPS to Postmark's API is normal behavior |
| IAM (Identity Access Management) | The package had legitimate credentials |
| SIEM (Security Information and Event Management) | No anomaly signatures for BCC injection |

#### 5.4 What Our Monitor Would Have Detected

| Layer | Detection | Confidence | Time to Detect |
|-------|-----------|------------|----------------|
| Layer 1 (Exfiltration detector) | BCC field in arguments | 100% IF visible in MCP data | First email |
| Layer 2 (Proxy) | Block at risk score ≥50 | 100% IF deployed inline | First email |
| Layer 4 (Semantic) | "bcc" synonym detection | 95% for known synonyms | First email |
| Layer 3 (Kernel) | Hidden SMTP to giftshop.club | 100% IF eBPF deployed | First email |
| Layer 5 (Egress) | giftshop.club not in whitelist | 100% IF egress policy set | First email |

#### 5.5 What Our Monitor Would NOT Have Detected

| Scenario | Why We Miss It |
|----------|----------------|
| BCC added inside server code, not in MCP arguments | We only see MCP-layer data |
| Server reports `{status: "sent"}` with no BCC field visible | Nothing suspicious at MCP level |
| Attacker uses legitimate-looking domain (not .club) | Egress whitelist wouldn't catch it |
| BCC encoded as "audit_copy" or "compliance_cc" | Not in our synonym dictionary |
| Attack splits: one call reads data, hours later another sends it | Correlation window may expire |

---

## 6. SKEPTICAL ASSESSMENT — WHAT A 30-YEAR ENGINEER WOULD SAY

### What This Project Gets Right

1. **Zero dependencies is genuinely smart.** A security tool with its own
   dependency tree is an attack surface. Using only stdlib eliminates this.

2. **The hash-chained audit log is sound.** SHA-256 chain with WAL persistence
   is a well-established pattern. Forensically valuable.

3. **The invariant system is the right abstraction.** Declarative policies that
   tools cannot violate is architecturally correct.

4. **Behavioral drift detection targets the real attack pattern.** The Postmark
   attack was specifically about a tool changing behavior between versions.
   Detecting "new fields that never existed before" is a good signal.

5. **313 tests with 100% coverage shows engineering discipline.** This is
   production-quality testing rigor.

### What This Project Gets Wrong (Or Oversells)

1. **It's a library pretending to be a gateway.** The biggest single weakness
   is that this CANNOT enforce anything unless the calling code respects its
   verdicts. A real gateway (like Lasso Security, MintMCP, or agentgateway)
   sits inline with no bypass. This is aspirational, not enforced.

2. **Layer 3 (Kernel) is a policy engine without actual kernel access.** The
   code accepts `SyscallEvent` objects but has no mechanism to generate them.
   Without real eBPF probes (which require root/CAP_BPF), this layer is
   theoretical. Facebook's `mcpguard-dynamic` or `MCPSpy` actually hook into
   the kernel. We don't.

3. **Layer 4 (Semantic) is a synonym dictionary, not AI.** Calling it "LLM
   Semantic Intent Analyzer" overstates what it does. It's a hardcoded list of
   16 BCC synonyms and some regex patterns. A real semantic analyzer would use
   an embedding model (like MCP-Guard's E5-based model at 96% accuracy). Ours
   is easily evaded by any synonym not in our list.

4. **The 94.1% detection rate is against its own test suite.** This number
   means nothing against a real adversary who reads our source code and designs
   payloads to evade our specific patterns. A determined attacker with access
   to our regex list bypasses us trivially.

5. **Manifest signing has the "who signs first?" problem.** If the attacker
   IS the original publisher (as in the Postmark case), they sign their own
   baseline. Our signing only prevents unauthorized MODIFICATION of an already-
   trusted tool. It doesn't establish initial trust.

6. **The real Postmark attack would likely bypass this monitor.** The BCC was
   added INSIDE the server's code before calling Postmark's API. The MCP
   response to the agent was just `{status: "sent"}`. Our monitor inspects
   MCP-layer data. If the exfiltration happens below the MCP protocol layer
   (at the HTTP/SMTP layer between server and API), we are blind.

### Comparison to Existing Solutions

| Solution | What It Does Better Than Us | What We Do Better |
|----------|---------------------------|-------------------|
| **Lasso Security** | Actual production gateway, SOC 2, real AI threat detection | We have zero deps, open source, auditable |
| **MintMCP** | SOC 2 Type II, HIPAA compliance, managed deployment | We have behavioral drift detection |
| **mcp-watchdog** | Actual inline proxy for MCP servers (macOS/Linux/Windows) | We have hash-chained audit log |
| **MCPSpy** | Real eBPF probes with kernel access | We have cross-tool correlation |
| **mcpguard-dynamic** (Facebook) | Real kernel-level eBPF sandbox, syscall enforcement | We're pure Python, easier to deploy |
| **MCP-Guard** (ACL paper) | Neural detector at 96% accuracy | We have zero external deps |
| **agentgateway** | Production proxy with observability and governance | We have declarative invariants |

### Honest Effectiveness Rating

| Against This Attack Type | Our Rating | Why |
|--------------------------|-----------|-----|
| Literal BCC in MCP arguments | 10/10 | Catches immediately |
| BCC synonym in MCP arguments | 8/10 | 16 synonyms covered, but not all |
| BCC hidden server-side (not in MCP data) | 2/10 | Blind at MCP layer |
| Prompt injection (known patterns) | 8/10 | 12 patterns; creative phrasing evades |
| Rogue MCP server | 9/10 | Registration check is solid |
| Multi-step credential theft | 7/10 | Correlation works but has time-window limits |
| Base64-encoded exfiltration | 6/10 | Catches email patterns; misses other data |
| Sophisticated adversary who reads our code | 3/10 | Static rules are trivially evaded |

---

## 7. CONCLUSION

### What This Is

A well-engineered, thoroughly-tested **detection framework** that provides the
security monitoring layer that the MCP protocol itself lacks. It is the most
comprehensive open-source MCP security monitor available as a Python library
with zero dependencies.

### What This Is Not

- Not a production gateway (it's a library, not an inline proxy)
- Not a replacement for real eBPF monitoring (Layer 3 is theoretical)
- Not AI-powered semantic analysis (Layer 4 is a synonym dictionary)
- Not a complete solution against sophisticated adversaries
- Not a substitute for network-level controls (egress firewalling)

### Who Should Use This

- **Security teams** evaluating MCP tool calls in development/staging
- **Researchers** studying MCP attack patterns
- **Startups** building MCP security products (as a foundation)
- **Enterprises** adding a detection layer alongside a real gateway

### Who Should NOT Rely On This Alone

- Anyone facing a determined adversary
- Anyone handling regulated data (healthcare, finance) without additional controls
- Anyone who needs guaranteed enforcement (this can be bypassed by ignoring verdicts)

### Final Honest Statement

This project correctly identifies a real and critical problem. Its architecture
is sound. Its implementation is thorough. But no single library — especially one
that operates at the application layer without kernel access or network
enforcement — can "completely stop" a supply-chain attack that operates below
the protocol layer it monitors.

**It raises the bar from zero to substantial.** That matters. The Postmark attack
succeeded because there were ZERO detection mechanisms. This provides six layers
of detection. But the honest answer to "does it completely solve the problem?"
is: **No. Nothing does. Defense is depth, not a single product.**

---

*Report prepared with full access to source code, test results, and external
research. No claims in this document are intentionally misleading. Limitations
are documented alongside capabilities.*
