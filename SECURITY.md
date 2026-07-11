# Security Policy

`mcp-security-gateway-monitor` is itself a security tool: it sits between AI
assistants and their MCP tools and blocks prompt injection, data exfiltration,
hidden-BCC attacks, and related abuse. Because it is a defensive control, we
hold it to a high supply-chain and disclosure standard. This document explains
how to report vulnerabilities, which versions we support, and the project's own
threat model.

## Supported Versions

| Version | Supported          | Notes                                    |
| ------- | ------------------ | ---------------------------------------- |
| 0.1.x   | :white_check_mark: | Current release line; receives fixes.    |
| < 0.1.0 | :x:                | Pre-release; not supported.              |

Security fixes are applied to the latest `0.1.x` release. Please upgrade to the
newest patch version before reporting an issue.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately using GitHub's coordinated disclosure:

1. Go to the repository's **Security** tab and choose
   **"Report a vulnerability"** (GitHub Private Vulnerability Reporting), or
2. If that is unavailable, open a minimal private channel with the maintainers
   via the repository owner (`poojakira`) and request a secure contact before
   sending any details.

When reporting, please include:

- A description of the issue and its security impact.
- The affected component/layer (e.g. Layer 4 Semantic Analyzer, `[dpi]` egress
  proxy) and version/commit.
- Steps to reproduce or a proof of concept.
- Any known workarounds.

### What to expect

- **Acknowledgement:** within **3 business days**.
- **Initial assessment / triage:** within **10 business days**.
- **Fix target:** Critical/High issues within **30 days**; Moderate/Low on a
  best-effort basis, coordinated with you.
- **Disclosure:** we practice coordinated disclosure. We will credit reporters
  who wish to be named once a fix is released. Please give us a reasonable
  window (default 90 days) before any public disclosure.

We welcome reports about the project's own detectors, its dependencies, its
build/release pipeline, and its documentation/configuration guidance.

## Threat Model (This Project)

Because this is a security control, its threat model has two sides: the threats
it is designed to stop, and the threats against the tool itself.

### Threats this tool defends against

The monitor inspects every MCP tool call through up to 10 defense layers:

- **Prompt injection** hidden inside tool arguments (jailbreaks, instruction
  overrides).
- **Data exfiltration** via encoded payloads, oversized bodies, or suspicious
  URLs/destinations.
- **Hidden recipients / BCC injection** (the real-world Postmark-style silent
  BCC attack).
- **Shadow / unregistered MCP servers** and tool-manifest tampering.
- **Unauthorized egress** — network connections and DNS lookups outside an
  explicit allow-list (default-deny).
- **Behavioral drift and multi-step attacks** correlated across calls.
- **Tools that lie about their behavior** — deep-packet inspection compares
  declared MCP intent against actual HTTP traffic.

### Threats against the tool itself, and our mitigations

- **Tampering with the audit trail** → the audit log is a SHA-256 hash-chained,
  append-only structure with a write-ahead log; tampering is detectable.
- **Bypassing the monitor** → default-deny egress and fail-closed handling of
  unknown servers; the proxy is inline rather than advisory.
- **Supply-chain compromise of the tool's own dependencies** → see below. The
  core is dependency-free, which drastically shrinks this attack surface.
- **Evasion via novel payloads** → layered defense combines deterministic rules
  with an optional ML classifier and honeypot canary tokens.

### Trust boundaries and assumptions

- The monitor is trusted; the MCP servers/tools it guards are **not** trusted.
- The host running the monitor is assumed to be trusted and reasonably hardened.
- The audit log's integrity depends on the confidentiality of the host it runs
  on; hash-chaining detects tampering but does not by itself prevent deletion.
- The optional `[dpi]` deep-packet inspection assumes the operator has authority
  to inspect the traffic in question.

### Out of scope

- Physical attacks and full host compromise (root on the monitor's host).
- Vulnerabilities in the upstream AI model or the MCP protocol specification.
- Misuse of the DPI/egress features to inspect traffic without authorization.

## Supply-Chain Security

Supply-chain integrity is a first-class concern for a security tool. Our
posture:

- **Zero-dependency core (a supply-chain advantage).** The core monitor and all
  five base defense layers use **only the Python standard library**
  (`dependencies = []` in `pyproject.toml`). There is no transitive runtime
  dependency tree to compromise, no `postinstall`-style hooks, and nothing to
  typosquat for a default install. This is the single biggest reduction in
  supply-chain attack surface the project makes — most CVEs in the Python
  ecosystem simply cannot reach a default install because those packages are
  never installed.
- **Optional extras are clearly fenced.** ML (`scikit-learn`, `numpy`) lives
  behind `[ml]`; deep-packet inspection (`mitmproxy`) behind `[dpi]`. Operators
  opt in to that additional surface deliberately.
- **SBOM.** A CycloneDX Software Bill of Materials is published at
  [`sbom.json`](./sbom.json), covering the full install (core + all extras).
- **Continuous auditing.** [`pip-audit`](https://pypi.org/project/pip-audit/)
  runs in CI on every push and pull request via
  [`.github/workflows/security.yml`](./.github/workflows/security.yml). A
  severity-aware gate (`scripts/pip_audit_gate.py`) **fails the build on any
  non-allow-listed HIGH or CRITICAL** advisory.
- **Transparent accepted risk.** Any exception (e.g. an un-fixable upstream-
  pinned transitive dependency) is documented with justification and a review
  date in [`security/audit-allowlist.txt`](./security/audit-allowlist.txt), and
  the latest full audit is recorded in
  [`security/dependency-audit.txt`](./security/dependency-audit.txt).
- **Automated updates.** [Dependabot](./.github/dependabot.yml) proposes weekly
  updates for Python dependencies and GitHub Actions.

### Current known issues (honest disclosure)

At the time of the latest audit, the **default / `[dev]` / `[ml]` installs have
no known vulnerabilities**. The optional `[dpi]` extra transitively pulls in
`tornado` and `msgpack` (via `mitmproxy`), which currently carry known
advisories (3 HIGH, 1 Moderate, 1 Low). mitmproxy pins these to versions below
the patched releases, so the fixes are not yet installable. These are tracked as
accepted risk in `security/audit-allowlist.txt` and will be re-evaluated when a
compatible mitmproxy release is available. See
[`security/dependency-audit.txt`](./security/dependency-audit.txt) for full
detail.
