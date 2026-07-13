# Novelty, Data & Production-Readiness — an honest, skeptical assessment

This document exists because the rest of the repo makes strong claims. Here we
push back on our own work. Read it before trusting any number elsewhere.

## What is genuinely novel here

- **MCP-specific, layered gateway.** Most prompt-injection/PII tooling is
  single-shot. Combining application detectors → inline proxy → egress/DPI
  intent-vs-actual comparison → rate-limit/recipient blast-radius → honeypot
  canaries → sandbox isolation, *specifically framed around MCP tool calls and
  the server-side BCC exfiltration class*, is a useful integration. The
  strongest idea is **blast-radius limiting** (rate limit + recipient
  allowlist): it contains an attack even when detection fails.
- **Cumulative scoring + tamper-evident, HMAC-anchored audit.** Summed
  (not max) risk scoring closes the "stay just under threshold" bypass, and the
  audit log now supports HMAC-keyed digests plus an external anchor so a
  filesystem-level attacker cannot silently rewrite history.

## What is NOT novel, or is over-claimed (be skeptical)

- **The 12 regex patterns are table stakes and bypassable.** NFKC
  normalization, zero-width stripping, base64/URL/HTML decoding and
  split-argument reconstruction now raise the bar, but regex is still a
  *screen-door*, not the wall. Treat it as defense-in-depth, not detection.
- **The "ML classifier" is not trained on production data.** It learns from a
  few dozen curated strings plus synthetically generated variants. That is a
  **unit-test fixture, not a dataset.** Any cross-validation "accuracy" on ~100
  samples has enormous variance (±15–20%) and is **not** evidence of real-world
  performance. The classifier ships as **BETA / QA** and must fail closed if it
  cannot load a properly signed, pre-trained model.
- **"100% coverage / 963 statements 0 missed" is statement coverage only** and
  historically excluded the scikit-learn layer when its extra was not
  installed. Statement coverage is not branch or mutation coverage and is not a
  measure of test strength.
- **No real false-positive rate exists.** FP rate is *the* metric that decides
  whether a security tool survives contact with production. We have none from
  real traffic.

## Data required before an honest v1 (currently absent)

| Need | Why | Source | Scale |
|------|-----|--------|-------|
| Real MCP tool-call telemetry | Train/evaluate the classifier on reality | Shadow-mode deploy at partner org(s) | 1M+ calls |
| Labeled prompt-injection corpus | Known-bad ground truth | `deepset/prompt-injection` (HF) + own red-team | 50k+ |
| Benign traffic corpus | FP rate is decisive | Shadow-mode Gmail/M365/Calendar usage | 500k+ |
| Adversarial evasion eval set | Prove obfuscation resistance | Automated red-team loop | 10k+ variants |

**Honest shipping recommendation:** ship the regex + blast-radius controls as
GA; mark the ML classifier **Beta**; do not claim ML efficacy until 90 days of
real shadow-mode telemetry are collected and a held-out FP rate is measured.

## Known gaps (not yet addressed in code)

- No SBOM/SLSA provenance for this tool's own builds; no third-party pentest;
  no fuzzing of the regex/ML boundary.
- Structured-logging is not yet unified across every `defense10/` component.
- Multi-tenant audit isolation is not modeled (single namespace).
- No formal, enumerated threat model (trust boundaries, actors, data flows).
