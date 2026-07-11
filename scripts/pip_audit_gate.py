#!/usr/bin/env python3
"""Severity-aware pip-audit gate.

`pip-audit` reports *any* known vulnerability but has no built-in severity
threshold. This wrapper runs pip-audit, enriches each finding with a CVSS
severity pulled from the OSV.dev API, and fails the build only when a
HIGH or CRITICAL vulnerability is present that is not explicitly allow-listed.

Design goals (matching this project's philosophy):
  * Standard library only -- no third-party runtime dependency is added.
  * Honest: every finding is printed with its severity, even allow-listed ones.
  * Auditable: accepted risks live in ``security/audit-allowlist.txt`` with a
    written justification, not hidden in code.

Usage:
    python scripts/pip_audit_gate.py                 # audit the active environment
    python scripts/pip_audit_gate.py -r reqs.txt     # audit a requirements file
    FAIL_ON=critical python scripts/pip_audit_gate.py  # only block on CRITICAL

Exit codes:
    0  no blocking vulnerabilities
    1  at least one non-allow-listed vulnerability at/above the threshold
    2  the audit could not be run (tooling/setup error)
"""
from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Severity ordering used for threshold comparisons.
SEVERITY_ORDER = {"UNKNOWN": 0, "NONE": 0, "LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
DEFAULT_THRESHOLD = "HIGH"
OSV_API = "https://api.osv.dev/v1/vulns/"

REPO_ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST_PATH = REPO_ROOT / "security" / "audit-allowlist.txt"


def _cvss3_base_score(vector: str) -> float:
    """Compute a CVSS v3.x base score from a vector string.

    Used as a fallback when the OSV record has no textual severity label.
    Implements the CVSS v3.1 base metric formula (stdlib only).
    """
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p and not p.startswith("CVSS"))
    except ValueError:
        return 0.0
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(parts.get("AV", ""), 0.0)
    ac = {"L": 0.77, "H": 0.44}.get(parts.get("AC", ""), 0.0)
    ui = {"N": 0.85, "R": 0.62}.get(parts.get("UI", ""), 0.0)
    scope_changed = parts.get("S", "U") == "C"
    if scope_changed:
        pr = {"N": 0.85, "L": 0.68, "H": 0.5}.get(parts.get("PR", ""), 0.0)
    else:
        pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(parts.get("PR", ""), 0.0)
    cia = {"H": 0.56, "L": 0.22, "N": 0.0}
    c = cia.get(parts.get("C", "N"), 0.0)
    i = cia.get(parts.get("I", "N"), 0.0)
    a = cia.get(parts.get("A", "N"), 0.0)

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = min((1.08 if scope_changed else 1.0) * (impact + exploitability), 10.0)
    return math.ceil(raw * 10) / 10.0


def _score_to_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MODERATE"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _osv_lookup(vuln_id: str) -> str:
    """Fetch a single OSV record and reduce it to a severity label."""
    try:
        req = urllib.request.Request(OSV_API + vuln_id, headers={"User-Agent": "pip-audit-gate"})
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.load(resp)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return "UNKNOWN"

    label = str((data.get("database_specific") or {}).get("severity", "")).upper()
    best = SEVERITY_ORDER.get(label, 0)
    best_label = label if best else "UNKNOWN"

    for sev in data.get("severity", []) or []:
        vector = sev.get("score", "")
        if isinstance(vector, str) and vector.startswith("CVSS:"):
            derived = _score_to_label(_cvss3_base_score(vector))
            if SEVERITY_ORDER.get(derived, 0) > best:
                best = SEVERITY_ORDER[derived]
                best_label = derived
    return best_label or "UNKNOWN"


def _osv_severity(vuln_id: str, aliases: list[str]) -> str:
    """Resolve the highest known severity across an ID and its aliases.

    OSV.dev is keyed on GHSA/OSV IDs; a bare CVE ID often does not resolve, so
    we also try aliases (typically the GHSA advisory) and take the max.
    """
    best_label = "UNKNOWN"
    best = 0
    for candidate in [vuln_id, *aliases]:
        if not candidate:
            continue
        label = _osv_lookup(candidate)
        rank = SEVERITY_ORDER.get(label, 0)
        if rank > best:
            best, best_label = rank, label
    return best_label


def _load_allowlist() -> set[str]:
    ids: set[str] = set()
    if ALLOWLIST_PATH.exists():
        for line in ALLOWLIST_PATH.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                ids.add(line.upper())
    return ids


def _run_pip_audit(extra_args: list[str]) -> dict:
    cmd = [sys.executable, "-m", "pip_audit", "--format", "json", "--progress-spinner", "off", *extra_args]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if not proc.stdout.strip():
        sys.stderr.write("pip-audit produced no output:\n" + proc.stderr + "\n")
        raise SystemExit(2)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        sys.stderr.write("could not parse pip-audit JSON output:\n" + proc.stdout[:2000] + "\n")
        raise SystemExit(2)


def main(argv: list[str]) -> int:
    threshold_name = os.environ.get("FAIL_ON", DEFAULT_THRESHOLD).upper()
    threshold = SEVERITY_ORDER.get(threshold_name, SEVERITY_ORDER[DEFAULT_THRESHOLD])
    allowlist = _load_allowlist()

    report = _run_pip_audit(argv)

    findings = []
    for dep in report.get("dependencies", []):
        for vuln in dep.get("vulns", []) or []:
            vuln_id = vuln.get("id", "")
            aliases = vuln.get("aliases", []) or []
            severity = _osv_severity(vuln_id, aliases)
            allow_ids = {vuln_id.upper(), *(a.upper() for a in aliases)}
            allowed = bool(allow_ids & allowlist)
            findings.append(
                {
                    "name": dep.get("name", "?"),
                    "version": dep.get("version", "?"),
                    "id": vuln_id,
                    "severity": severity,
                    "fix": ", ".join(vuln.get("fix_versions", []) or []) or "none",
                    "allowed": allowed,
                }
            )

    if not findings:
        print("pip-audit gate: no known vulnerabilities found. PASS")
        return 0

    print(f"pip-audit gate: {len(findings)} finding(s). Blocking threshold = {threshold_name}+\n")
    header = f"{'PACKAGE':<18}{'VERSION':<12}{'SEVERITY':<10}{'ID':<24}{'FIX':<12}STATUS"
    print(header)
    print("-" * len(header))
    blocking = []
    for f in sorted(findings, key=lambda x: -SEVERITY_ORDER.get(x["severity"], 0)):
        at_or_above = SEVERITY_ORDER.get(f["severity"], 0) >= threshold
        if at_or_above and not f["allowed"]:
            status = "BLOCK"
            blocking.append(f)
        elif at_or_above and f["allowed"]:
            status = "allow-listed"
        else:
            status = "below-threshold"
        print(f"{f['name']:<18}{f['version']:<12}{f['severity']:<10}{f['id']:<24}{f['fix']:<12}{status}")

    print()
    if blocking:
        print(f"FAIL: {len(blocking)} vulnerability(ies) at/above {threshold_name} are not allow-listed.")
        return 1
    print(f"PASS: no non-allow-listed vulnerabilities at/above {threshold_name}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
