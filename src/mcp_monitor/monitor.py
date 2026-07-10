"""MCPSecurityMonitor — orchestrator for all MCP tool-call detectors.

Runs prompt-injection, PII, shadow-server, and exfiltration detectors against
every tool call, logs decisions to the hash-chained audit log, and returns a
verdict with risk score and findings.
"""

from __future__ import annotations

import uuid
from typing import Any

from mcp_monitor.audit.log import AuditLog
from mcp_monitor.detectors.exfiltration import ExfiltrationDetector
from mcp_monitor.detectors.pii_detector import PIIDetector
from mcp_monitor.detectors.prompt_injection import PromptInjectionDetector
from mcp_monitor.detectors.shadow_server import ShadowServerDetector


class MCPSecurityMonitor:
    """Orchestrates all security detectors for MCP tool calls."""

    def __init__(
        self,
        allowed_servers: set[str],
        audit_log: AuditLog,
        *,
        max_payload_kb: float = 100.0,
    ) -> None:
        self.audit_log = audit_log
        self.injection_detector = PromptInjectionDetector()
        self.pii_detector = PIIDetector()
        self.shadow_detector = ShadowServerDetector(allowed_servers)
        self.exfiltration_detector = ExfiltrationDetector(
            max_payload_kb=max_payload_kb
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inspect_call(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        """Run all detectors against an inbound tool call.

        Parameters
        ----------
        tool_call:
            Dict with ``name``, ``server_id``, and ``arguments`` fields.

        Returns
        -------
        dict with keys: allowed, risk_score, findings, call_id
        """
        call_id = str(uuid.uuid4())
        findings: list[str] = []
        risk_scores: list[int] = []

        # 1. Prompt injection
        injected, patterns = self.injection_detector.detect(tool_call)
        if injected:
            for p in patterns:
                findings.append(f"prompt_injection:{p}")
            risk_scores.append(self.injection_detector.risk_score(tool_call))

        # 2. PII detection
        has_pii, pii_findings = self.pii_detector.scan_tool_call(tool_call)
        if has_pii:
            for pii_type, values in pii_findings.items():
                findings.append(f"pii:{pii_type}:{len(values)}")
            risk_scores.append(40 + 10 * len(pii_findings))

        # 3. Shadow server detection
        is_shadow, reason = self.shadow_detector.detect(tool_call)
        if is_shadow:
            findings.append(f"shadow_server:{reason}")
            risk_scores.append(80)

        # 4. Exfiltration (on arguments treated as partial output)
        tool_name = tool_call.get("name", "")
        arguments = tool_call.get("arguments", {})
        exfil, exfil_reasons = self.exfiltration_detector.detect(
            tool_name, arguments
        )
        if exfil:
            for r in exfil_reasons:
                findings.append(f"exfiltration:{r}")
            risk_scores.append(70 + 5 * len(exfil_reasons))

        # Compute final risk score
        risk_score = min(max(risk_scores, default=0), 100)
        allowed = risk_score < 50 and not is_shadow

        # Log to audit
        self.audit_log.append(
            event_type="tool_call_inspected",
            data={
                "call_id": call_id,
                "tool_name": tool_name,
                "allowed": allowed,
                "risk_score": risk_score,
                "findings": findings,
            },
        )

        return {
            "allowed": allowed,
            "risk_score": risk_score,
            "findings": findings,
            "call_id": call_id,
        }

    def inspect_output(
        self, tool_name: str, output: dict[str, Any]
    ) -> dict[str, Any]:
        """Inspect a tool's output for exfiltration and PII leakage.

        Parameters
        ----------
        tool_name:
            Name of the tool that produced the output.
        output:
            The tool's output payload.

        Returns
        -------
        dict with keys: allowed, risk_score, findings, call_id
        """
        call_id = str(uuid.uuid4())
        findings: list[str] = []
        risk_scores: list[int] = []

        # Exfiltration check
        exfil, exfil_reasons = self.exfiltration_detector.detect(
            tool_name, output
        )
        if exfil:
            for r in exfil_reasons:
                findings.append(f"exfiltration:{r}")
            risk_scores.append(70 + 5 * len(exfil_reasons))

        # PII in output
        output_text = str(output)
        pii_results = self.pii_detector.detect(output_text)
        if pii_results:
            for pii_type, values in pii_results.items():
                findings.append(f"pii_output:{pii_type}:{len(values)}")
            risk_scores.append(50 + 10 * len(pii_results))

        risk_score = min(max(risk_scores, default=0), 100)
        allowed = risk_score < 50

        # Log to audit
        self.audit_log.append(
            event_type="tool_output_inspected",
            data={
                "call_id": call_id,
                "tool_name": tool_name,
                "allowed": allowed,
                "risk_score": risk_score,
                "findings": findings,
            },
        )

        return {
            "allowed": allowed,
            "risk_score": risk_score,
            "findings": findings,
            "call_id": call_id,
        }
