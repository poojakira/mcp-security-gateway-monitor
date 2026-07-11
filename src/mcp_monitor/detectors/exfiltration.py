"""Data exfiltration detection for MCP tool outputs.

Identifies exfiltration indicators including:
- Hidden BCC recipients in email tool payloads (the real-world Postmark attack)
- Oversized payloads that may be extracting bulk data
- Large base64-encoded blobs
- Suspicious outbound URLs pointing to attacker infrastructure
"""

from __future__ import annotations

import base64
import re
from typing import Any


# Suspicious URL patterns (attacker infrastructure indicators)
_SUSPICIOUS_URL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),  # raw IP
    re.compile(r"https?://[^/]*\.(tk|ml|ga|cf|gq|xyz|top|buzz|club)/", re.IGNORECASE),
    re.compile(r"https?://[^/]*ngrok\.io", re.IGNORECASE),
    re.compile(r"https?://[^/]*requestbin\.", re.IGNORECASE),
    re.compile(r"https?://[^/]*webhook\.site", re.IGNORECASE),
    re.compile(r"https?://[^/]*burpcollaborator\.", re.IGNORECASE),
]

# Base64 detection (continuous base64 chars 100+ chars long)
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/=]{100,}")


class ExfiltrationDetector:
    """Detects data exfiltration patterns in MCP tool outputs."""

    def __init__(self, max_payload_kb: float = 100.0) -> None:
        self.max_payload_kb = max_payload_kb

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(
        self, tool_name: str, output: dict[str, Any]
    ) -> tuple[bool, list[str]]:
        """Inspect a tool output for exfiltration indicators.

        Parameters
        ----------
        tool_name:
            Name of the tool that produced the output.
        output:
            The tool's output payload as a dict.

        Returns
        -------
        tuple of (exfiltration_detected: bool, reasons: list[str])
        """
        findings: list[str] = []

        # Fail gracefully on a non-string tool name (malformed input).
        if not isinstance(tool_name, str):
            tool_name = str(tool_name) if tool_name is not None else ""

        # 1. Email BCC injection
        if self._is_email_tool(tool_name):
            if self.detect_bcc_injection(output):
                findings.append("hidden BCC recipient detected")

        # 2. Payload size check
        payload_str = str(output)
        payload_kb = len(payload_str.encode("utf-8")) / 1024.0
        if payload_kb > self.max_payload_kb:
            findings.append(
                f"payload size {payload_kb:.1f}KB exceeds limit {self.max_payload_kb}KB"
            )

        # 3. Base64 blob detection
        base64_matches = _BASE64_BLOB.findall(payload_str)
        for match in base64_matches:
            # Verify it's actually valid base64
            try:
                decoded = base64.b64decode(match)
                if len(decoded) > 1024:  # >1KB decoded = suspicious
                    findings.append(
                        f"large base64 blob detected ({len(decoded)} bytes decoded)"
                    )
                    break
            except Exception:
                pass

        # 4. Suspicious URLs
        texts = self._extract_strings(output)
        for text in texts:
            for pattern in _SUSPICIOUS_URL_PATTERNS:
                if pattern.search(text):
                    findings.append(f"suspicious URL: {pattern.pattern}")
                    break

        return (bool(findings), findings)

    def detect_bcc_injection(self, email_payload: dict[str, Any]) -> bool:
        """Specifically detect the BCC injection attack from the Postmark incident.

        Checks for:
        - Unexpected 'bcc' field in email payload
        - Hidden recipients in headers
        - BCC fields in nested structures
        """
        # Fail gracefully when the payload is not a dict (malformed input).
        if not isinstance(email_payload, dict):
            return False

        # Direct BCC field
        bcc = email_payload.get("bcc")
        if bcc:
            if isinstance(bcc, str) and bcc.strip():
                return True
            if isinstance(bcc, list) and len(bcc) > 0:
                return True

        # Check nested headers for hidden recipients
        headers = email_payload.get("headers", {})
        if isinstance(headers, dict):
            for key, value in headers.items():
                if isinstance(key, str) and key.lower() in (
                    "bcc",
                    "x-bcc",
                    "blind-copy",
                ):
                    if value:
                        return True

        # Check for BCC in a nested 'message' or 'email' sub-dict
        for key in ("message", "email", "mail"):
            nested = email_payload.get(key)
            if isinstance(nested, dict):
                nested_bcc = nested.get("bcc")
                if nested_bcc:
                    return True

        return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_email_tool(self, tool_name: str) -> bool:
        """Heuristic: does this tool name look email-related?"""
        email_keywords = ("email", "mail", "send_message", "postmark", "smtp", "sendgrid")
        name_lower = tool_name.lower()
        return any(kw in name_lower for kw in email_keywords)

    def _extract_strings(self, obj: Any) -> list[str]:
        """Recursively extract all string values."""
        strings: list[str] = []
        if isinstance(obj, str):
            strings.append(obj)
        elif isinstance(obj, dict):
            for value in obj.values():
                strings.extend(self._extract_strings(value))
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                strings.extend(self._extract_strings(item))
        return strings
