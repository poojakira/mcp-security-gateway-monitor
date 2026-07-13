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


# Abuse-prone TLDs frequently used for throwaway attacker infrastructure. This
# static list is a cheap first pass only; production deployments should layer a
# live domain-reputation feed (e.g. an AbuseIPDB / PhishTank lookup) on top —
# see ``reputation_lookup`` hook below.
_SUSPICIOUS_TLDS = (
    "tk|ml|ga|cf|gq|xyz|top|buzz|club|click|download|loan|date|men|win|bid|"
    "trade|webcam|science|cam|mom|lol|work|review|stream|racing|party|gdn|pw|"
    "zip|mov|country|kim|cricket|accountant|faith|link"
)

# Suspicious URL patterns (attacker infrastructure indicators)
_SUSPICIOUS_URL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),  # raw IP
    # Match the abuse-prone TLD at a host boundary (end, port, path, query or
    # fragment) instead of requiring a trailing "/", which let "https://evil.tk"
    # slip through unmatched.
    re.compile(
        rf"https?://[^/\s:]*\.(?:{_SUSPICIOUS_TLDS})(?=[:/?#]|$)",
        re.IGNORECASE,
    ),
    re.compile(r"https?://[^/]*ngrok\.io", re.IGNORECASE),
    re.compile(r"https?://[^/]*requestbin\.", re.IGNORECASE),
    re.compile(r"https?://[^/]*webhook\.site", re.IGNORECASE),
    re.compile(r"https?://[^/]*burpcollaborator\.", re.IGNORECASE),
]

# Encoded-blob detection. We look for standard base64 AND url-safe base64
# (which uses '-'/'_' instead of '+'/'/' and often drops '=' padding), since
# attackers routinely switch encodings to dodge a single-alphabet regex.
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/=]{100,}")
_BASE64URL_BLOB = re.compile(r"[A-Za-z0-9_-]{100,}={0,2}")


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

        # 3. Encoded blob detection (standard + url-safe base64)
        if self._has_large_encoded_blob(payload_str):
            findings.append("large base64 blob detected")

        # 4. Suspicious URLs
        texts = self._extract_strings(output)
        for text in texts:
            for pattern in _SUSPICIOUS_URL_PATTERNS:
                if pattern.search(text):
                    findings.append(f"suspicious URL: {pattern.pattern}")
                    break

        return (bool(findings), findings)

    def _has_large_encoded_blob(self, payload_str: str, min_decoded: int = 1024) -> bool:
        """Return True if payload contains a base64/base64url blob decoding to
        more than ``min_decoded`` bytes."""
        for pattern, decoder in (
            (_BASE64_BLOB, base64.b64decode),
            (_BASE64URL_BLOB, base64.urlsafe_b64decode),
        ):
            for match in pattern.findall(payload_str):
                try:
                    # Pad to a multiple of 4 so unpadded url-safe blobs decode.
                    padded = match + "=" * (-len(match) % 4)
                    if len(decoder(padded)) > min_decoded:
                        return True
                except Exception:
                    continue
        return False

    def detect_bcc_injection(self, email_payload: dict[str, Any]) -> bool:
        """Specifically detect the BCC injection attack from the Postmark incident.

        Checks for:
        - Unexpected 'bcc' field in email payload
        - Hidden recipients in headers
        - BCC fields in nested structures
        """
        # Direct BCC field
        if self._has_recipient(email_payload.get("bcc")):
            return True

        # Check nested headers for hidden recipients (more header variants)
        headers = email_payload.get("headers", {})
        if isinstance(headers, dict):
            for key, value in headers.items():
                if key.lower() in (
                    "bcc",
                    "x-bcc",
                    "blind-copy",
                    "blind-cc",
                    "blindcopy",
                ):
                    if self._has_recipient(value):
                        return True

        # Check for BCC in a nested 'message' or 'email' sub-dict
        for key in ("message", "email", "mail"):
            nested = email_payload.get(key)
            if isinstance(nested, dict) and self._has_recipient(nested.get("bcc")):
                return True

        return False

    @staticmethod
    def _has_recipient(value: Any) -> bool:
        """True if *value* holds at least one non-empty recipient.

        Guards against false positives from empty strings or lists containing
        only blank entries (e.g. ``["", ""]``).
        """
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, (list, tuple, set)):
            return any(str(item).strip() for item in value)
        if isinstance(value, dict):
            return any(str(item).strip() for item in value.values())
        return value is not None and bool(str(value).strip())

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
