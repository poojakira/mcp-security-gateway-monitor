"""Data exfiltration detection for MCP tool outputs.

Identifies exfiltration indicators including:
- Hidden BCC recipients in email tool payloads (the real-world Postmark attack)
- Oversized payloads that may be extracting bulk data
- Large base64-encoded blobs
- Suspicious outbound URLs pointing to attacker infrastructure
"""

from __future__ import annotations

import base64
import email
import re
import unicodedata
from email.parser import HeaderParser
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
HEADER_KEY_SKELETON = str.maketrans({"с": "c", "С": "C"})
BCC_HEADER_KEYS = {"bcc", "x-bcc", "blind-copy", "carbon_copy", "cc", "rcpt_to"}


class ExfiltrationDetector:
    """Detects data exfiltration patterns in MCP tool outputs."""

    def __init__(self, max_payload_kb: float = 100.0) -> None:
        self.max_payload_kb = max_payload_kb

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, tool_name: str, output: dict[str, Any]) -> tuple[bool, list[str]]:
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
        """Detect BCC/CC recipient injection in structured, raw, and MIME payloads."""
        return self._contains_bcc(email_payload)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_email_tool(self, tool_name: str) -> bool:
        """Heuristic: does this tool name look email-related?"""
        email_keywords = (
            "email",
            "mail",
            "send_message",
            "postmark",
            "smtp",
            "sendgrid",
        )
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

    def _contains_bcc(self, obj: Any) -> bool:
        if isinstance(obj, dict):
            for key, value in obj.items():
                normalized_key = self._normalize_header_key(str(key))
                if normalized_key in BCC_HEADER_KEYS and self._has_value(value):
                    return True
                if self._contains_bcc(value):
                    return True
        elif isinstance(obj, (list, tuple)):
            return any(self._contains_bcc(item) for item in obj)
        elif isinstance(obj, str):
            return self._raw_headers_contain_bcc(obj)
        return False

    def _raw_headers_contain_bcc(self, raw: str) -> bool:
        parsed = HeaderParser().parsestr(raw)
        for key, value in parsed.items():
            if self._normalize_header_key(key) in BCC_HEADER_KEYS and self._has_value(value):
                return True

        msg = email.message_from_string(raw)
        for part in msg.walk():
            for key, value in part.items():
                if self._normalize_header_key(key) in BCC_HEADER_KEYS and self._has_value(value):
                    return True
        return False

    def _normalize_header_key(self, key: str) -> str:
        skeleton = unicodedata.normalize("NFKC", key).translate(HEADER_KEY_SKELETON)
        return skeleton.encode("ascii", errors="ignore").decode().lower()

    def _has_value(self, value: Any) -> bool:
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, (list, tuple, set)):
            return len(value) > 0
        return value is not None