"""PII detection and redaction for MCP tool call data.

Identifies personally identifiable information (PII) such as emails, SSNs,
credit card numbers, phone numbers, IP addresses, and more. Supports both
detection and in-place redaction.
"""

from __future__ import annotations

import re
from typing import Any


# Minimum 8 PII types.
PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
    ),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
    "phone_us": re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"),
    "ip_address": re.compile(
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    ),
    "date_of_birth": re.compile(
        r"\b(0[1-9]|1[0-2])/(0[1-9]|[12]\d|3[01])/(19|20)\d{2}\b"
    ),
    "passport": re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "api_key": re.compile(r"\b(sk|pk)[-_](?:live|test)[-_][a-zA-Z0-9]{24,}\b"),
}


class PIIDetector:
    """Detects and redacts PII in text and MCP tool-call payloads."""

    def __init__(self) -> None:
        self.patterns = PII_PATTERNS

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, text: str) -> dict[str, list[str]]:
        """Return mapping of PII type to list of found values in *text*."""
        findings: dict[str, list[str]] = {}
        for pii_type, pattern in self.patterns.items():
            matches = pattern.findall(text)
            if matches:
                findings[pii_type] = matches
        return findings

    def redact(self, text: str, replacement: str = "[REDACTED]") -> str:
        """Replace all detected PII in *text* with *replacement*."""
        result = text
        for pattern in self.patterns.values():
            result = pattern.sub(replacement, result)
        return result

    def scan_tool_call(
        self, tool_call: dict[str, Any]
    ) -> tuple[bool, dict[str, list[str]]]:
        """Scan all string values in a tool call for PII.

        Returns
        -------
        tuple of (has_pii: bool, findings: dict mapping pii_type to values)
        """
        texts = self._extract_strings(tool_call)
        combined: dict[str, list[str]] = {}
        for text in texts:
            for pii_type, values in self.detect(text).items():
                combined.setdefault(pii_type, []).extend(values)
        return (bool(combined), combined)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_strings(self, obj: Any) -> list[str]:
        """Recursively extract all string values from nested structure."""
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
