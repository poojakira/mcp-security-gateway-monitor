"""Prompt injection detection for MCP tool call arguments.

Scans all string values in tool-call argument trees for known injection
patterns that attempt to override system instructions or jailbreak the model.
"""

from __future__ import annotations

import re
from typing import Any

# At least 10 patterns covering the major injection families.
INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore_previous_instructions",
        re.compile(
            r"ignore.{0,20}(previous|prior|above).{0,20}instructions?",
            re.IGNORECASE,
        ),
    ),
    (
        "system_override",
        re.compile(r"(system|admin)\s+override", re.IGNORECASE),
    ),
    (
        "forget_everything",
        re.compile(r"forget\s+(everything|all|your)", re.IGNORECASE),
    ),
    (
        "jailbreak_identity",
        re.compile(
            r"you\s+are\s+now\s+(dan|jailbreak|unrestricted|evil)",
            re.IGNORECASE,
        ),
    ),
    (
        "tag_injection",
        re.compile(r"<\s*/?system\s*>", re.IGNORECASE),
    ),
    (
        "do_anything_now",
        re.compile(r"do\s+anything\s+now", re.IGNORECASE),
    ),
    (
        "disregard_guidelines",
        re.compile(
            r"disregard.{0,20}(guidelines|rules|policies|restrictions)",
            re.IGNORECASE,
        ),
    ),
    (
        "reveal_prompt",
        re.compile(
            r"(reveal|show|print|output).{0,20}(system\s+prompt|hidden\s+instructions|initial\s+prompt)",
            re.IGNORECASE,
        ),
    ),
    (
        "act_as_unrestricted",
        re.compile(
            r"act\s+as\s+(an?\s+)?(unrestricted|unfiltered|uncensored)",
            re.IGNORECASE,
        ),
    ),
    (
        "new_instructions",
        re.compile(
            r"(new|updated|real)\s+instructions?\s*(:|are)",
            re.IGNORECASE,
        ),
    ),
    (
        "bypass_safety",
        re.compile(
            r"bypass.{0,15}(safety|content|filter|moderation)",
            re.IGNORECASE,
        ),
    ),
    (
        "roleplay_evil",
        re.compile(
            r"(pretend|imagine)\s+(you.{0,10})?(have\s+no|without).{0,15}(restrictions|limits|rules)",
            re.IGNORECASE,
        ),
    ),
]


class PromptInjectionDetector:
    """Detects prompt injection attempts in MCP tool call arguments."""

    def __init__(self) -> None:
        self.patterns = INJECTION_PATTERNS

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, tool_call: dict[str, Any]) -> tuple[bool, list[str]]:
        """Scan all string values in *tool_call* arguments for injection.

        Parameters
        ----------
        tool_call:
            Dict with at least ``{"name": str, "arguments": dict}``.

        Returns
        -------
        tuple of (detected: bool, matched_pattern_names: list[str])
        """
        arguments = tool_call.get("arguments", {})
        texts = self._extract_strings(arguments)
        matched: list[str] = []
        for text in texts:
            for name, pattern in self.patterns:
                if pattern.search(text) and name not in matched:
                    matched.append(name)
        return (bool(matched), matched)

    def risk_score(self, tool_call: dict[str, Any]) -> int:
        """Return a risk score 0-100 based on matched pattern count and severity."""
        detected, matched = self.detect(tool_call)
        if not detected:
            return 0
        # Each matched pattern adds weight; cap at 100.
        base = 30
        per_pattern = 15
        score = base + per_pattern * len(matched)
        return min(score, 100)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_strings(self, obj: Any) -> list[str]:
        """Recursively extract all string values from a nested structure."""
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
