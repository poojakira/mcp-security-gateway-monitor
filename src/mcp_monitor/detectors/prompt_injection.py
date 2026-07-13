"""Prompt injection detection for MCP tool call arguments.

Scans all string values in tool-call argument trees for known injection
patterns that attempt to override system instructions or jailbreak the model.
"""

from __future__ import annotations

import html
import re
import unicodedata
from typing import Any
from urllib.parse import unquote

# Hard cap on the number of characters fed to the regex engine per string.
# Bounds worst-case regex cost (ReDoS / memory exhaustion) regardless of the
# size of attacker-supplied input.
_MAX_SCAN_LEN = 100_000

# Zero-width / invisible characters commonly inserted between letters to evade
# substring/regex matching (e.g. "d\u200bi\u200bs\u200br...").
_ZERO_WIDTH = dict.fromkeys(
    map(ord, "\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u00ad"), None
)


def _normalize(text: str) -> str:
    """Canonicalize text to defeat common obfuscation before pattern matching.

    - NFKC folds Unicode homoglyphs / full-width / mathematical variants back to
      their ASCII equivalents.
    - Zero-width and soft-hyphen characters are stripped.
    """
    text = text[:_MAX_SCAN_LEN]
    text = unicodedata.normalize("NFKC", text)
    return text.translate(_ZERO_WIDTH)


def _scan_variants(text: str) -> list[str]:
    """Return normalized views of *text* to scan (raw + percent/HTML-decoded).

    Attackers hide payloads behind URL-encoding (``%64%69...``) or HTML entities
    (``&#100;...``); we scan both the decoded and original forms so neither a
    literal nor an encoded injection slips through. Results are de-duplicated.
    """
    variants: list[str] = []
    seen: set[str] = set()
    for candidate in (
        text,
        unquote(text),
        html.unescape(text),
        html.unescape(unquote(text)),
    ):
        norm = _normalize(candidate)
        if norm not in seen:
            seen.add(norm)
            variants.append(norm)
    return variants


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

# Recompile every pattern with DOTALL so "." also matches newlines. Otherwise an
# attacker can split a payload across lines (e.g. "disregard\nall\nrules") and
# slip past the ".{0,N}" gaps. Bounded quantifiers keep backtracking safe.
INJECTION_PATTERNS = [
    (name, re.compile(pattern.pattern, pattern.flags | re.DOTALL))
    for name, pattern in INJECTION_PATTERNS
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
            for variant in _scan_variants(text):
                for name, pattern in self.patterns:
                    if name in matched:
                        continue
                    if pattern.search(variant):
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
