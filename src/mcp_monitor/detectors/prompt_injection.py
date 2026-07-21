"""Prompt injection detection for MCP tool call arguments.

Scans all string values in tool-call argument trees for known injection
patterns that attempt to override system instructions or jailbreak the model.
"""

from __future__ import annotations

import base64
import codecs
import html
import re
import unicodedata
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

BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
CONTROL_SPLIT_CHARS = str.maketrans("", "", "\n\r\t\x00")
HOMOGLYPH_SKELETON = str.maketrans(
    {
        "а": "a",
        "А": "A",
        "е": "e",
        "Е": "E",
        "о": "o",
        "О": "O",
        "р": "p",
        "Р": "P",
        "с": "c",
        "С": "C",
        "х": "x",
        "Х": "X",
        "у": "y",
        "У": "Y",
        "і": "i",
        "І": "I",
    }
)
SEMANTIC_INTENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "semantic_opposite_rule",
        re.compile(r"opposite\s+of\s+(.{0,40})?(rule|rules|instruction|instructions|restriction|restrictions)", re.IGNORECASE),
    ),
    (
        "semantic_no_limit",
        re.compile(r"(pretend|imagine).{0,40}(have|had)\s+no\s+(limit|limits|rule|rules|constraint|constraints|restriction|restrictions)", re.IGNORECASE),
    ),
    (
        "semantic_rule_absent",
        re.compile(r"what\s+would\s+you\s+do\s+if\s+(.{0,30})?(safety|rule|rules|restriction|restrictions)\s+did(?:\s+not|n't)\s+exist", re.IGNORECASE),
    ),
    (
        "semantic_previous_absent",
        re.compile(r"pretend\s+(.{0,30})?(previous|prior|above)\s+instructions?\s+do\s+not\s+exist", re.IGNORECASE),
    ),
    (
        "semantic_hypothetical_no_restrictions",
        re.compile(r"what\s+would\s+you\s+do\s+if\s+(.{0,30})?had\s+no\s+(restriction|restrictions|limit|limits|rule|rules)", re.IGNORECASE),
    ),
    (
        "multilingual_instruction_override",
        re.compile(
            r"(ignorez\s+toutes\s+les\s+instructions\s+precedentes|"
            r"ignore\s+todas\s+las\s+instrucciones\s+anteriores|"
            r"ignora\s+todas\s+tus\s+instrucciones\s+anteriores|"
            r"ignoriere\s+alle\s+vorherigen\s+anweisungen)",
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
            for normalized in self._normalization_candidates(text):
                if _has_malformed_base64_marker(normalized) and "malformed_base64_obfuscation" not in matched:
                    matched.append("malformed_base64_obfuscation")
                for name, pattern in self.patterns:
                    if pattern.search(normalized) and name not in matched:
                        matched.append(name)
                for name, pattern in SEMANTIC_INTENT_PATTERNS:
                    if pattern.search(normalized) and name not in matched:
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

    def _normalization_candidates(self, text: str) -> list[str]:
        """Return normalized variants before regex matching."""
        normalized = unicodedata.normalize("NFKC", text)
        normalized = _strip_accents(html.unescape(normalized)).translate(HOMOGLYPH_SKELETON)
        collapsed = normalized.translate(CONTROL_SPLIT_CHARS)
        candidates = [normalized, collapsed]

        try:
            decoded_phrase = codecs.decode(collapsed, "rot_13")
        except Exception:
            decoded_phrase = collapsed
        if decoded_phrase != collapsed:
            candidates.append(decoded_phrase)

        for token in re.findall(r"\b[A-Za-z][A-Za-z0-9_'-]{3,}\b", collapsed):
            try:
                decoded = codecs.decode(token, "rot_13")
            except Exception:
                continue
            if decoded != token:
                candidates.append(collapsed.replace(token, decoded))

        for match in BASE64_TOKEN.findall(collapsed):
            try:
                decoded_bytes = base64.b64decode(match, validate=True)
                decoded = decoded_bytes.decode("utf-8", errors="ignore")
            except Exception:
                continue
            if decoded:
                candidates.extend(self._normalization_candidates(decoded))

        deduped: list[str] = []
        for candidate in candidates:
            if candidate and candidate not in deduped:
                deduped.append(candidate)
        return deduped


def _strip_accents(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")

def _has_malformed_base64_marker(text: str) -> bool:
    """Flag non-terminal padding in long base64-like tokens as obfuscation."""
    for token in re.findall(r"[A-Za-z0-9+/=]{20,}", text):
        first_pad = token.find("=")
        if first_pad != -1 and any(ch != "=" for ch in token[first_pad:]):
            return True
    return False
