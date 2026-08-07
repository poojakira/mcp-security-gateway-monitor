"""Prompt injection detection for MCP tool call arguments.

Hybrid detector using:
  1. Input normalization — strips zero-width chars, normalizes homoglyphs, decodes base64
  2. FAST regex first-pass (< 1ms) — 50+ patterns for known injection families
  3. ML second-pass — TF-IDF classifier from defense10 for ambiguous cases

If regex matches with high confidence, the ML pass is skipped.
If regex doesn't match, the ML classifier provides a secondary risk signal.
"""

from __future__ import annotations

import base64
import codecs
import re
import unicodedata
from typing import Any

# ---------------------------------------------------------------------------
# Unicode normalization utilities
# ---------------------------------------------------------------------------

# Zero-width characters that can hide content
ZERO_WIDTH_CHARS: set[str] = {
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\ufeff",  # byte order mark / zero-width no-break space
    "\u2060",  # word joiner
    "\u180e",  # mongolian vowel separator
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
}

# Bidirectional override characters
BIDI_CHARS: set[str] = {
    "\u202a",  # left-to-right embedding
    "\u202b",  # right-to-left embedding
    "\u202c",  # pop directional formatting
    "\u202d",  # left-to-right override
    "\u202e",  # right-to-left override
    "\u2066",  # left-to-right isolate
    "\u2067",  # right-to-left isolate
    "\u2068",  # first strong isolate
    "\u2069",  # pop directional isolate
}

# Homoglyph map: visually similar Unicode chars -> ASCII equivalents
# Covers Cyrillic, Greek, and other common substitutions
HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic lookalikes
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u0458": "j",  # Cyrillic ј
    "\u04bb": "h",  # Cyrillic һ
    "\u0410": "A",  # Cyrillic А
    "\u0412": "B",  # Cyrillic В
    "\u0415": "E",  # Cyrillic Е
    "\u041a": "K",  # Cyrillic К
    "\u041c": "M",  # Cyrillic М
    "\u041d": "H",  # Cyrillic Н
    "\u041e": "O",  # Cyrillic О
    "\u0420": "P",  # Cyrillic Р
    "\u0421": "C",  # Cyrillic С
    "\u0422": "T",  # Cyrillic Т
    "\u0425": "X",  # Cyrillic Х
    # Greek lookalikes
    "\u03b1": "a",  # Greek α
    "\u03bf": "o",  # Greek ο
    "\u03c1": "p",  # Greek ρ
    "\u0391": "A",  # Greek Α
    "\u0392": "B",  # Greek Β
    "\u0395": "E",  # Greek Ε
    "\u0397": "H",  # Greek Η
    "\u0399": "I",  # Greek Ι
    "\u039a": "K",  # Greek Κ
    "\u039c": "M",  # Greek Μ
    "\u039d": "N",  # Greek Ν
    "\u039f": "O",  # Greek Ο
    "\u03a1": "P",  # Greek Ρ
    "\u03a4": "T",  # Greek Τ
    "\u03a5": "Y",  # Greek Υ
    "\u03a7": "X",  # Greek Χ
    "\u03b5": "e",  # Greek ε
    # Fullwidth Latin
    "\uff41": "a",
    "\uff42": "b",
    "\uff43": "c",
    "\uff44": "d",
    "\uff45": "e",
    "\uff46": "f",
    "\uff47": "g",
    "\uff48": "h",
    "\uff49": "i",
    "\uff4a": "j",
    "\uff4b": "k",
    "\uff4c": "l",
    "\uff4d": "m",
    "\uff4e": "n",
    "\uff4f": "o",
    "\uff50": "p",
    "\uff51": "q",
    "\uff52": "r",
    "\uff53": "s",
    "\uff54": "t",
    "\uff55": "u",
    "\uff56": "v",
    "\uff57": "w",
    "\uff58": "x",
    "\uff59": "y",
    "\uff5a": "z",
    # Mathematical/special
    "\u2010": "-",  # hyphen
    "\u2011": "-",  # non-breaking hyphen
    "\u2012": "-",  # figure dash
    "\u2013": "-",  # en dash
    "\u2014": "-",  # em dash
}

# Pre-compile base64 detection pattern
_BASE64_BLOCK_RE = re.compile(
    r"[A-Za-z0-9+/]{20,}={0,2}",
)

# ROT13 detection heuristic: known injection phrases after ROT13
_ROT13_MARKERS = re.compile(
    r"(vtaber|sbetrg|flfgrz|bireevqr|olcnff|qvfertneq|eriyrny|cebzcg|vafgehpgvbaf)",
    re.IGNORECASE,
)


def strip_zero_width(text: str) -> str:
    """Remove zero-width and bidirectional override characters."""
    chars_to_strip = ZERO_WIDTH_CHARS | BIDI_CHARS
    return "".join(ch for ch in text if ch not in chars_to_strip)


def normalize_homoglyphs(text: str) -> str:
    """Replace known Unicode homoglyphs with ASCII equivalents."""
    # First, try NFKC normalization (handles fullwidth, compatibility forms)
    text = unicodedata.normalize("NFKC", text)
    # Then apply our explicit homoglyph map for remaining cases
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def decode_base64_blocks(text: str) -> list[str]:
    """Find and decode base64-encoded blocks in text.

    Returns list of successfully decoded strings (UTF-8 decodable).
    """
    decoded: list[str] = []
    for match in _BASE64_BLOCK_RE.finditer(text):
        candidate = match.group(0)
        # Pad if necessary
        padded = candidate + "=" * (4 - len(candidate) % 4) if len(candidate) % 4 else candidate
        try:
            raw = base64.b64decode(padded, validate=True)
            result = raw.decode("utf-8", errors="strict")
            # Only keep if it looks like text (printable ratio)
            printable_ratio = sum(1 for c in result if c.isprintable() or c.isspace()) / max(
                len(result), 1
            )
            if printable_ratio > 0.7 and len(result) >= 4:
                decoded.append(result)
        except Exception:
            continue
    return decoded


def decode_rot13(text: str) -> str | None:
    """If text contains ROT13-encoded injection markers, return decoded version."""
    if _ROT13_MARKERS.search(text):
        return codecs.decode(text, "rot_13")
    return None


def normalize_input(text: str) -> list[str]:
    """Full normalization pipeline. Returns list of text variants to scan.

    Always includes the normalized version. May include decoded base64/ROT13.
    """
    variants: list[str] = []

    # Step 1: Strip zero-width chars
    cleaned = strip_zero_width(text)

    # Step 2: Normalize homoglyphs
    normalized = normalize_homoglyphs(cleaned)
    variants.append(normalized)

    # Step 3: Decode base64 blocks
    b64_decoded = decode_base64_blocks(normalized)
    for decoded in b64_decoded:
        # Recursively normalize decoded content
        inner_normalized = normalize_homoglyphs(strip_zero_width(decoded))
        variants.append(inner_normalized)

    # Step 4: Check for ROT13
    rot13_result = decode_rot13(normalized)
    if rot13_result:
        variants.append(rot13_result)

    return variants



# ---------------------------------------------------------------------------
# Detection patterns — 50+ rules covering major injection families
# ---------------------------------------------------------------------------

INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # --- Classic instruction override ---
    (
        "ignore_previous_instructions",
        re.compile(
            r"ignore.{0,20}(previous|prior|above|all|earlier).{0,20}instructions?",
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
            r"you\s+are\s+now\s+(dan|jailbreak|unrestricted|evil|dude|god)",
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
            r"disregard.{0,20}(guidelines|rules|policies|restrictions|directives|safety)",
            re.IGNORECASE,
        ),
    ),
    (
        "reveal_prompt",
        re.compile(
            r"(reveal|show|print|output|display|repeat|echo).{0,20}"
            r"(system\s+prompt|hidden\s+instructions|initial\s+prompt|original\s+prompt)",
            re.IGNORECASE,
        ),
    ),
    (
        "act_as_unrestricted",
        re.compile(
            r"act\s+as\s+(an?\s+)?(unrestricted|unfiltered|uncensored|evil|unlimited)",
            re.IGNORECASE,
        ),
    ),
    (
        "new_instructions",
        re.compile(
            r"(new|updated|real|actual|true)\s+instructions?\s*(:|are|supersede|follow)",
            re.IGNORECASE,
        ),
    ),
    (
        "bypass_safety",
        re.compile(
            r"bypass.{0,15}(safety|content|filter|moderation|guardrail|restriction)",
            re.IGNORECASE,
        ),
    ),
    (
        "roleplay_evil",
        re.compile(
            r"(pretend|imagine|suppose)\s+(you.{0,10})?(have\s+no|without|lack).{0,15}"
            r"(restrictions|limits|rules|guidelines|filters)",
            re.IGNORECASE,
        ),
    ),
    # --- Prompt leaking ---
    (
        "prompt_leak_what_is",
        re.compile(
            r"what\s+(is|are)\s+(your|the)\s+(system\s+prompt|instructions|rules|directives)",
            re.IGNORECASE,
        ),
    ),
    (
        "prompt_leak_repeat",
        re.compile(
            r"(repeat|recite|copy|paste|type\s+out).{0,20}"
            r"(everything|all|the\s+text|your\s+instructions|the\s+above|system\s+message)",
            re.IGNORECASE,
        ),
    ),
    (
        "prompt_leak_verbatim",
        re.compile(
            r"(verbatim|word\s+for\s+word|exactly\s+as\s+written)",
            re.IGNORECASE,
        ),
    ),
    # --- Delimiter injection ---
    (
        "delimiter_json_escape",
        re.compile(r'\\n\s*\\n\s*\{?\s*"(role|system|instruction)', re.IGNORECASE),
    ),
    (
        "delimiter_triple_backtick",
        re.compile(r"```\s*(system|instruction|prompt|override)", re.IGNORECASE),
    ),
    (
        "delimiter_separator",
        re.compile(
            r"[-=]{5,}.{0,20}(system|instruction|new\s+role|override|prompt)",
            re.IGNORECASE,
        ),
    ),
    (
        "delimiter_xml_tag",
        re.compile(
            r"<\s*/?(instruction|prompt|context|role|task|message)\s*>",
            re.IGNORECASE,
        ),
    ),
    # --- Markdown/HTML injection ---
    (
        "html_script_injection",
        re.compile(r"<\s*script[\s>]", re.IGNORECASE),
    ),
    (
        "html_event_handler",
        re.compile(r"on(error|load|click|mouseover)\s*=", re.IGNORECASE),
    ),
    (
        "markdown_link_injection",
        re.compile(
            r"\[.*?\]\(\s*(javascript:|data:|vbscript:)",
            re.IGNORECASE,
        ),
    ),
    (
        "html_iframe_injection",
        re.compile(r"<\s*iframe[\s>]", re.IGNORECASE),
    ),
    (
        "markdown_image_exfil",
        re.compile(
            r"!\[.*?\]\(\s*https?://[^)]*\{.*?\}",
            re.IGNORECASE,
        ),
    ),
]


# Extend with encoding, multi-language, indirect, and unicode patterns
INJECTION_PATTERNS.extend([
    # --- Encoding tricks ---
    (
        "base64_instruction",
        re.compile(
            r"(decode|base64|b64|eval)\s*[\(:]?\s*[A-Za-z0-9+/]{16,}={0,2}",
            re.IGNORECASE,
        ),
    ),
    (
        "hex_encoded_payload",
        re.compile(
            r"(\\x[0-9a-f]{2}){4,}",
            re.IGNORECASE,
        ),
    ),
    (
        "unicode_escape_payload",
        re.compile(
            r"(\\u[0-9a-f]{4}){3,}",
            re.IGNORECASE,
        ),
    ),
    (
        "rot13_instruction",
        re.compile(
            r"(rot13|rot-13|caesar)\s*(decode|cipher|transform|apply)",
            re.IGNORECASE,
        ),
    ),
    (
        "encoded_ignore_instruction",
        re.compile(
            r"(aWdub3Jl|Zm9yZ2V0|c3lzdGVt|b3ZlcnJpZGU)",  # base64 fragments of common attacks
            re.IGNORECASE,
        ),
    ),
    # --- Multi-language injection ---
    (
        "injection_spanish",
        re.compile(
            r"(ignora|olvida|desactiva).{0,20}(instrucciones|reglas|anteriores|sistema)",
            re.IGNORECASE,
        ),
    ),
    (
        "injection_french",
        re.compile(
            r"(ignore[rz]?|oublie[rz]?).{0,20}(instructions|r[eè]gles|pr[eé]c[eé]dentes|syst[eè]me)",
            re.IGNORECASE,
        ),
    ),
    (
        "injection_german",
        re.compile(
            r"(ignorier|vergiss).{0,20}(anweisungen|regeln|vorherige|system)",
            re.IGNORECASE,
        ),
    ),
    (
        "injection_chinese",
        re.compile(
            r"(忽略|无视|跳过).{0,10}(指令|规则|之前|系统|提示)",
        ),
    ),
    (
        "injection_japanese",
        re.compile(
            r"(無視|忘れ|システム).{0,10}(指示|ルール|プロンプト|命令)",
        ),
    ),
    (
        "injection_russian",
        re.compile(
            r"(игнорируй|забудь|отмени).{0,20}(инструкции|правила|систем)",
            re.IGNORECASE,
        ),
    ),
    (
        "injection_arabic",
        re.compile(
            r"(تجاهل|انسى|تخطى).{0,20}(التعليمات|القواعد|النظام)",
        ),
    ),
    (
        "injection_portuguese",
        re.compile(
            r"(ignor[ea]|esque[cç]a).{0,20}(instru[cç][oõ]es|regras|anteriores|sistema)",
            re.IGNORECASE,
        ),
    ),
    (
        "injection_korean",
        re.compile(
            r"(무시|잊어|시스템).{0,10}(지시|규칙|프롬프트|명령)",
        ),
    ),
    # --- Indirect injection (hidden in documents/emails) ---
    (
        "indirect_hidden_instruction",
        re.compile(
            r"(IMPORTANT|URGENT|NOTE\s+TO\s+AI|ATTENTION\s+AI|INSTRUCTION\s+FOR\s+(THE\s+)?AI)",
            re.IGNORECASE,
        ),
    ),
    (
        "indirect_assistant_note",
        re.compile(
            r"(dear|hey|hi|hello)\s+(assistant|ai|chatbot|model|gpt|claude|llm)",
            re.IGNORECASE,
        ),
    ),
    (
        "indirect_hidden_text",
        re.compile(
            r"(hidden|invisible|secret)\s+(instruction|command|message|text)\s*(:|for)",
            re.IGNORECASE,
        ),
    ),
    (
        "indirect_email_injection",
        re.compile(
            r"(when\s+you\s+read|upon\s+reading|if\s+you.{0,10}(see|process)\s+this).{0,30}"
            r"(ignore|override|forget|execute|follow\s+these)",
            re.IGNORECASE,
        ),
    ),
    (
        "indirect_document_payload",
        re.compile(
            r"(begin|start)\s+(secret|hidden|special)\s+(section|instructions|protocol)",
            re.IGNORECASE,
        ),
    ),
    # --- Unicode-based attacks ---
    (
        "unicode_bidi_override",
        re.compile(r"[\u202a-\u202e\u2066-\u2069]"),
    ),
    (
        "unicode_tag_chars",
        re.compile(r"[\U000e0001-\U000e007f]"),  # Unicode tag characters
    ),
    (
        "unicode_confusables",
        re.compile(
            r"[\u0430\u0435\u043e\u0440\u0441\u0443\u0445]"  # Cyrillic confusables in Latin context
            r".{0,5}(ignore|system|override|bypass|forget)",
            re.IGNORECASE,
        ),
    ),
    # --- Advanced evasion ---
    (
        "char_splitting",
        re.compile(
            r"(i|I)\s*g\s*n\s*o\s*r\s*e.{0,5}(i|p)\s*n\s*s\s*t\s*r\s*u\s*c",
            re.IGNORECASE,
        ),
    ),
    (
        "payload_concatenation",
        re.compile(
            r"(combine|concatenate|join|merge).{0,30}(instruction|command|payload|string)",
            re.IGNORECASE,
        ),
    ),
    (
        "token_smuggling",
        re.compile(
            r"(split|chunk|fragment|piece).{0,20}(token|word|instruction|command)",
            re.IGNORECASE,
        ),
    ),
    (
        "context_switch",
        re.compile(
            r"(end\s+of|exit|leave|stop).{0,15}(context|conversation|chat|session|mode).{0,15}"
            r"(new|begin|start|enter)",
            re.IGNORECASE,
        ),
    ),
    (
        "developer_mode",
        re.compile(
            r"(developer|debug|maintenance|god|sudo)\s*(mode|access|privileges?)",
            re.IGNORECASE,
        ),
    ),
    (
        "hypothetical_frame",
        re.compile(
            r"(hypothetically|theoretically|in\s+a\s+fictional|for\s+a\s+story).{0,30}"
            r"(how\s+(would|to|can)|ignore|bypass|override)",
            re.IGNORECASE,
        ),
    ),
    (
        "completion_manipulation",
        re.compile(
            r"(continue|complete|finish)\s+(the\s+)?(following|this|sentence|pattern)\s*:"
            r".{0,30}(ignore|system|override)",
            re.IGNORECASE,
        ),
    ),
    (
        "few_shot_injection",
        re.compile(
            r"(example|sample)\s*\d*\s*:?\s*(user|human|input)\s*:.{0,50}"
            r"(assistant|ai|output|response)\s*:",
            re.IGNORECASE,
        ),
    ),
    (
        "instruction_boundary",
        re.compile(
            r"(###|===|\*\*\*|---)\s*(end|begin|start).{0,10}(instruction|system|prompt)",
            re.IGNORECASE,
        ),
    ),
])



# ---------------------------------------------------------------------------
# Pre-scan heuristics for zero-width and bidi detection (before normalization)
# ---------------------------------------------------------------------------

_ZERO_WIDTH_RE = re.compile(
    r"[\u200b\u200c\u200d\ufeff\u2060\u180e]",
)

_BIDI_RE = re.compile(
    r"[\u202a-\u202e\u2066-\u2069]",
)


class PromptInjectionDetector:
    """Detects prompt injection attempts in MCP tool call arguments.

    Uses a multi-pass approach:
      1. Pre-scan for structural indicators (zero-width chars, bidi overrides)
      2. Normalize input (strip zero-width, homoglyphs->ASCII, decode base64/ROT13)
      3. Regex patterns for fast, deterministic detection of known attacks
      4. ML classifier (TF-IDF + structural features) for ambiguous cases
    """

    def __init__(self, *, enable_ml: bool = True) -> None:
        self.patterns = INJECTION_PATTERNS
        self._enable_ml = enable_ml
        self._ml_classifier: Any = None

    def _get_ml_classifier(self) -> Any:
        """Lazy-load the ML classifier on first use."""
        if self._ml_classifier is None and self._enable_ml:
            try:
                from mcp_monitor.defense10.ml_classifier import MLThreatClassifier

                self._ml_classifier = MLThreatClassifier(threshold=0.7)
                self._ml_classifier.train()
            except Exception:
                # If ML deps unavailable, degrade gracefully to regex-only
                self._enable_ml = False
        return self._ml_classifier

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
        raw_texts = self._extract_strings(arguments)
        matched: list[str] = []

        for raw_text in raw_texts:
            # Pre-scan: detect structural indicators before normalization
            self._prescan(raw_text, matched)

            # Normalize and get all text variants to scan
            variants = normalize_input(raw_text)

            # Regex scan on all variants
            for text in variants:
                for name, pattern in self.patterns:
                    if pattern.search(text) and name not in matched:
                        matched.append(name)

        # If regex matched, high confidence — skip ML
        if matched:
            return (True, matched)

        # Pass 2: ML classifier for ambiguous cases
        if self._enable_ml and raw_texts:
            clf = self._get_ml_classifier()
            if clf is not None:
                prediction = clf.classify(tool_call)
                if prediction.is_threat and prediction.confidence >= 0.7:
                    family = prediction.threat_family or "ml_detected"
                    matched.append(f"ml_{family}")

        return (bool(matched), matched)

    def risk_score(self, tool_call: dict[str, Any]) -> int:
        """Return a risk score 0-100 based on matched pattern count and severity.

        Combines regex confidence with ML confidence for a unified score.
        """
        arguments = tool_call.get("arguments", {})
        raw_texts = self._extract_strings(arguments)
        regex_matched: list[str] = []

        for raw_text in raw_texts:
            # Pre-scan
            self._prescan(raw_text, regex_matched)

            # Normalize and scan
            variants = normalize_input(raw_text)
            for text in variants:
                for name, pattern in self.patterns:
                    if pattern.search(text) and name not in regex_matched:
                        regex_matched.append(name)

        if regex_matched:
            # High confidence from regex
            base = 30
            per_pattern = 15
            score = base + per_pattern * len(regex_matched)
            return min(score, 100)

        # ML pass for ambiguous cases
        if self._enable_ml and raw_texts:
            clf = self._get_ml_classifier()
            if clf is not None:
                prediction = clf.classify(tool_call)
                if prediction.is_threat:
                    return min(int(prediction.confidence * 80), 80)

        return 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _prescan(self, text: str, matched: list[str]) -> None:
        """Detect structural Unicode attacks before normalization strips them."""
        if _ZERO_WIDTH_RE.search(text):
            if "zero_width_chars_detected" not in matched:
                matched.append("zero_width_chars_detected")
        if _BIDI_RE.search(text):
            if "unicode_bidi_override" not in matched:
                matched.append("unicode_bidi_override")

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
