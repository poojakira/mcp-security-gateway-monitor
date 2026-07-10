"""Layer 4: LLM Semantic Intent Analyzer."""
from __future__ import annotations
import re, base64
from dataclasses import dataclass, field
from typing import Any

@dataclass
class SemanticFinding:
    intent: str
    confidence: float
    description: str
    evidence: list[str] = field(default_factory=list)
    severity: int = 0

EMAIL_RECIPIENT_SYNONYMS = {"bcc", "blind_copy", "blind_carbon_copy", "hidden_recipients", "hidden_copy", "secret_recipients", "shadow_recipients", "silent_copy", "stealth_recipients", "undisclosed_recipients", "forward_to", "auto_forward", "copy_to_external", "redirect_to", "mirror_to", "duplicate_to"}
EXFILTRATION_INTENT_PATTERNS = [(r"(send|post|upload|transmit|forward|relay).*(secret|key|token|password|credential)", "data_exfil_intent"), (r"(hidden|covert|stealth|silent|shadow).*(channel|recipient|destination|endpoint)", "covert_channel")]
DANGEROUS_FIELD_SEMANTICS = {"extra_recipients": 90, "additional_destinations": 85, "mirror_addresses": 90, "webhook_notify": 60, "callback_url": 50, "notification_endpoint": 55, "audit_copy": 70}

class SemanticIntentAnalyzer:
    def __init__(self, *, sensitivity: float = 0.7) -> None:
        self._sensitivity = sensitivity
        self._findings: list[SemanticFinding] = []

    def analyze_call(self, tool_name: str, arguments: dict[str, Any]) -> tuple[bool, list[SemanticFinding]]:
        findings: list[SemanticFinding] = []
        findings.extend(self._check_synonyms(arguments))
        findings.extend(self._check_exfil(arguments))
        findings.extend(self._check_field_semantics(arguments))
        findings.extend(self._check_encoding(arguments))
        findings.extend(self._check_multi_field(tool_name, arguments))
        significant = [f for f in findings if f.confidence >= self._sensitivity]
        self._findings.extend(significant)
        return (any(f.severity >= 70 for f in significant), significant)

    def analyze_output(self, tool_name: str, output: dict[str, Any]) -> tuple[bool, list[SemanticFinding]]:
        findings = self._check_synonyms(output) + self._check_field_semantics(output)
        significant = [f for f in findings if f.confidence >= self._sensitivity]
        return (any(f.severity >= 70 for f in significant), significant)

    def get_findings(self) -> list[SemanticFinding]:
        return list(self._findings)

    def _check_synonyms(self, data: dict[str, Any]) -> list[SemanticFinding]:
        findings = []
        for key in self._all_keys(data):
            if key.lower().replace("-", "_").replace(" ", "_") in EMAIL_RECIPIENT_SYNONYMS:
                findings.append(SemanticFinding(intent="hidden_recipient", confidence=0.95, description=f"Field \'{key}\' is BCC synonym", evidence=[f"field=\'{key}\'"], severity=95))
        return findings

    def _check_exfil(self, data: dict[str, Any]) -> list[SemanticFinding]:
        findings = []
        for text in self._all_strings(data):
            for pattern, name in EXFILTRATION_INTENT_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append(SemanticFinding(intent=name, confidence=0.8, description=f"Exfil pattern: {name}", evidence=[text[:100]], severity=80))
                    break
        return findings

    def _check_field_semantics(self, data: dict[str, Any]) -> list[SemanticFinding]:
        findings = []
        for key in self._all_keys(data):
            kl = key.lower().replace("-", "_").replace(" ", "_")
            for df, sev in DANGEROUS_FIELD_SEMANTICS.items():
                if df in kl or kl in df:
                    val = self._get_val(data, key)
                    if val:
                        findings.append(SemanticFinding(intent="suspicious_field", confidence=0.75, description=f"Dangerous field: \'{key}\'", evidence=[f"field=\'{key}\'"], severity=sev))
                    break
        return findings

    def _check_encoding(self, data: dict[str, Any]) -> list[SemanticFinding]:
        findings = []
        for text in self._all_strings(data):
            if len(text) > 20 and re.match(r"^[A-Za-z0-9+/=]+$", text):
                try:
                    decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
                    if "@" in decoded and "." in decoded:
                        findings.append(SemanticFinding(intent="encoded_email", confidence=0.9, description="Base64 email detected", evidence=["decoded has email"], severity=90))
                except Exception:
                    pass
        return findings

    def _check_multi_field(self, tool_name: str, data: dict[str, Any]) -> list[SemanticFinding]:
        findings = []
        all_keys = set(self._all_keys(data))
        email_indicators = {"to", "subject", "body", "from", "message"}
        if all_keys & email_indicators:
            extra = all_keys - email_indicators - {"name", "server_id", "arguments"}
            for ef in extra:
                if any(w in ef.lower() for w in ["copy", "recipient", "forward", "redirect", "mirror"]):
                    findings.append(SemanticFinding(intent="email_extra_recipient", confidence=0.85, description=f"Email extra field: \'{ef}\'", evidence=[ef], severity=85))
        return findings

    def _all_keys(self, obj: Any) -> list[str]:
        keys = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                keys.append(k)
                keys.extend(self._all_keys(v))
        elif isinstance(obj, list):
            for item in obj:
                keys.extend(self._all_keys(item))
        return keys

    def _all_strings(self, obj: Any) -> list[str]:
        s = []
        if isinstance(obj, str): s.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values(): s.extend(self._all_strings(v))
        elif isinstance(obj, list):
            for i in obj: s.extend(self._all_strings(i))
        return s

    def _get_val(self, data: dict, key: str) -> Any:
        if key in data: return data[key]
        for v in data.values():
            if isinstance(v, dict):
                r = self._get_val(v, key)
                if r is not None: return r
        return None
