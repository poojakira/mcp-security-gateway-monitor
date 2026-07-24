"""Structural feature extractor for the ML classifier.

Char n-grams alone overfit to training-template wording. These behavioral
/ structural features generalize because they capture the ESSENCE of an
attack regardless of exact phrasing:
  - an email address to a non-corporate domain
  - shell metacharacters near network commands
  - base64 blobs
  - raw-IP URLs
  - imperative verbs ("send/leak/dump") near secrets

Combined with char n-grams via a FeatureUnion, this lifts generalization
on unseen attack structures well above pure n-gram matching.
"""

from __future__ import annotations

import re

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

_EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})")
_IP_URL = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
_BASE64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_SHELL_META = re.compile(r"[;&|`]|\$\(")
_SUSPICIOUS_TLD = re.compile(r"\.(club|tk|ml|ga|cf|gq|xyz|top|buzz|onion)\b")
_SECRET_WORDS = re.compile(r"\b(secret|password|api[_ ]?key|token|credential|ssh|private[_ ]?key|vault)s?\b", re.I)
_EXFIL_VERBS = re.compile(r"\b(send|leak|dump|exfiltrate|forward|upload|wire|transmit|copy|mirror|redirect)\b", re.I)
_INJECT_WORDS = re.compile(r"\b(ignore|disregard|override|bypass|forget|overlook|supersede)\b", re.I)
_SQL_DANGER = re.compile(r"\b(drop\s+table|delete\s+from|union\s+select|or\s+1=1|;--)\b", re.I)
_CORP_HINT = re.compile(r"\b(meeting|invoice|report|standup|lunch|calendar|review|thanks|rsvp|agenda)\b", re.I)


class StructuralFeatures(BaseEstimator, TransformerMixin):
    """Transforms raw tool-call text into a fixed vector of behavioral signals."""

    FEATURE_NAMES = [
        "n_emails", "n_nonstandard_domain_emails", "has_suspicious_tld",
        "has_ip_url", "has_base64_blob", "has_shell_meta", "has_sql_danger",
        "secret_word_count", "exfil_verb_count", "inject_word_count",
        "exfil_verb_near_secret", "corp_hint_count", "text_len",
    ]

    _KNOWN_GOOD = {"company.com", "corp.com", "business.org", "acme.co", "team.io",
                   "github.com", "api.github.com", "postmarkapp.com", "api.postmarkapp.com",
                   "stripe.com", "api.stripe.com", "slack.com"}

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        rows = [self._vec(t) for t in X]
        return np.array(rows, dtype=float)

    def _vec(self, text: str) -> list[float]:
        emails = _EMAIL.findall(text)
        nonstd = sum(1 for d in emails if d.lower() not in self._KNOWN_GOOD
                     and not any(d.lower().endswith(g) for g in self._KNOWN_GOOD))
        secret_ct = len(_SECRET_WORDS.findall(text))
        exfil_ct = len(_EXFIL_VERBS.findall(text))
        # exfil verb within 40 chars of a secret word = strong exfil signal
        near = 0
        for m in _SECRET_WORDS.finditer(text):
            window = text[max(0, m.start() - 40): m.end() + 40]
            if _EXFIL_VERBS.search(window):
                near = 1
                break
        return [
            float(len(emails)),
            float(nonstd),
            1.0 if _SUSPICIOUS_TLD.search(text) else 0.0,
            1.0 if _IP_URL.search(text) else 0.0,
            1.0 if _BASE64.search(text) else 0.0,
            1.0 if _SHELL_META.search(text) else 0.0,
            1.0 if _SQL_DANGER.search(text) else 0.0,
            float(secret_ct),
            float(exfil_ct),
            float(len(_INJECT_WORDS.findall(text))),
            float(near),
            float(len(_CORP_HINT.findall(text))),
            float(min(len(text), 2000)) / 2000.0,
        ]
