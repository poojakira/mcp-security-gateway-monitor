"""Layer B: DPI egress proxy — compares MCP INTENT vs ACTUAL network call.

THE KEY INSIGHT THAT DEFEATS THE POSTMARK ATTACK:
The MCP tool call says: send to ['user@company.com'].
The actual HTTP POST to api.postmarkapp.com says: To=user@company.com,
    Bcc=phan@giftshop.club.

If you compare the two, the discrepancy is undeniable. The server added a
recipient the agent never authorized. This is mathematical certainty, not
heuristics — the extra recipient is right there in the outbound packet.

This module provides:
1. IntentRegistry — records what each MCP tool call authorized.
2. EgressInspector — parses actual outbound HTTP/SMTP payloads and compares
   the real recipients against the authorized ones.
3. A mitmproxy addon (get_mitmproxy_addon) for live TLS-terminated inspection.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EgressVerdict:
    allowed: bool
    reason: str
    authorized_recipients: list[str] = field(default_factory=list)
    actual_recipients: list[str] = field(default_factory=list)
    unauthorized_recipients: list[str] = field(default_factory=list)
    severity: int = 0
    timestamp: float = field(default_factory=time.time)


_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


class IntentRegistry:
    """Records the recipients each MCP tool call authorized, keyed by a
    correlation id, so we can later compare against the actual egress call.

    TTL: Intent records expire after max_age_seconds to prevent unbounded memory.
    """

    def __init__(
        self, *, max_age_seconds: float = 300.0, max_entries: int = 10000
    ) -> None:
        self._intents: dict[str, dict[str, Any]] = {}
        self._max_age = max_age_seconds
        self._max_entries = max_entries

    def record(self, correlation_id: str, tool_call: dict[str, Any]) -> None:
        self._evict_stale()
        args = tool_call.get("arguments", {})
        recipients = self._extract_authorized_recipients(args)
        self._intents[correlation_id] = {
            "recipients": recipients,
            "tool": tool_call.get("name", ""),
            "ts": time.time(),
        }

    def get(self, correlation_id: str) -> dict[str, Any] | None:
        record = self._intents.get(correlation_id)
        if record and (time.time() - record["ts"]) > self._max_age:
            del self._intents[correlation_id]
            return None
        return record

    def _evict_stale(self) -> None:
        """Remove expired entries and enforce max size."""
        now = time.time()
        if len(self._intents) > self._max_entries:
            # Remove oldest entries
            sorted_keys = sorted(
                self._intents.keys(), key=lambda k: self._intents[k]["ts"]
            )
            for k in sorted_keys[: len(sorted_keys) // 2]:
                del self._intents[k]
        # Remove expired
        expired = [k for k, v in self._intents.items() if now - v["ts"] > self._max_age]
        for k in expired:
            del self._intents[k]

    @staticmethod
    def _extract_authorized_recipients(args: dict[str, Any]) -> set[str]:
        """Only fields the AGENT explicitly set count as authorized."""
        authorized: set[str] = set()
        for key in ("to", "recipient", "recipients", "cc"):
            val = args.get(key)
            if isinstance(val, str):
                authorized.update(m.lower() for m in _EMAIL_RE.findall(val))
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        authorized.update(m.lower() for m in _EMAIL_RE.findall(item))
        return authorized


class EgressInspector:
    """Inspects an actual outbound payload and compares its recipients to
    what the originating MCP tool call authorized."""

    def __init__(self, registry: IntentRegistry) -> None:
        self._registry = registry
        self._verdicts: list[EgressVerdict] = []

    def inspect(self, correlation_id: str, actual_payload: Any) -> EgressVerdict:
        """Compare actual outbound recipients vs authorized recipients."""
        intent = self._registry.get(correlation_id)
        authorized = set(intent["recipients"]) if intent else set()

        actual = self._extract_all_emails(actual_payload)

        # Any recipient in the actual call NOT authorized by the agent = exfil
        unauthorized = sorted(actual - authorized)

        if unauthorized:
            verdict = EgressVerdict(
                allowed=False,
                reason=f"UNAUTHORIZED recipients in outbound call: {unauthorized}",
                authorized_recipients=sorted(authorized),
                actual_recipients=sorted(actual),
                unauthorized_recipients=unauthorized,
                severity=98,
            )
        else:
            verdict = EgressVerdict(
                allowed=True,
                reason="all outbound recipients were authorized by the agent",
                authorized_recipients=sorted(authorized),
                actual_recipients=sorted(actual),
            )
        self._verdicts.append(verdict)
        return verdict

    def all_verdicts(self) -> list[EgressVerdict]:
        return list(self._verdicts)

    @staticmethod
    def _extract_all_emails(payload: Any) -> set[str]:
        """Extract every email address appearing anywhere in the actual
        outbound payload — including BCC, headers, SMTP RCPT TO."""
        text = payload if isinstance(payload, str) else json.dumps(payload, default=str)
        return {m.lower() for m in _EMAIL_RE.findall(text)}


def get_mitmproxy_addon(inspector: "EgressInspector"):
    """Return a mitmproxy addon class for LIVE TLS-terminated inspection.

    Deploy: mitmdump -s this_addon.py  with the sandboxed MCP server's
    traffic routed through the proxy. Every outbound API call is compared
    against the authorizing MCP intent in real time.
    """

    class _EgressAddon:
        def __init__(self) -> None:
            self.inspector = inspector

        def request(self, flow) -> None:  # pragma: no cover - needs live proxy
            # Correlation id passed by the gateway as a header
            cid = flow.request.headers.get("X-MCP-Correlation-Id", "")
            body = flow.request.get_text() or ""
            verdict = self.inspector.inspect(cid, body)
            if not verdict.allowed:
                # BLOCK the outbound call — the exfiltration never leaves
                flow.response = _make_blocked_response(verdict)

    def _make_blocked_response(verdict):  # pragma: no cover
        from mitmproxy import http

        return http.Response.make(
            403,
            json.dumps({"blocked": True, "reason": verdict.reason}).encode(),
            {"Content-Type": "application/json"},
        )

    return _EgressAddon
