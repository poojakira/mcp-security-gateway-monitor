"""Honeypot / canary token system.

WHY THIS CATCHES ATTACKS EVERY OTHER LAYER MISSES:
Plant fake secrets ("canary tokens") in the environment — a fake API key,
a fake password, a fake customer record. No legitimate workflow ever uses
them. If one of these EVER appears in an outbound tool call, you have
100% certainty of compromise, with zero false positives.

This is how you catch the "unknown unknowns" — the novel attack no
signature or model has seen. The attacker doesn't know which secrets are
real. The moment they exfiltrate a canary, they announce themselves.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CanaryTrip:
    """Record of a canary token being detected in outbound data."""

    token_id: str
    token_value: str
    context: str
    severity: int = 100  # Canary trips are ALWAYS critical — zero false positives
    timestamp: float = field(default_factory=time.time)


class HoneypotVault:
    """Generates and monitors canary tokens.

    Usage:
        vault = HoneypotVault()
        fake_key = vault.mint("aws_key")   # plant this in the environment
        ...
        trips = vault.scan(outbound_payload)  # any canary present => compromise
    """

    def __init__(self) -> None:
        # token_value -> metadata
        self._tokens: dict[str, dict[str, Any]] = {}
        self._trips: list[CanaryTrip] = []

    def mint(self, token_type: str = "generic", label: str = "") -> str:
        """Create a canary token. Plant the return value where an attacker
        would find it (env var, config, fake DB row).

        Formats are designed to be INDISTINGUISHABLE from real secrets
        (no 'CANARY' substring — that would tip off the attacker).
        """
        rand = secrets.token_hex(16)
        if token_type == "aws_key":
            # Real AWS key format: AKIA + 16 uppercase alphanumeric
            value = f"AKIA{secrets.token_hex(8).upper()[:16]}"
        elif token_type == "api_key":
            # Looks like a real Stripe key (no CANARY marker)
            value = f"sk_live_{secrets.token_hex(16)}"
        elif token_type == "password":
            # Looks like a generated password
            value = f"{secrets.token_urlsafe(16)}"
        elif token_type == "email":
            # Looks like a real internal address
            names = ["admin", "ops", "security", "billing", "noreply"]
            value = f"{secrets.choice(names)}-{rand[:4]}@internal.company.io"
        else:
            value = secrets.token_hex(20)

        token_id = hashlib.sha256(value.encode()).hexdigest()[:16]
        self._tokens[value] = {
            "token_id": token_id,
            "type": token_type,
            "label": label,
            "minted_at": time.time(),
        }
        return value

    def scan(self, payload: Any, context: str = "") -> list[CanaryTrip]:
        """Scan any outbound payload for canary tokens.

        Returns a list of trips. A non-empty list means CONFIRMED compromise.
        """
        text = self._flatten(payload)
        trips: list[CanaryTrip] = []
        for value, meta in self._tokens.items():
            if value in text:
                trip = CanaryTrip(
                    token_id=meta["token_id"],
                    token_value=value,
                    context=context or "outbound_payload",
                )
                trips.append(trip)
                self._trips.append(trip)
        return trips

    def scan_tool_call(self, tool_call: dict[str, Any]) -> list[CanaryTrip]:
        """Convenience: scan a full MCP tool call."""
        return self.scan(tool_call, context=f"tool_call:{tool_call.get('name','')}")

    def all_trips(self) -> list[CanaryTrip]:
        return list(self._trips)

    def token_count(self) -> int:
        return len(self._tokens)

    def _flatten(self, obj: Any) -> str:
        """Flatten any nested structure to a searchable string."""
        if isinstance(obj, str):
            return obj
        if isinstance(obj, dict):
            return " ".join(self._flatten(v) for v in obj.values())
        if isinstance(obj, (list, tuple)):
            return " ".join(self._flatten(i) for i in obj)
        return str(obj)
