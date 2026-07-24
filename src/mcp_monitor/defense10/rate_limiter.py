"""Layer 5+ : Rate limiting + recipient whitelist (BLAST RADIUS LIMITING).

WHY THIS IS THE MOST IMPORTANT LAYER AGAINST A DETERMINED ADVERSARY:
Detection is never 100%. Something eventually evades every filter.
So the final defense is: even if the attack SUCCEEDS, cap the damage.

The Postmark attack exfiltrated 3,000-15,000 emails/DAY. With:
  - max 10 emails/hour per server
  - human approval required for any NEW recipient domain
  - the attacker gets AT MOST ~10 emails before a human sees the anomaly.

That converts a catastrophic breach into a minor, contained incident.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any


@dataclass
class RateLimitDecision:
    allowed: bool
    reason: str
    current_count: int = 0
    limit: int = 0
    window_seconds: float = 0.0


class RateLimiter:
    """Sliding-window rate limiter per (server, action)."""

    def __init__(self) -> None:
        # (server_id, action) -> deque of timestamps
        self._events: dict[tuple[str, str], deque] = defaultdict(deque)
        # (server_id, action) -> (max_count, window_seconds)
        self._limits: dict[tuple[str, str], tuple[int, float]] = {}

    def set_limit(self, server_id: str, action: str, max_count: int, window_seconds: float) -> None:
        """Configure a rate limit, e.g. set_limit('postmark','send',10,3600)."""
        self._limits[(server_id, action)] = (max_count, window_seconds)

    def check(self, server_id: str, action: str) -> RateLimitDecision:
        """Check and record an event against its rate limit."""
        key = (server_id, action)
        limit = self._limits.get(key)
        if limit is None:
            return RateLimitDecision(allowed=True, reason="no_limit_configured")

        max_count, window = limit
        now = time.time()
        q = self._events[key]
        q.append(now)
        # Evict old events outside the window
        while q and now - q[0] > window:
            q.popleft()

        count = len(q)
        if count > max_count:
            return RateLimitDecision(
                allowed=False,
                reason=f"rate_limit_exceeded: {count} > {max_count} per {window}s",
                current_count=count, limit=max_count, window_seconds=window,
            )
        return RateLimitDecision(
            allowed=True, reason="within_limit",
            current_count=count, limit=max_count, window_seconds=window,
        )


class RecipientWhitelist:
    """Enforces that email/data goes only to pre-approved destinations.

    Any NEW recipient triggers a hold-for-approval, not an outright send.
    This is exactly what would have stopped giftshop.club: it was never
    on anyone's approved recipient list.
    """

    def __init__(self, *, auto_learn: bool = False) -> None:
        self._approved: dict[str, set[str]] = defaultdict(set)
        self._pending: list[dict[str, Any]] = []
        self._auto_learn = auto_learn

    def approve(self, server_id: str, recipient: str) -> None:
        self._approved[server_id].add(recipient.lower())

    def approve_domain(self, server_id: str, domain: str) -> None:
        self._approved[server_id].add("@" + domain.lower().lstrip("@"))

    def check(self, server_id: str, recipients: list[str]) -> RateLimitDecision:
        """Verify every recipient is approved. Hold unknowns for review."""
        approved = self._approved[server_id]
        unknown: list[str] = []
        for r in recipients:
            rl = r.lower()
            domain = "@" + rl.split("@")[-1] if "@" in rl else ""
            if rl in approved or (domain and domain in approved):
                continue
            unknown.append(r)

        if unknown:
            self._pending.append({"server_id": server_id, "recipients": unknown, "ts": time.time()})
            if self._auto_learn:
                for r in unknown:
                    approved.add(r.lower())
            return RateLimitDecision(
                allowed=False,
                reason=f"unapproved_recipients: {unknown} (held for human approval)",
            )
        return RateLimitDecision(allowed=True, reason="all_recipients_approved")

    def pending_approvals(self) -> list[dict[str, Any]]:
        return list(self._pending)
