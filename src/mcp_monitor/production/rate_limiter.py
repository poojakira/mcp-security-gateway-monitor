"""HTTP-level token bucket rate limiter.

Provides per-endpoint rate limiting independent of the per-server
rate limiter in defense10/. Returns 429 when tokens are exhausted.
"""

from __future__ import annotations

import threading
import time


class RateLimiter:
    """Token bucket rate limiter.

    Parameters
    ----------
    tokens_per_minute:
        Maximum requests allowed per minute (refill rate).
    burst_size:
        Maximum token bucket capacity. Defaults to tokens_per_minute.
    """

    def __init__(
        self,
        tokens_per_minute: int = 1000,
        burst_size: int | None = None,
    ) -> None:
        self.tokens_per_minute = tokens_per_minute
        self.burst_size = burst_size if burst_size is not None else tokens_per_minute
        self._tokens: float = float(self.burst_size)
        self._last_refill: float = time.monotonic()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        """Check if a request is allowed and consume a token.

        Returns
        -------
        True if the request is allowed, False if rate limited (429).
        """
        with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

    def remaining_tokens(self) -> float:
        """Return the current number of available tokens."""
        with self._lock:
            self._refill()
            return self._tokens

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        # Tokens refill at tokens_per_minute / 60 per second
        refill_rate = self.tokens_per_minute / 60.0
        new_tokens = elapsed * refill_rate
        self._tokens = min(self._tokens + new_tokens, float(self.burst_size))
        self._last_refill = now

    def reset(self) -> None:
        """Reset the rate limiter to full capacity."""
        with self._lock:
            self._tokens = float(self.burst_size)
            self._last_refill = time.monotonic()
