"""Circuit breaker pattern for defense layers.

Prevents cascading failures by opening the circuit after consecutive errors,
then probing with half-open state after a timeout.
"""

from __future__ import annotations

import enum
import time
import threading
from typing import Any, Callable, Optional


class CircuitState(enum.Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Circuit breaker wrapping a callable (e.g., a defense layer).

    Parameters
    ----------
    name:
        Identifier for this circuit breaker (e.g., layer name).
    failure_threshold:
        Number of consecutive failures before opening the circuit.
    recovery_timeout:
        Seconds to wait before transitioning from open to half_open.
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        """Current circuit state, accounting for timeout transitions."""
        with self._lock:
            if self._state == CircuitState.OPEN:
                elapsed = time.monotonic() - self._last_failure_time
                if elapsed >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
            return self._state

    def call(
        self,
        func: Callable[..., Any],
        *args: Any,
        fallback: Optional[Callable[..., Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Execute func through the circuit breaker.

        Parameters
        ----------
        func:
            The callable to protect.
        fallback:
            Optional fallback callable if circuit is open.
        *args, **kwargs:
            Arguments passed to func or fallback.

        Returns
        -------
        Result of func or fallback.

        Raises
        ------
        CircuitOpenError:
            If circuit is open and no fallback is provided.
        """
        current_state = self.state

        if current_state == CircuitState.OPEN:
            if fallback is not None:
                return fallback(*args, **kwargs)
            raise CircuitOpenError(f"Circuit '{self.name}' is open")

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception:
            self._on_failure()
            if fallback is not None and self.state == CircuitState.OPEN:
                return fallback(*args, **kwargs)
            raise

    def _on_success(self) -> None:
        """Record a successful call."""
        with self._lock:
            self._failure_count = 0
            self._state = CircuitState.CLOSED

    def _on_failure(self) -> None:
        """Record a failed call."""
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN

    def reset(self) -> None:
        """Manually reset the circuit to closed state."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._last_failure_time = 0.0


class CircuitOpenError(Exception):
    """Raised when a call is attempted on an open circuit."""

    pass
