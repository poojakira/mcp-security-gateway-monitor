"""Prometheus-compatible metrics using stdlib only.

Tracks request counts, latency histograms, errors, active requests,
and circuit breaker states. Exposes metrics in Prometheus text exposition format.
"""

from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional


# Default histogram buckets (seconds) targeting p50/p95/p99
DEFAULT_BUCKETS = (
    0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75,
    1.0, 2.5, 5.0, 7.5, 10.0, float("inf"),
)


class MetricsCollector:
    """Collects and exposes Prometheus-compatible metrics.

    Thread-safe counters, gauges, and histograms.
    """

    def __init__(self, buckets: tuple[float, ...] = DEFAULT_BUCKETS) -> None:
        self._lock = threading.Lock()
        self._buckets = buckets

        # Counters
        self._request_total: int = 0
        self._error_total: int = 0
        self._request_total_by_endpoint: Dict[str, int] = {}

        # Gauge
        self._active_requests: int = 0

        # Histogram data
        self._duration_sum: float = 0.0
        self._duration_count: int = 0
        self._duration_buckets: List[int] = [0] * len(self._buckets)

        # Circuit breaker states
        self._circuit_states: Dict[str, str] = {}

    def inc_request(self, endpoint: str = "") -> None:
        """Increment total request counter."""
        with self._lock:
            self._request_total += 1
            if endpoint:
                self._request_total_by_endpoint[endpoint] = (
                    self._request_total_by_endpoint.get(endpoint, 0) + 1
                )

    def inc_error(self) -> None:
        """Increment error counter."""
        with self._lock:
            self._error_total += 1

    def inc_active(self) -> None:
        """Increment active requests gauge."""
        with self._lock:
            self._active_requests += 1

    def dec_active(self) -> None:
        """Decrement active requests gauge."""
        with self._lock:
            self._active_requests -= 1

    def observe_duration(self, duration_seconds: float) -> None:
        """Record a request duration in the histogram."""
        with self._lock:
            self._duration_sum += duration_seconds
            self._duration_count += 1
            for i, bound in enumerate(self._buckets):
                if duration_seconds <= bound:
                    self._duration_buckets[i] += 1

    def set_circuit_state(self, name: str, state: str) -> None:
        """Record current circuit breaker state for a layer."""
        with self._lock:
            self._circuit_states[name] = state

    def get_active_requests(self) -> int:
        """Return current active requests count."""
        with self._lock:
            return self._active_requests

    def expose(self) -> str:
        """Return metrics in Prometheus text exposition format."""
        with self._lock:
            lines: List[str] = []

            # request_total counter
            lines.append(
                "# HELP mcp_request_total Total number of requests."
            )
            lines.append("# TYPE mcp_request_total counter")
            lines.append(f"mcp_request_total {self._request_total}")

            # Per-endpoint counters
            for endpoint, count in sorted(
                self._request_total_by_endpoint.items()
            ):
                lines.append(
                    f'mcp_request_total{{endpoint="{endpoint}"}} {count}'
                )

            # error_total counter
            lines.append(
                "# HELP mcp_error_total Total number of errors."
            )
            lines.append("# TYPE mcp_error_total counter")
            lines.append(f"mcp_error_total {self._error_total}")

            # active_requests gauge
            lines.append(
                "# HELP mcp_active_requests Current in-flight requests."
            )
            lines.append("# TYPE mcp_active_requests gauge")
            lines.append(f"mcp_active_requests {self._active_requests}")

            # request_duration_seconds histogram
            lines.append(
                "# HELP mcp_request_duration_seconds "
                "Request duration histogram."
            )
            lines.append("# TYPE mcp_request_duration_seconds histogram")
            cumulative = 0
            for i, bound in enumerate(self._buckets):
                cumulative += self._duration_buckets[i]
                if bound == float("inf"):
                    lines.append(
                        f'mcp_request_duration_seconds_bucket{{le="+Inf"}} '
                        f"{cumulative}"
                    )
                else:
                    lines.append(
                        f'mcp_request_duration_seconds_bucket{{le="{bound}"}} '
                        f"{cumulative}"
                    )
            lines.append(
                f"mcp_request_duration_seconds_sum {self._duration_sum}"
            )
            lines.append(
                f"mcp_request_duration_seconds_count {self._duration_count}"
            )

            # circuit_breaker_state
            if self._circuit_states:
                lines.append(
                    "# HELP mcp_circuit_breaker_state "
                    "Circuit breaker state per layer (0=closed, 1=open, 2=half_open)."
                )
                lines.append("# TYPE mcp_circuit_breaker_state gauge")
                state_map = {"closed": 0, "open": 1, "half_open": 2}
                for name, state in sorted(self._circuit_states.items()):
                    val = state_map.get(state, -1)
                    lines.append(
                        f'mcp_circuit_breaker_state{{layer="{name}"}} {val}'
                    )

            lines.append("")  # Trailing newline
            return "\n".join(lines)
