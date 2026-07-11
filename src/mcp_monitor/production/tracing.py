"""Distributed tracing using stdlib only.

Generates W3C traceparent-compatible trace IDs and span IDs.
Outputs spans as structured JSON log entries for collection by
OpenTelemetry collectors or ELK.
"""

from __future__ import annotations

import collections
import json
import os
import time
from typing import Any, Dict, List, Optional


def _generate_trace_id() -> str:
    """Generate a 128-bit (32 hex char) trace ID."""
    return os.urandom(16).hex()


def _generate_span_id() -> str:
    """Generate a 64-bit (16 hex char) span ID."""
    return os.urandom(8).hex()


class Span:
    """Represents a single span in a trace.

    Parameters
    ----------
    name:
        Span operation name (e.g., "inspect_call", "layer_3_semantic").
    trace_id:
        Parent trace ID.
    parent_span_id:
        Parent span ID (None for root span).
    """

    def __init__(
        self,
        name: str,
        trace_id: str,
        parent_span_id: Optional[str] = None,
    ) -> None:
        self.name = name
        self.trace_id = trace_id
        self.span_id = _generate_span_id()
        self.parent_span_id = parent_span_id
        self.start_time: float = time.time()
        self.end_time: Optional[float] = None
        self.attributes: Dict[str, Any] = {}
        self.status: str = "OK"

    def set_attribute(self, key: str, value: Any) -> None:
        """Set a span attribute."""
        self.attributes[key] = value

    def set_status(self, status: str) -> None:
        """Set span status (OK or ERROR)."""
        self.status = status

    def end(self) -> None:
        """Mark the span as ended."""
        self.end_time = time.time()

    @property
    def duration_ms(self) -> float:
        """Duration in milliseconds."""
        end = self.end_time or time.time()
        return (end - self.start_time) * 1000

    def to_dict(self) -> Dict[str, Any]:
        """Convert span to a dict for JSON serialization."""
        result: Dict[str, Any] = {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "name": self.name,
            "start_time": self._format_time(self.start_time),
            "duration_ms": round(self.duration_ms, 3),
            "status": self.status,
            "attributes": self.attributes,
        }
        if self.parent_span_id:
            result["parent_span_id"] = self.parent_span_id
        if self.end_time:
            result["end_time"] = self._format_time(self.end_time)
        return result

    def to_json(self) -> str:
        """Serialize span to JSON string."""
        return json.dumps(self.to_dict(), default=str)

    @staticmethod
    def _format_time(t: float) -> str:
        """Format time as ISO 8601."""
        tm = time.gmtime(t)
        ms = int((t % 1) * 1000)
        return time.strftime("%Y-%m-%dT%H:%M:%S", tm) + f".{ms:03d}Z"


class Tracer:
    """Creates and manages traces with W3C traceparent support.

    Uses a bounded deque to prevent unbounded memory growth under
    sustained load. Once the maximum span count is reached, the oldest
    spans are discarded automatically.

    Parameters
    ----------
    service_name:
        Service name attached to all spans.
    max_spans:
        Maximum number of spans to retain in memory. Older spans are
        evicted when this limit is reached. Defaults to 10000.
    """

    def __init__(
        self,
        service_name: str = "mcp-security-monitor",
        max_spans: int = 10000,
    ) -> None:
        self.service_name = service_name
        self._spans: collections.deque = collections.deque(maxlen=max_spans)

    def start_trace(self) -> str:
        """Start a new trace and return the trace_id."""
        return _generate_trace_id()

    def start_span(
        self,
        name: str,
        trace_id: str,
        parent_span_id: Optional[str] = None,
    ) -> Span:
        """Create and start a new span.

        Parameters
        ----------
        name:
            Operation name for this span.
        trace_id:
            Trace this span belongs to.
        parent_span_id:
            Parent span ID for nested spans.

        Returns
        -------
        A new Span instance.
        """
        span = Span(name=name, trace_id=trace_id, parent_span_id=parent_span_id)
        span.set_attribute("service.name", self.service_name)
        self._spans.append(span)
        return span

    def end_span(self, span: Span) -> None:
        """End a span and record its completion."""
        span.end()

    @staticmethod
    def parse_traceparent(header: str) -> Optional[Dict[str, str]]:
        """Parse a W3C traceparent header.

        Format: {version}-{trace_id}-{parent_span_id}-{flags}
        Example: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01

        Returns
        -------
        Dict with trace_id, parent_span_id, and flags, or None if invalid.
        """
        if not header:
            return None
        parts = header.strip().split("-")
        if len(parts) != 4:
            return None
        version, trace_id, parent_span_id, flags = parts
        if len(trace_id) != 32 or len(parent_span_id) != 16:
            return None
        return {
            "version": version,
            "trace_id": trace_id,
            "parent_span_id": parent_span_id,
            "flags": flags,
        }

    @staticmethod
    def create_traceparent(
        trace_id: str, span_id: str, sampled: bool = True
    ) -> str:
        """Create a W3C traceparent header value.

        Parameters
        ----------
        trace_id:
            128-bit trace ID (32 hex chars).
        span_id:
            64-bit span ID (16 hex chars).
        sampled:
            Whether this trace is sampled.

        Returns
        -------
        W3C traceparent header string.
        """
        flags = "01" if sampled else "00"
        return f"00-{trace_id}-{span_id}-{flags}"

    def get_completed_spans(self) -> List[Span]:
        """Return all completed spans."""
        return [s for s in self._spans if s.end_time is not None]

    def clear(self) -> None:
        """Clear all recorded spans."""
        self._spans.clear()
