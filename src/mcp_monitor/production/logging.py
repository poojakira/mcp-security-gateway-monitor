"""Structured JSON logging using stdlib logging module.

Produces ELK/Datadog-compatible JSON log entries with trace context.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional


class JSONFormatter(logging.Formatter):
    """Formats log records as JSON with trace context and service metadata."""

    def __init__(self, service: str = "mcp-security-monitor") -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as a JSON string."""
        log_entry: dict[str, Any] = {
            "timestamp": self._format_timestamp(record.created),
            "level": record.levelname,
            "message": record.getMessage(),
            "service": self.service,
            "logger": record.name,
        }

        # Add trace context if available
        trace_id = getattr(record, "trace_id", None)
        if trace_id:
            log_entry["trace_id"] = trace_id

        span_id = getattr(record, "span_id", None)
        if span_id:
            log_entry["span_id"] = span_id

        # Add any extra fields
        extra = getattr(record, "extra_fields", None)
        if extra and isinstance(extra, dict):
            log_entry.update(extra)

        # Add exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)

    @staticmethod
    def _format_timestamp(created: float) -> str:
        """Format timestamp as ISO 8601 with milliseconds."""
        t = time.gmtime(created)
        ms = int((created % 1) * 1000)
        return time.strftime("%Y-%m-%dT%H:%M:%S", t) + f".{ms:03d}Z"


def get_logger(
    name: str,
    level: str = "INFO",
    service: str = "mcp-security-monitor",
) -> logging.Logger:
    """Create a logger with JSON formatting.

    Parameters
    ----------
    name:
        Logger name (typically module name).
    level:
        Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    service:
        Service name included in every log entry.

    Returns
    -------
    Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Only add handler if logger has none (avoid duplicate handlers)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter(service=service))
        logger.addHandler(handler)
        logger.propagate = False

    return logger


class TraceLogAdapter(logging.LoggerAdapter):
    """Logger adapter that injects trace_id and span_id into log records."""

    def __init__(
        self,
        logger: logging.Logger,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
    ) -> None:
        super().__init__(logger, {})
        self._trace_id = trace_id
        self._span_id = span_id

    def process(
        self, msg: str, kwargs: Any
    ) -> tuple[str, Any]:
        """Inject trace context into the log record."""
        extra = kwargs.get("extra", {})
        if self._trace_id:
            extra["trace_id"] = self._trace_id
        if self._span_id:
            extra["span_id"] = self._span_id
        kwargs["extra"] = extra
        return msg, kwargs
