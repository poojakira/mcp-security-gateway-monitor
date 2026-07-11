"""Graceful shutdown handling.

Registers SIGTERM/SIGINT handlers to drain in-flight requests,
flush the WAL, and exit cleanly.
"""

from __future__ import annotations

import asyncio
import signal
import threading
import time
from typing import Any, Callable, Optional

from mcp_monitor.production.logging import get_logger

_logger = get_logger(__name__)


class GracefulShutdown:
    """Manages graceful shutdown of the production server.

    Parameters
    ----------
    drain_timeout:
        Maximum seconds to wait for in-flight requests to complete.
    on_shutdown:
        Optional callback invoked during shutdown (e.g., flush WAL).
    """

    def __init__(
        self,
        drain_timeout: float = 30.0,
        on_shutdown: Optional[Callable[[], None]] = None,
    ) -> None:
        self.drain_timeout = drain_timeout
        self.on_shutdown = on_shutdown
        self._shutdown_event = threading.Event()
        self._active_requests = 0
        self._lock = threading.Lock()

    @property
    def is_shutting_down(self) -> bool:
        """Whether shutdown has been initiated."""
        return self._shutdown_event.is_set()

    def register_signals(self) -> None:
        """Register signal handlers for SIGTERM and SIGINT."""
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def register_signals_async(self, loop: asyncio.AbstractEventLoop) -> None:
        """Register signal handlers for asyncio event loop."""
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._initiate_shutdown)

    def _handle_signal(self, signum: int, frame: Any) -> None:
        """Signal handler that initiates shutdown."""
        sig_name = signal.Signals(signum).name
        _logger.info(
            f"Received {sig_name}, initiating graceful shutdown",
            extra={"extra_fields": {"signal": sig_name}},
        )
        self._initiate_shutdown()

    def _initiate_shutdown(self) -> None:
        """Set the shutdown flag."""
        self._shutdown_event.set()

    def request_started(self) -> None:
        """Track that a new request has started."""
        with self._lock:
            self._active_requests += 1

    def request_finished(self) -> None:
        """Track that a request has completed."""
        with self._lock:
            self._active_requests -= 1

    @property
    def active_requests(self) -> int:
        """Number of currently in-flight requests."""
        with self._lock:
            return self._active_requests

    def wait_for_drain(self) -> bool:
        """Wait for all in-flight requests to complete.

        Returns
        -------
        True if all requests drained within timeout, False otherwise.
        """
        deadline = time.monotonic() + self.drain_timeout
        while time.monotonic() < deadline:
            if self.active_requests == 0:
                return True
            time.sleep(0.1)
        return self.active_requests == 0

    def execute_shutdown(self) -> None:
        """Execute the full shutdown sequence.

        1. Stop accepting new requests (via is_shutting_down flag)
        2. Wait for in-flight requests to drain
        3. Run on_shutdown callback (e.g., flush WAL)
        """
        self._initiate_shutdown()
        _logger.info(
            f"Draining {self.active_requests} in-flight requests "
            f"(timeout: {self.drain_timeout}s)"
        )

        drained = self.wait_for_drain()
        if not drained:
            _logger.warning(
                f"Drain timeout exceeded, "
                f"{self.active_requests} requests still in flight"
            )

        if self.on_shutdown:
            try:
                self.on_shutdown()
                _logger.info("Shutdown callback completed successfully")
            except Exception as exc:
                _logger.error(f"Shutdown callback failed: {exc}")

        _logger.info("Shutdown complete")
