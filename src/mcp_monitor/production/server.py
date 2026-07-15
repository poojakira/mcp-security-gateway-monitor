"""asyncio-based HTTP server for MCP Security Gateway Monitor.

Provides versioned API endpoints integrating all production components:
config, logging, circuit breakers, rate limiting, alerting, metrics,
tracing, shadow mode, and graceful shutdown.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from secrets import compare_digest
import time
from typing import Any, Dict, Optional, Tuple

from mcp_monitor.monitor import MCPSecurityMonitor
from mcp_monitor.audit.log import AuditEntry, AuditLog
from mcp_monitor.audit.wal import WriteAheadLog
from mcp_monitor.production.config import Config
from mcp_monitor.production.logging import get_logger
from mcp_monitor.production.circuit_breaker import CircuitBreaker
from mcp_monitor.production.rate_limiter import RateLimiter
from mcp_monitor.production.alerting import AlertingHook
from mcp_monitor.production.metrics import MetricsCollector
from mcp_monitor.production.tracing import Tracer
from mcp_monitor.production.shutdown import GracefulShutdown


class ProductionServer:
    """asyncio HTTP server with full production infrastructure.

    Integrates configuration, logging, circuit breakers, rate limiting,
    alerting, metrics, tracing, shadow mode, and graceful shutdown.
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self._logger = get_logger(
            "mcp_monitor.production.server",
            level=self.config.log_level,
        )

        # Set up core monitor
        wal_path = self.config.wal_path or os.path.join(
            tempfile.gettempdir(), "mcp_monitor_wal.jsonl"
        )
        audit_path = self.config.audit_path or os.path.join(
            tempfile.gettempdir(), "mcp_monitor_audit.jsonl"
        )
        self._wal = WriteAheadLog(wal_path)
        self._audit_log = AuditLog(log_file=audit_path)
        self._monitor = MCPSecurityMonitor(
            allowed_servers=self.config.allowed_servers,
            audit_log=self._audit_log,
            max_payload_kb=self.config.max_payload_kb,
        )

        # Production components
        self._rate_limiter = RateLimiter(tokens_per_minute=self.config.rate_limit_rpm)
        self._metrics = MetricsCollector()
        self._tracer = Tracer()
        self._alerting = AlertingHook(
            webhook_url=self.config.webhook_url,
            risk_threshold=80,
        )
        self._circuit_breaker = CircuitBreaker(
            name="inspect_call",
            failure_threshold=self.config.circuit_breaker_threshold,
            recovery_timeout=self.config.circuit_breaker_timeout,
        )
        self._output_circuit_breaker = CircuitBreaker(
            name="inspect_output",
            failure_threshold=self.config.circuit_breaker_threshold,
            recovery_timeout=self.config.circuit_breaker_timeout,
        )
        self._shutdown = GracefulShutdown(
            drain_timeout=30.0,
            on_shutdown=self._flush_wal,
        )

        self._server: Optional[asyncio.Server] = None

    def _flush_wal(self) -> None:
        """Flush the WAL during shutdown."""
        try:
            self._wal.checkpoint()
            self._logger.info("WAL flushed successfully")
        except Exception as exc:
            self._logger.error(f"WAL flush failed: {exc}")

    async def start(self) -> None:
        """Start the HTTP server."""
        loop = asyncio.get_event_loop()

        # Register signal handlers (only on Unix-like systems)
        try:
            self._shutdown.register_signals_async(loop)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

        self._server = await asyncio.start_server(
            self._handle_connection,
            "0.0.0.0",
            self.config.listen_port,
        )
        self._logger.info(
            f"Server started on port {self.config.listen_port}",
            extra={
                "extra_fields": {
                    "port": self.config.listen_port,
                    "shadow_mode": self.config.shadow_mode,
                }
            },
        )

        async with self._server:
            try:
                await self._server.serve_forever()
            except asyncio.CancelledError:
                pass
            finally:
                await self._graceful_shutdown()

    async def _graceful_shutdown(self) -> None:
        """Execute graceful shutdown sequence."""
        self._shutdown.execute_shutdown()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single HTTP connection."""
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=30.0)
            if not request_line:
                writer.close()
                return

            # Parse request line
            request_str = request_line.decode("utf-8", errors="replace").strip()
            parts = request_str.split(" ")
            if len(parts) < 2:
                await self._send_response(writer, 400, {"error": "Bad request"})
                return

            method = parts[0].upper()
            path = parts[1]

            # Read headers
            headers: Dict[str, str] = {}
            while True:
                header_line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                header_str = header_line.decode("utf-8", errors="replace").strip()
                if not header_str:
                    break
                if ":" in header_str:
                    key, value = header_str.split(":", 1)
                    headers[key.strip().lower()] = value.strip()

            # Read body if content-length specified
            body = b""
            content_length = int(headers.get("content-length", "0"))
            if content_length > 0:
                # Check payload size
                max_bytes = int(self.config.max_payload_kb * 1024)
                if content_length > max_bytes:
                    await self._send_response(
                        writer, 413, {"error": "Payload too large"}
                    )
                    return
                body = await asyncio.wait_for(
                    reader.readexactly(content_length), timeout=30.0
                )

            # Check shutdown
            if self._shutdown.is_shutting_down:
                await self._send_response(
                    writer, 503, {"error": "Server shutting down"}
                )
                return

            # Determine if this is an operational endpoint that should
            # bypass rate limiting (health probes, readiness checks,
            # metrics scrapes). These must remain available even under
            # load to prevent Kubernetes from marking pods as unready.
            _RATE_LIMIT_EXEMPT_PATHS = {"/v1/health", "/v1/ready", "/v1/metrics"}
            if path not in _RATE_LIMIT_EXEMPT_PATHS:
                # Rate limiting (only for non-operational endpoints)
                if not self._rate_limiter.allow():
                    self._metrics.inc_error()
                    await self._send_response(
                        writer, 429, {"error": "Rate limit exceeded"}
                    )
                    return

            # Route request
            self._shutdown.request_started()
            self._metrics.inc_active()
            self._metrics.inc_request(path)
            start_time = time.monotonic()

            # Tracing
            traceparent = headers.get("traceparent", "")
            parsed_tp = self._tracer.parse_traceparent(traceparent)
            if parsed_tp:
                trace_id = parsed_tp["trace_id"]
                parent_span_id = parsed_tp["parent_span_id"]
            else:
                trace_id = self._tracer.start_trace()
                parent_span_id = None

            span = self._tracer.start_span(
                name=f"{method} {path}",
                trace_id=trace_id,
                parent_span_id=parent_span_id,
            )

            try:
                status, response_body = await self._route(
                    method, path, body, headers, trace_id, span.span_id
                )
                span.set_attribute("http.status_code", status)
                if status >= 400:
                    span.set_status("ERROR")
                    self._metrics.inc_error()
            except Exception as exc:
                self._logger.error(f"Request handling error: {exc}")
                status = 500
                response_body = {"error": "Internal server error"}
                span.set_status("ERROR")
                self._metrics.inc_error()
            finally:
                self._tracer.end_span(span)
                duration = time.monotonic() - start_time
                self._metrics.observe_duration(duration)
                self._metrics.dec_active()
                self._shutdown.request_finished()

            # Add trace headers to response
            response_headers = {
                "X-Trace-Id": trace_id,
                "X-Span-Id": span.span_id,
                "traceparent": self._tracer.create_traceparent(trace_id, span.span_id),
            }

            await self._send_response(
                writer, status, response_body, extra_headers=response_headers
            )

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            self._logger.error(f"Connection error: {exc}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _route(
        self,
        method: str,
        path: str,
        body: bytes,
        headers: Dict[str, str],
        trace_id: str,
        span_id: str,
    ) -> Tuple[int, Any]:
        """Route a request to the appropriate handler."""
        # Health check
        if method == "GET" and path == "/v1/health":
            return self._handle_health()

        # Readiness probe
        if method == "GET" and path == "/v1/ready":
            return self._handle_ready()

        # Metrics
        if method == "GET" and path == "/v1/metrics":
            return self._handle_metrics()

        if method == "POST" and path in {"/v1/inspect_call", "/v1/inspect_output"}:
            auth_status = self._authorize(headers)
            if auth_status is not None:
                return auth_status
            self._record_wal_event(path, body, trace_id, span_id)
            if path == "/v1/inspect_call":
                return self._handle_inspect_call(body, trace_id, span_id)
            return self._handle_inspect_output(body, trace_id, span_id)
        return 404, {"error": "Not found"}

    def _authorize(
        self, headers: Dict[str, str]
    ) -> Optional[Tuple[int, Dict[str, str]]]:
        """Authorize protected inspection endpoints."""
        if self.config.allow_anonymous:
            return None
        if not self.config.api_key:
            self._metrics.inc_error()
            return 503, {"error": "MCP_API_KEY is not configured"}
        supplied = headers.get("x-api-key", "")
        if not supplied or not compare_digest(supplied, self.config.api_key):
            self._metrics.inc_error()
            return 401, {"error": "Unauthorized"}
        return None

    def _record_wal_event(
        self, path: str, body: bytes, trace_id: str, span_id: str
    ) -> None:
        """Persist protected request metadata to WAL before processing."""
        import hashlib

        entry = AuditEntry(
            event_type="production_request_received",
            data={
                "path": path,
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "body_bytes": len(body),
                "trace_id": trace_id,
                "span_id": span_id,
            },
            prev_hash="0" * 64,
        )
        entry.entry_hash = entry.compute_hash()
        self._wal.write(entry)

    def _handle_health(self) -> Tuple[int, Dict[str, Any]]:
        """GET /v1/health - Health check endpoint."""
        return 200, {
            "status": "healthy",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def _handle_ready(self) -> Tuple[int, Dict[str, Any]]:
        """GET /v1/ready - Readiness probe (checks WAL writability)."""
        try:
            # Test WAL writability by checking parent dir is writable
            wal_path = self.config.wal_path or os.path.join(
                tempfile.gettempdir(), "mcp_monitor_wal.jsonl"
            )
            wal_dir = os.path.dirname(wal_path) or "."
            if os.access(wal_dir, os.W_OK):
                return 200, {"status": "ready"}
            else:
                return 503, {"status": "not_ready", "reason": "WAL not writable"}
        except Exception as exc:
            return 503, {"status": "not_ready", "reason": str(exc)}

    def _handle_metrics(self) -> Tuple[int, str]:
        """GET /v1/metrics - Prometheus text exposition format."""
        # Update circuit breaker states
        self._metrics.set_circuit_state(
            "inspect_call", self._circuit_breaker.state.value
        )
        self._metrics.set_circuit_state(
            "inspect_output", self._output_circuit_breaker.state.value
        )
        return 200, self._metrics.expose()

    def _handle_inspect_call(
        self, body: bytes, trace_id: str, span_id: str
    ) -> Tuple[int, Dict[str, Any]]:
        """POST /v1/inspect_call - Forward to MCPSecurityMonitor."""
        try:
            tool_call = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return 400, {"error": f"Invalid JSON: {exc}"}

        # Use circuit breaker
        try:
            result = self._circuit_breaker.call(
                self._monitor.inspect_call,
                tool_call,
                fallback=lambda tc: {
                    "allowed": False,
                    "risk_score": 100,
                    "findings": ["circuit_breaker_open_fail_closed"],
                    "call_id": "circuit-open",
                },
            )
        except Exception as exc:
            self._logger.error(f"inspect_call failed: {exc}")
            return 500, {"error": "Internal processing error"}

        # Shadow mode: log but always allow
        if self.config.shadow_mode:
            self._logger.info(
                "Shadow mode: findings logged but not blocking",
                extra={
                    "extra_fields": {
                        "trace_id": trace_id,
                        "original_allowed": result.get("allowed"),
                        "risk_score": result.get("risk_score"),
                        "findings": result.get("findings"),
                    }
                },
            )
            result["allowed"] = True
            result["shadow_mode"] = True

        # Alert on critical findings
        self._alerting.check_and_alert(result)

        # Add trace context to response
        result["trace_id"] = trace_id
        result["span_id"] = span_id

        return 200, result

    def _handle_inspect_output(
        self, body: bytes, trace_id: str, span_id: str
    ) -> Tuple[int, Dict[str, Any]]:
        """POST /v1/inspect_output - Forward to MCPSecurityMonitor."""
        try:
            payload = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return 400, {"error": f"Invalid JSON: {exc}"}

        tool_name = payload.get("tool_name", "")
        output = payload.get("output", {})

        # Use circuit breaker for graceful degradation
        try:
            result = self._output_circuit_breaker.call(
                self._monitor.inspect_output,
                tool_name,
                output,
                fallback=lambda tn, out: {
                    "allowed": False,
                    "risk_score": 100,
                    "findings": ["circuit_breaker_open_fail_closed"],
                    "tool_name": tn,
                },
            )
        except Exception as exc:
            self._logger.error(f"inspect_output failed: {exc}")
            return 500, {"error": "Internal processing error"}

        # Shadow mode
        if self.config.shadow_mode:
            self._logger.info(
                "Shadow mode: output findings logged but not blocking",
                extra={
                    "extra_fields": {
                        "trace_id": trace_id,
                        "original_allowed": result.get("allowed"),
                        "risk_score": result.get("risk_score"),
                        "findings": result.get("findings"),
                    }
                },
            )
            result["allowed"] = True
            result["shadow_mode"] = True

        # Alert on critical findings
        self._alerting.check_and_alert(result)

        # Add trace context
        result["trace_id"] = trace_id
        result["span_id"] = span_id

        return 200, result

    async def _send_response(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        body: Any,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Send an HTTP response."""
        status_messages = {
            200: "OK",
            400: "Bad Request",
            404: "Not Found",
            413: "Payload Too Large",
            429: "Too Many Requests",
            500: "Internal Server Error",
            503: "Service Unavailable",
        }
        status_msg = status_messages.get(status, "Unknown")

        if isinstance(body, str):
            body_bytes = body.encode("utf-8")
            content_type = "text/plain; charset=utf-8"
        else:
            body_bytes = json.dumps(body, default=str).encode("utf-8")
            content_type = "application/json"

        headers = [
            f"HTTP/1.1 {status} {status_msg}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body_bytes)}",
            "Connection: close",
        ]
        if extra_headers:
            for key, value in extra_headers.items():
                headers.append(f"{key}: {value}")

        response = "\r\n".join(headers) + "\r\n\r\n"
        writer.write(response.encode("utf-8") + body_bytes)
        await writer.drain()


def run_server(config: Optional[Config] = None) -> None:
    """Entry point to run the production server."""
    server = ProductionServer(config=config)
    asyncio.run(server.start())
