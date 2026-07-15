"""Comprehensive tests for production infrastructure modules.

Tests cover: config, JSON logging, circuit breaker, rate limiter,
alerting, metrics, tracing, shadow mode, API endpoints, and shutdown.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from mcp_monitor.production.config import Config
from mcp_monitor.production.logging import JSONFormatter, get_logger
from mcp_monitor.production.circuit_breaker import (
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
)
from mcp_monitor.production.rate_limiter import RateLimiter
from mcp_monitor.production.alerting import AlertingHook
from mcp_monitor.production.metrics import MetricsCollector
from mcp_monitor.production.tracing import Tracer
from mcp_monitor.production.shutdown import GracefulShutdown
from mcp_monitor.production.server import ProductionServer


# ============================================================
# Config Tests
# ============================================================


class TestConfig:
    """Tests for Config class."""

    def test_defaults(self):
        """Config uses sensible defaults when no env vars set."""
        with patch.dict(os.environ, {}, clear=True):
            # Clear any MCP_ vars that might be set
            env_copy = {k: v for k, v in os.environ.items() if not k.startswith("MCP_")}
            with patch.dict(os.environ, env_copy, clear=True):
                cfg = Config()
                assert cfg.listen_port == 8080
                assert cfg.shadow_mode is False
                assert cfg.webhook_url is None
                assert cfg.rate_limit_rpm == 1000
                assert cfg.circuit_breaker_threshold == 5
                assert cfg.circuit_breaker_timeout == 30.0
                assert cfg.log_level == "INFO"
                assert cfg.allowed_servers == set()
                assert cfg.max_payload_kb == 100.0
                assert cfg.wal_path is None
                assert cfg.audit_path is None

    def test_from_env(self):
        """Config reads values from environment variables."""
        env = {
            "MCP_LISTEN_PORT": "9090",
            "MCP_SHADOW_MODE": "true",
            "MCP_WEBHOOK_URL": "https://hooks.slack.com/test",
            "MCP_RATE_LIMIT_RPM": "500",
            "MCP_CIRCUIT_BREAKER_THRESHOLD": "3",
            "MCP_CIRCUIT_BREAKER_TIMEOUT": "60",
            "MCP_LOG_LEVEL": "DEBUG",
            "MCP_ALLOWED_SERVERS": "server1,server2,server3",
            "MCP_MAX_PAYLOAD_KB": "200",
            "MCP_WAL_PATH": "/tmp/test.wal",
            "MCP_AUDIT_PATH": "/tmp/test.audit",
        }
        with patch.dict(os.environ, env):
            cfg = Config()
            assert cfg.listen_port == 9090
            assert cfg.shadow_mode is True
            assert cfg.webhook_url == "https://hooks.slack.com/test"
            assert cfg.rate_limit_rpm == 500
            assert cfg.circuit_breaker_threshold == 3
            assert cfg.circuit_breaker_timeout == 60.0
            assert cfg.log_level == "DEBUG"
            assert cfg.allowed_servers == {"server1", "server2", "server3"}
            assert cfg.max_payload_kb == 200.0
            assert cfg.wal_path == "/tmp/test.wal"
            assert cfg.audit_path == "/tmp/test.audit"

    def test_shadow_mode_variants(self):
        """Shadow mode accepts multiple truthy values."""
        for val in ("true", "True", "1", "yes"):
            with patch.dict(os.environ, {"MCP_SHADOW_MODE": val}):
                cfg = Config()
                assert cfg.shadow_mode is True

        for val in ("false", "0", "no", ""):
            with patch.dict(os.environ, {"MCP_SHADOW_MODE": val}):
                cfg = Config()
                assert cfg.shadow_mode is False

    def test_allowed_servers_empty(self):
        """Empty MCP_ALLOWED_SERVERS gives empty set."""
        with patch.dict(os.environ, {"MCP_ALLOWED_SERVERS": ""}):
            cfg = Config()
            assert cfg.allowed_servers == set()

    def test_repr(self):
        """Config has a useful repr."""
        env = {"MCP_LISTEN_PORT": "8080", "MCP_SHADOW_MODE": "false"}
        with patch.dict(os.environ, env, clear=False):
            cfg = Config()
            r = repr(cfg)
            assert "Config(" in r
            assert "listen_port=" in r


# ============================================================
# Logging Tests
# ============================================================


class TestJSONLogging:
    """Tests for structured JSON logging."""

    def test_json_format(self):
        """Log output is valid JSON with required fields."""
        formatter = JSONFormatter(service="test-service")
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test message",
            args=None,
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["level"] == "INFO"
        assert data["message"] == "Test message"
        assert data["service"] == "test-service"
        assert "timestamp" in data
        assert data["timestamp"].endswith("Z")

    def test_trace_context_in_log(self):
        """Trace context is included when set."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Traced",
            args=None,
            exc_info=None,
        )
        record.trace_id = "abc123"
        record.span_id = "def456"
        output = formatter.format(record)
        data = json.loads(output)
        assert data["trace_id"] == "abc123"
        assert data["span_id"] == "def456"

    def test_extra_fields(self):
        """Extra fields are included in log output."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="test.py",
            lineno=1,
            msg="Extra test",
            args=None,
            exc_info=None,
        )
        record.extra_fields = {"request_id": "req-1", "latency_ms": 42}
        output = formatter.format(record)
        data = json.loads(output)
        assert data["request_id"] == "req-1"
        assert data["latency_ms"] == 42

    def test_get_logger(self):
        """get_logger creates a properly configured logger."""
        logger = get_logger("test.production.logging")
        assert logger.level == logging.INFO
        assert len(logger.handlers) >= 1
        assert isinstance(logger.handlers[0].formatter, JSONFormatter)

    def test_exception_in_log(self):
        """Exception info is included in log output."""
        formatter = JSONFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys

            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="Error occurred",
            args=None,
            exc_info=exc_info,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert "exception" in data
        assert "ValueError" in data["exception"]


# ============================================================
# Circuit Breaker Tests
# ============================================================


class TestCircuitBreaker:
    """Tests for circuit breaker state transitions."""

    def test_starts_closed(self):
        """Circuit breaker starts in closed state."""
        cb = CircuitBreaker("test", failure_threshold=3)
        assert cb.state == CircuitState.CLOSED

    def test_stays_closed_on_success(self):
        """Circuit stays closed on successful calls."""
        cb = CircuitBreaker("test", failure_threshold=3)
        result = cb.call(lambda: "ok")
        assert result == "ok"
        assert cb.state == CircuitState.CLOSED

    def test_opens_after_threshold_failures(self):
        """Circuit opens after N consecutive failures."""
        cb = CircuitBreaker("test", failure_threshold=3)

        def fail():
            raise RuntimeError("fail")

        for _ in range(3):
            with pytest.raises(RuntimeError):
                cb.call(fail)

        assert cb.state == CircuitState.OPEN

    def test_open_uses_fallback(self):
        """Open circuit uses fallback when provided."""
        cb = CircuitBreaker("test", failure_threshold=2)

        def fail():
            raise RuntimeError("fail")

        # Open the circuit
        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.call(fail)

        assert cb.state == CircuitState.OPEN

        # Now call with fallback
        result = cb.call(fail, fallback=lambda: "fallback_value")
        assert result == "fallback_value"

    def test_open_raises_without_fallback(self):
        """Open circuit raises CircuitOpenError without fallback."""
        cb = CircuitBreaker("test", failure_threshold=2)

        def fail():
            raise RuntimeError("fail")

        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.call(fail)

        with pytest.raises(CircuitOpenError):
            cb.call(fail)

    def test_half_open_after_timeout(self):
        """Circuit transitions to half_open after recovery timeout."""
        cb = CircuitBreaker("test", failure_threshold=2, recovery_timeout=0.1)

        def fail():
            raise RuntimeError("fail")

        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.call(fail)

        assert cb.state == CircuitState.OPEN
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_success_closes(self):
        """Successful call in half_open state closes circuit."""
        cb = CircuitBreaker("test", failure_threshold=2, recovery_timeout=0.1)

        def fail():
            raise RuntimeError("fail")

        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.call(fail)

        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN

        result = cb.call(lambda: "recovered")
        assert result == "recovered"
        assert cb.state == CircuitState.CLOSED

    def test_reset(self):
        """Manual reset restores closed state."""
        cb = CircuitBreaker("test", failure_threshold=2)

        def fail():
            raise RuntimeError("fail")

        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.call(fail)

        assert cb.state == CircuitState.OPEN
        cb.reset()
        assert cb.state == CircuitState.CLOSED


# ============================================================
# Rate Limiter Tests
# ============================================================


class TestRateLimiter:
    """Tests for token bucket rate limiter."""

    def test_allows_within_limit(self):
        """Requests within rate limit are allowed."""
        rl = RateLimiter(tokens_per_minute=60)
        assert rl.allow() is True

    def test_denies_when_exhausted(self):
        """Requests are denied when tokens exhausted."""
        rl = RateLimiter(tokens_per_minute=5, burst_size=5)
        for _ in range(5):
            assert rl.allow() is True
        assert rl.allow() is False

    def test_refills_over_time(self):
        """Tokens refill based on elapsed time."""
        rl = RateLimiter(tokens_per_minute=6000, burst_size=5)
        # Exhaust all tokens
        for _ in range(5):
            rl.allow()
        assert rl.allow() is False

        # Wait for refill (6000/min = 100/sec, so 0.05s gives 5 tokens)
        time.sleep(0.06)
        assert rl.allow() is True

    def test_remaining_tokens(self):
        """remaining_tokens reports current count."""
        rl = RateLimiter(tokens_per_minute=100, burst_size=10)
        assert rl.remaining_tokens() == 10.0
        rl.allow()
        remaining = rl.remaining_tokens()
        assert remaining < 10.0

    def test_reset(self):
        """Reset restores full capacity."""
        rl = RateLimiter(tokens_per_minute=10, burst_size=10)
        for _ in range(10):
            rl.allow()
        assert rl.allow() is False
        rl.reset()
        assert rl.allow() is True

    def test_burst_size(self):
        """Custom burst size limits maximum tokens."""
        rl = RateLimiter(tokens_per_minute=1000, burst_size=3)
        for _ in range(3):
            assert rl.allow() is True
        assert rl.allow() is False


# ============================================================
# Alerting Tests
# ============================================================


class TestAlerting:
    """Tests for webhook alerting."""

    def test_no_alert_below_threshold(self):
        """No alert fired when risk_score below threshold."""
        hook = AlertingHook(
            webhook_url="https://hooks.example.com/test",
            risk_threshold=80,
        )
        result = {"risk_score": 50, "findings": ["pii:email:1"], "call_id": "c1"}
        assert hook.check_and_alert(result) is False

    def test_no_alert_without_webhook_url(self):
        """No alert fired when webhook_url is None."""
        hook = AlertingHook(webhook_url=None, risk_threshold=80)
        result = {"risk_score": 90, "findings": ["critical"], "call_id": "c1"}
        assert hook.check_and_alert(result) is False

    @patch("mcp_monitor.production.alerting.urllib.request.urlopen")
    def test_alert_fires_above_threshold(self, mock_urlopen):
        """Alert fires when risk_score >= threshold."""
        hook = AlertingHook(
            webhook_url="https://hooks.example.com/test",
            risk_threshold=80,
            cooldown_seconds=0,
        )
        result = {
            "risk_score": 90,
            "findings": ["shadow_server:unknown"],
            "call_id": "c1",
        }
        fired = hook.check_and_alert(result)
        assert fired is True
        # Wait for background thread
        time.sleep(0.2)
        mock_urlopen.assert_called_once()

    @patch("mcp_monitor.production.alerting.urllib.request.urlopen")
    def test_cooldown_prevents_duplicate(self, mock_urlopen):
        """Cooldown prevents duplicate alerts for same findings."""
        hook = AlertingHook(
            webhook_url="https://hooks.example.com/test",
            risk_threshold=80,
            cooldown_seconds=10,
        )
        result = {"risk_score": 95, "findings": ["critical"], "call_id": "c1"}
        assert hook.check_and_alert(result) is True
        # Second alert same findings within cooldown
        assert hook.check_and_alert(result) is False

    @patch("mcp_monitor.production.alerting.urllib.request.urlopen")
    def test_webhook_payload_format(self, mock_urlopen):
        """Webhook payload is Slack-compatible JSON."""
        hook = AlertingHook(
            webhook_url="https://hooks.example.com/test",
            risk_threshold=50,
            cooldown_seconds=0,
        )
        result = {
            "risk_score": 85,
            "findings": ["exfiltration:large_payload"],
            "call_id": "test-id",
        }
        hook.check_and_alert(result)
        time.sleep(0.2)

        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        payload = json.loads(req.data.decode("utf-8"))
        assert "text" in payload
        assert "CRITICAL" in payload["text"]
        assert payload["risk_score"] == 85
        assert payload["severity"] == "critical"


# ============================================================
# Metrics Tests
# ============================================================


class TestMetrics:
    """Tests for Prometheus metrics collection."""

    def test_request_counter(self):
        """Request counter increments correctly."""
        mc = MetricsCollector()
        mc.inc_request("/v1/inspect_call")
        mc.inc_request("/v1/inspect_call")
        mc.inc_request("/v1/health")
        output = mc.expose()
        assert "mcp_request_total 3" in output

    def test_error_counter(self):
        """Error counter increments."""
        mc = MetricsCollector()
        mc.inc_error()
        mc.inc_error()
        output = mc.expose()
        assert "mcp_error_total 2" in output

    def test_active_requests_gauge(self):
        """Active requests gauge tracks correctly."""
        mc = MetricsCollector()
        mc.inc_active()
        mc.inc_active()
        assert mc.get_active_requests() == 2
        mc.dec_active()
        assert mc.get_active_requests() == 1
        output = mc.expose()
        assert "mcp_active_requests 1" in output

    def test_duration_histogram(self):
        """Duration histogram records observations."""
        mc = MetricsCollector()
        mc.observe_duration(0.05)
        mc.observe_duration(0.5)
        mc.observe_duration(2.0)
        output = mc.expose()
        assert "mcp_request_duration_seconds_count 3" in output
        assert "mcp_request_duration_seconds_sum" in output
        assert "le=" in output

    def test_circuit_breaker_state(self):
        """Circuit breaker state is exposed."""
        mc = MetricsCollector()
        mc.set_circuit_state("layer_3", "closed")
        mc.set_circuit_state("layer_5", "open")
        output = mc.expose()
        assert 'mcp_circuit_breaker_state{layer="layer_3"} 0' in output
        assert 'mcp_circuit_breaker_state{layer="layer_5"} 1' in output

    def test_prometheus_format(self):
        """Output follows Prometheus text exposition format."""
        mc = MetricsCollector()
        mc.inc_request()
        output = mc.expose()
        assert "# HELP" in output
        assert "# TYPE" in output
        assert "counter" in output
        assert "gauge" in output
        assert "histogram" in output


# ============================================================
# Tracing Tests
# ============================================================


class TestTracing:
    """Tests for distributed tracing."""

    def test_trace_id_format(self):
        """Trace ID is 32 hex characters (128 bits)."""
        tracer = Tracer()
        trace_id = tracer.start_trace()
        assert len(trace_id) == 32
        int(trace_id, 16)  # Should be valid hex

    def test_span_creation(self):
        """Spans are created with proper attributes."""
        tracer = Tracer(service_name="test-service")
        trace_id = tracer.start_trace()
        span = tracer.start_span("test_op", trace_id)
        assert span.trace_id == trace_id
        assert len(span.span_id) == 16
        assert span.name == "test_op"
        assert span.attributes["service.name"] == "test-service"

    def test_span_end(self):
        """Ending a span records end time and duration."""
        tracer = Tracer()
        trace_id = tracer.start_trace()
        span = tracer.start_span("op", trace_id)
        time.sleep(0.01)
        tracer.end_span(span)
        assert span.end_time is not None
        assert span.duration_ms > 0

    def test_parent_span(self):
        """Child spans reference parent span ID."""
        tracer = Tracer()
        trace_id = tracer.start_trace()
        parent = tracer.start_span("parent_op", trace_id)
        child = tracer.start_span("child_op", trace_id, parent.span_id)
        assert child.parent_span_id == parent.span_id

    def test_traceparent_creation(self):
        """W3C traceparent header is correctly formatted."""
        tp = Tracer.create_traceparent(
            "4bf92f3577b34da6a3ce929d0e0e4736",
            "00f067aa0ba902b7",
            sampled=True,
        )
        assert tp == "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

    def test_traceparent_parsing(self):
        """W3C traceparent header is correctly parsed."""
        result = Tracer.parse_traceparent(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        )
        assert result is not None
        assert result["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
        assert result["parent_span_id"] == "00f067aa0ba902b7"
        assert result["flags"] == "01"

    def test_traceparent_invalid(self):
        """Invalid traceparent returns None."""
        assert Tracer.parse_traceparent("") is None
        assert Tracer.parse_traceparent("invalid") is None
        assert Tracer.parse_traceparent("00-short-id-01") is None

    def test_span_to_json(self):
        """Span serializes to valid JSON."""
        tracer = Tracer()
        trace_id = tracer.start_trace()
        span = tracer.start_span("test", trace_id)
        span.set_attribute("http.method", "POST")
        span.end()
        data = json.loads(span.to_json())
        assert data["trace_id"] == trace_id
        assert data["name"] == "test"
        assert "duration_ms" in data

    def test_completed_spans(self):
        """get_completed_spans returns only ended spans."""
        tracer = Tracer()
        trace_id = tracer.start_trace()
        s1 = tracer.start_span("s1", trace_id)
        tracer.start_span("s2", trace_id)
        tracer.end_span(s1)
        completed = tracer.get_completed_spans()
        assert len(completed) == 1
        assert completed[0].name == "s1"


# ============================================================
# Shutdown Tests
# ============================================================


class TestGracefulShutdown:
    """Tests for graceful shutdown handling."""

    def test_initial_state(self):
        """Shutdown starts in non-shutting-down state."""
        gs = GracefulShutdown()
        assert gs.is_shutting_down is False
        assert gs.active_requests == 0

    def test_request_tracking(self):
        """Active requests are tracked correctly."""
        gs = GracefulShutdown()
        gs.request_started()
        gs.request_started()
        assert gs.active_requests == 2
        gs.request_finished()
        assert gs.active_requests == 1

    def test_shutdown_flag(self):
        """execute_shutdown sets the shutdown flag."""
        gs = GracefulShutdown(drain_timeout=0.1)
        gs.execute_shutdown()
        assert gs.is_shutting_down is True

    def test_drain_with_no_requests(self):
        """Drain completes immediately when no requests."""
        gs = GracefulShutdown(drain_timeout=1.0)
        assert gs.wait_for_drain() is True

    def test_drain_waits_for_requests(self):
        """Drain waits for in-flight requests to complete."""
        gs = GracefulShutdown(drain_timeout=2.0)
        gs.request_started()

        def finish_later():
            time.sleep(0.1)
            gs.request_finished()

        t = threading.Thread(target=finish_later)
        t.start()
        assert gs.wait_for_drain() is True
        t.join()

    def test_drain_timeout(self):
        """Drain times out if requests don't complete."""
        gs = GracefulShutdown(drain_timeout=0.1)
        gs.request_started()
        assert gs.wait_for_drain() is False
        gs.request_finished()

    def test_on_shutdown_callback(self):
        """Shutdown callback is invoked."""
        callback = MagicMock()
        gs = GracefulShutdown(drain_timeout=0.1, on_shutdown=callback)
        gs.execute_shutdown()
        callback.assert_called_once()


# ============================================================
# Server Integration Tests
# ============================================================


class TestProductionServer:
    """Integration tests for the production HTTP server."""

    def _make_server(self, **env_overrides):
        """Create a server with test configuration."""
        env = {
            "MCP_LISTEN_PORT": "0",
            "MCP_SHADOW_MODE": "false",
            "MCP_RATE_LIMIT_RPM": "1000",
            "MCP_LOG_LEVEL": "WARNING",
        }
        env.update(env_overrides)
        with patch.dict(os.environ, env):
            config = Config()
        return ProductionServer(config=config)

    def test_health_endpoint(self):
        """GET /v1/health returns healthy status."""
        server = self._make_server()
        status, body = server._handle_health()
        assert status == 200
        assert body["status"] == "healthy"
        assert "timestamp" in body

    def test_ready_endpoint(self):
        """GET /v1/ready returns ready status."""
        server = self._make_server()
        status, body = server._handle_ready()
        assert status == 200
        assert body["status"] == "ready"

    def test_metrics_endpoint(self):
        """GET /v1/metrics returns Prometheus format."""
        server = self._make_server()
        status, body = server._handle_metrics()
        assert status == 200
        assert "mcp_request_total" in body
        assert "# TYPE" in body

    def test_inspect_call_endpoint(self):
        """POST /v1/inspect_call processes tool calls."""
        server = self._make_server(MCP_ALLOWED_SERVERS="test-server")
        tool_call = {
            "name": "read_file",
            "server_id": "test-server",
            "arguments": {"path": "/etc/passwd"},
        }
        body = json.dumps(tool_call).encode("utf-8")
        status, result = server._handle_inspect_call(body, "trace123", "span456")
        assert status == 200
        assert "allowed" in result
        assert "risk_score" in result
        assert "findings" in result
        assert result["trace_id"] == "trace123"

    def test_inspect_call_invalid_json(self):
        """POST /v1/inspect_call rejects invalid JSON."""
        server = self._make_server()
        status, result = server._handle_inspect_call(b"not json", "t1", "s1")
        assert status == 400
        assert "error" in result

    def test_inspect_output_endpoint(self):
        """POST /v1/inspect_output processes tool outputs."""
        server = self._make_server(MCP_ALLOWED_SERVERS="test-server")
        payload = {
            "tool_name": "read_file",
            "output": {"content": "hello world"},
        }
        body = json.dumps(payload).encode("utf-8")
        status, result = server._handle_inspect_output(body, "trace1", "span1")
        assert status == 200
        assert "allowed" in result
        assert "risk_score" in result

    def test_shadow_mode(self):
        """Shadow mode always returns allowed=True."""
        server = self._make_server(MCP_SHADOW_MODE="true")
        tool_call = {
            "name": "execute_command",
            "server_id": "unknown-server",
            "arguments": {"command": "rm -rf /"},
        }
        body = json.dumps(tool_call).encode("utf-8")
        status, result = server._handle_inspect_call(body, "t1", "s1")
        assert status == 200
        assert result["allowed"] is True
        assert result.get("shadow_mode") is True

    def test_inspect_route_requires_api_key(self):
        """Protected inspect routes fail closed when MCP_API_KEY is absent."""
        server = self._make_server()
        body = json.dumps(
            {"name": "read_file", "server_id": "trusted", "arguments": {}}
        ).encode("utf-8")
        loop = asyncio.new_event_loop()
        try:
            status, result = loop.run_until_complete(
                server._route("POST", "/v1/inspect_call", body, {}, "trace", "span")
            )
            assert status == 503
            assert result["error"] == "MCP_API_KEY is not configured"
        finally:
            loop.close()

    def test_inspect_route_rejects_bad_api_key(self):
        """Protected inspect routes reject missing or wrong API keys."""
        server = self._make_server(MCP_API_KEY="secret")
        body = json.dumps(
            {"name": "read_file", "server_id": "trusted", "arguments": {}}
        ).encode("utf-8")
        loop = asyncio.new_event_loop()
        try:
            status, result = loop.run_until_complete(
                server._route(
                    "POST",
                    "/v1/inspect_call",
                    body,
                    {"x-api-key": "wrong"},
                    "trace",
                    "span",
                )
            )
            assert status == 401
            assert result["error"] == "Unauthorized"
        finally:
            loop.close()

    def test_inspect_route_writes_wal_before_processing(self, tmp_path):
        """Protected inspect routes write request metadata to WAL before monitor processing."""
        wal_path = tmp_path / "server.wal"
        server = self._make_server(MCP_API_KEY="secret", MCP_WAL_PATH=str(wal_path))
        body = json.dumps(
            {"name": "read_file", "server_id": "trusted", "arguments": {}}
        ).encode("utf-8")
        loop = asyncio.new_event_loop()
        try:
            status, result = loop.run_until_complete(
                server._route(
                    "POST",
                    "/v1/inspect_call",
                    body,
                    {"x-api-key": "secret"},
                    "trace",
                    "span",
                )
            )
            assert status == 200
            assert "allowed" in result
            recovered = server._wal.recover()
            assert len(recovered) == 1
            assert recovered[0].event_type == "production_request_received"
            assert recovered[0].data["path"] == "/v1/inspect_call"
        finally:
            loop.close()

    def test_inspect_call_circuit_breaker_fails_closed(self):
        """Circuit breaker fallback blocks instead of allowing risky traffic."""
        server = self._make_server(MCP_CIRCUIT_BREAKER_THRESHOLD="1")
        server._monitor.inspect_call = lambda tc: (_ for _ in ()).throw(
            RuntimeError("boom")
        )
        body = json.dumps(
            {"name": "send_email", "server_id": "trusted", "arguments": {}}
        ).encode("utf-8")
        status, result = server._handle_inspect_call(body, "trace", "span")
        assert status == 200
        assert result["allowed"] is False
        assert result["risk_score"] == 100
        assert "circuit_breaker_open_fail_closed" in result["findings"]

    def test_routing_404(self):
        """Unknown paths return 404."""
        server = self._make_server()
        loop = asyncio.new_event_loop()
        try:
            status, body = loop.run_until_complete(
                server._route("GET", "/unknown", b"", {}, "t", "s")
            )
            assert status == 404
        finally:
            loop.close()

    def test_routing_health(self):
        """Health route works through _route method."""
        server = self._make_server()
        loop = asyncio.new_event_loop()
        try:
            status, body = loop.run_until_complete(
                server._route("GET", "/v1/health", b"", {}, "t", "s")
            )
            assert status == 200
            assert body["status"] == "healthy"
        finally:
            loop.close()
