"""Configuration via environment variables (12-factor app).

All settings are read from os.environ with sensible defaults.
"""

from __future__ import annotations

import os
from typing import Optional, Set


class Config:
    """Production configuration read from environment variables."""

    def __init__(self) -> None:
        self.listen_port: int = int(os.environ.get("MCP_LISTEN_PORT", "8080"))
        self.shadow_mode: bool = os.environ.get("MCP_SHADOW_MODE", "false").lower() in (
            "true",
            "1",
            "yes",
        )
        self.webhook_url: Optional[str] = os.environ.get("MCP_WEBHOOK_URL")
        self.rate_limit_rpm: int = int(os.environ.get("MCP_RATE_LIMIT_RPM", "1000"))
        self.circuit_breaker_threshold: int = int(
            os.environ.get("MCP_CIRCUIT_BREAKER_THRESHOLD", "5")
        )
        self.circuit_breaker_timeout: float = float(
            os.environ.get("MCP_CIRCUIT_BREAKER_TIMEOUT", "30")
        )
        self.log_level: str = os.environ.get("MCP_LOG_LEVEL", "INFO").upper()
        self.allowed_servers: Set[str] = self._parse_allowed_servers(
            os.environ.get("MCP_ALLOWED_SERVERS", "")
        )
        self.max_payload_kb: float = float(os.environ.get("MCP_MAX_PAYLOAD_KB", "100"))
        self.wal_path: Optional[str] = os.environ.get("MCP_WAL_PATH")
        self.audit_path: Optional[str] = os.environ.get("MCP_AUDIT_PATH")
        self.api_key: Optional[str] = os.environ.get("MCP_API_KEY")
        self.allow_anonymous: bool = os.environ.get(
            "MCP_ALLOW_ANONYMOUS", "false"
        ).lower() in ("true", "1", "yes")

    @staticmethod
    def _parse_allowed_servers(value: str) -> Set[str]:
        """Parse comma-separated server list."""
        if not value.strip():
            return set()
        return {s.strip() for s in value.split(",") if s.strip()}

    def __repr__(self) -> str:
        return (
            f"Config(listen_port={self.listen_port}, "
            f"shadow_mode={self.shadow_mode}, "
            f"rate_limit_rpm={self.rate_limit_rpm}, "
            f"log_level={self.log_level})"
        )
