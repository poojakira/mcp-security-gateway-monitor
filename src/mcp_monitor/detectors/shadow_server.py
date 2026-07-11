"""Shadow MCP server detection.

Flags tool calls targeting unregistered or untrusted MCP servers, preventing
lateral movement via rogue tool endpoints that were never approved by the
operator.
"""

from __future__ import annotations

import time
from typing import Any


class ShadowServerDetector:
    """Detects tool calls to unexpected/unregistered MCP servers."""

    def __init__(self, allowed_servers: set[str]) -> None:
        self._allowed: set[str] = set(allowed_servers)
        # server_id -> {capabilities, registered_at, call_count}
        self._registry: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_server(
        self, server_id: str, capabilities: list[str]
    ) -> None:
        """Register a server as known/trusted with its declared capabilities."""
        self._allowed.add(server_id)
        self._registry[server_id] = {
            "capabilities": capabilities,
            "registered_at": time.time(),
            "call_count": 0,
        }

    def detect(self, tool_call: dict[str, Any]) -> tuple[bool, str]:
        """Determine whether a tool call targets an unregistered server.

        Parameters
        ----------
        tool_call:
            Must contain a ``"server_id"`` field.

        Returns
        -------
        tuple of (is_shadow: bool, reason: str)
        """
        server_id = tool_call.get("server_id")
        if server_id is None:
            return (True, "tool_call missing server_id field")

        # An unhashable server_id (list/dict/etc.) can't be a legitimate
        # server identifier; treat it as shadow instead of crashing on the
        # set membership test.
        try:
            is_allowed = server_id in self._allowed
        except TypeError:
            return (True, "server_id is not a valid (hashable) identifier")

        if not is_allowed:
            return (True, f"server '{server_id}' is not registered")

        # Track usage
        if server_id in self._registry:
            self._registry[server_id]["call_count"] += 1

        # Check capability mismatch
        tool_name = tool_call.get("name", "")
        # Fail gracefully when the tool name is a non-string (or missing).
        if not isinstance(tool_name, str):
            tool_name = str(tool_name) if tool_name is not None else ""
        capability_prefix = tool_name.split(".")[0] if "." in tool_name else ""
        if (
            capability_prefix
            and server_id in self._registry
            and self._registry[server_id]["capabilities"]
        ):
            caps = self._registry[server_id]["capabilities"]
            if capability_prefix not in caps and tool_name not in caps:
                return (
                    True,
                    f"server '{server_id}' not registered for capability '{capability_prefix}'",
                )

        return (False, "")

    def score_server_trust(self, server_id: str) -> int:
        """Return a trust score 0-100 for a given server.

        Scoring:
        - Not in allowed list: 0
        - In allowed list but not registered with capabilities: 30
        - Registered with capabilities and history: 50-100 based on usage
        """
        if server_id not in self._allowed:
            return 0

        if server_id not in self._registry:
            return 30

        info = self._registry[server_id]
        # Base trust for registered servers
        base = 50
        # Bonus for usage history (up to 50 more)
        usage_bonus = min(info["call_count"] * 5, 50)
        return min(base + usage_bonus, 100)

    @property
    def allowed_servers(self) -> set[str]:
        """Return current set of allowed server IDs."""
        return set(self._allowed)

    @property
    def registered_servers(self) -> dict[str, dict[str, Any]]:
        """Return registry info (read-only copy)."""
        return dict(self._registry)
