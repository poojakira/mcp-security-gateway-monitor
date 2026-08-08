"""JSON-RPC 2.0 adapter for MCP (Model Context Protocol) messages.

The MCP protocol uses JSON-RPC 2.0 as its transport format. This module:
  - Parses JSON-RPC 2.0 messages (single and batch)
  - Extracts tool name and arguments from tools/call requests
  - Converts to the internal format expected by detectors
  - Handles notifications (no id field) and error responses
  - Validates JSON-RPC 2.0 structure

Reference: https://spec.modelcontextprotocol.io/
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


class JSONRPCError(Exception):
    """Raised when a JSON-RPC message is malformed or invalid."""

    def __init__(self, message: str, code: int = -32600) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class ParsedToolCall:
    """Internal representation of a parsed MCP tool call.

    Attributes
    ----------
    name : str
        The tool name from params.name.
    arguments : dict[str, Any]
        The tool arguments from params.arguments.
    request_id : int | str | None
        The JSON-RPC request id. None for notifications.
    method : str
        The JSON-RPC method (e.g., "tools/call", "tools/list").
    is_notification : bool
        True if the message has no id field (JSON-RPC notification).
    raw_message : dict[str, Any]
        The original JSON-RPC message for reference.
    """

    name: str
    arguments: dict[str, Any]
    request_id: int | str | None = None
    method: str = "tools/call"
    is_notification: bool = False
    raw_message: dict[str, Any] = field(default_factory=dict)

    def to_internal_format(self) -> dict[str, Any]:
        """Convert to the internal tool_call format expected by detectors.

        Returns dict with ``name`` and ``arguments`` keys matching what
        PromptInjectionDetector.detect() expects.
        """
        return {
            "name": self.name,
            "arguments": self.arguments,
        }


class MCPJSONRPCAdapter:
    """Adapter that parses MCP JSON-RPC 2.0 messages and extracts tool calls.

    Supports:
      - Single JSON-RPC requests (tools/call, tools/list, etc.)
      - Batch requests (array of JSON-RPC messages)
      - Notifications (messages without an id field)
      - Response messages (result or error)

    Usage
    -----
    >>> adapter = MCPJSONRPCAdapter()
    >>> parsed = adapter.parse_message(raw_json_str)
    >>> for tool_call in parsed:
    ...     internal = tool_call.to_internal_format()
    ...     result = detector.detect(internal)
    """

    # Methods that carry tool call payloads we should inspect
    TOOL_CALL_METHODS: set[str] = {"tools/call"}

    # All known MCP methods
    KNOWN_METHODS: set[str] = {
        "tools/call",
        "tools/list",
        "resources/read",
        "resources/list",
        "prompts/get",
        "prompts/list",
        "completion/complete",
        "logging/setLevel",
        "initialize",
        "ping",
        "notifications/initialized",
        "notifications/cancelled",
        "notifications/progress",
        "notifications/resources/updated",
        "notifications/resources/list_changed",
        "notifications/tools/list_changed",
        "notifications/prompts/list_changed",
    }

    def parse_message(self, raw: str | bytes | dict | list) -> list[ParsedToolCall]:
        """Parse a raw MCP JSON-RPC 2.0 message into tool calls.

        Parameters
        ----------
        raw : str | bytes | dict | list
            Raw JSON string, bytes, or already-parsed dict/list.

        Returns
        -------
        list[ParsedToolCall]
            List of parsed tool calls. Empty if message is not a tools/call.

        Raises
        ------
        JSONRPCError
            If the message is not valid JSON-RPC 2.0.
        """
        # Parse JSON if needed
        if isinstance(raw, (str, bytes)):
            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, ValueError) as e:
                raise JSONRPCError(f"Invalid JSON: {e}", code=-32700) from e
        else:
            data = raw

        # Handle batch requests (array of messages)
        if isinstance(data, list):
            return self._parse_batch(data)

        # Single message
        if isinstance(data, dict):
            result = self._parse_single(data)
            return [result] if result is not None else []

        raise JSONRPCError("JSON-RPC message must be object or array", code=-32600)

    def parse_and_extract(self, raw: str | bytes | dict | list) -> list[dict[str, Any]]:
        """Parse message and return internal-format dicts ready for detectors.

        Convenience method that combines parse_message + to_internal_format.

        Returns
        -------
        list[dict[str, Any]]
            List of dicts with ``name`` and ``arguments`` keys.
        """
        parsed = self.parse_message(raw)
        return [p.to_internal_format() for p in parsed]

    def is_tool_call_request(self, raw: str | bytes | dict | list) -> bool:
        """Check if a message contains any tools/call requests."""
        try:
            parsed = self.parse_message(raw)
            return len(parsed) > 0
        except JSONRPCError:
            return False

    # ------------------------------------------------------------------
    # Internal parsing
    # ------------------------------------------------------------------

    def _parse_batch(self, messages: list) -> list[ParsedToolCall]:
        """Parse a JSON-RPC batch (array of messages)."""
        if not messages:
            raise JSONRPCError("Empty batch request", code=-32600)

        results: list[ParsedToolCall] = []
        for msg in messages:
            if not isinstance(msg, dict):
                # Skip invalid entries in batch, don't fail entire batch
                continue
            parsed = self._parse_single(msg)
            if parsed is not None:
                results.append(parsed)
        return results

    def _parse_single(self, msg: dict[str, Any]) -> ParsedToolCall | None:
        """Parse a single JSON-RPC 2.0 message.

        Returns None if the message is not a tools/call request
        (e.g., it's a response, notification for non-tool method, etc.)
        """
        # Validate JSON-RPC 2.0 structure
        jsonrpc_version = msg.get("jsonrpc")
        if jsonrpc_version != "2.0":
            raise JSONRPCError(
                f"Invalid or missing jsonrpc version: {jsonrpc_version!r}",
                code=-32600,
            )

        # Check if this is a response (has result or error field, no method)
        if "result" in msg or "error" in msg:
            # Response message — not a tool call request to inspect
            return None

        # Must have a method for requests/notifications
        method = msg.get("method")
        if not isinstance(method, str):
            raise JSONRPCError(
                "Missing or invalid 'method' field in request",
                code=-32600,
            )

        # Determine if notification (no id field)
        is_notification = "id" not in msg
        request_id = msg.get("id")

        # Only process tools/call methods for security scanning
        if method not in self.TOOL_CALL_METHODS:
            # Return a ParsedToolCall with empty arguments for non-tool methods
            # so callers can still track what methods are being called
            if method.startswith("tools/") or method.startswith("notifications/"):
                return ParsedToolCall(
                    name="",
                    arguments={},
                    request_id=request_id,
                    method=method,
                    is_notification=is_notification,
                    raw_message=msg,
                )
            return None

        # Extract params
        params = msg.get("params", {})
        if not isinstance(params, dict):
            raise JSONRPCError(
                "tools/call 'params' must be an object",
                code=-32602,
            )

        # Extract tool name and arguments
        tool_name = params.get("name", "")
        if not isinstance(tool_name, str):
            raise JSONRPCError(
                "tools/call params.name must be a string",
                code=-32602,
            )

        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            raise JSONRPCError(
                "tools/call params.arguments must be an object",
                code=-32602,
            )

        return ParsedToolCall(
            name=tool_name,
            arguments=arguments,
            request_id=request_id,
            method=method,
            is_notification=is_notification,
            raw_message=msg,
        )
