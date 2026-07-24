"""Declarative security invariant enforcement for MCP tool calls.

WHY THIS EXISTS:
The MCP spec and the new 2026-07-28 revision both delegate ALL execution
safety to deployers. Forbes: "MCP alone does not standardize the execution
layer." Anthropic: "expected behavior." OpenAI: no response.

The result: there is NO declarative way to say "email tools must NEVER
have a BCC field" or "database tools must NEVER execute DROP statements."
Every deployer must hand-code these checks.

WHAT THIS MODULE DOES:
- Provides a declarative invariant language for MCP security policies
- Evaluates invariants against tool calls and outputs at runtime
- Supports field-presence, field-absence, value-range, regex-match rules
- Composable: AND/OR/NOT logic for complex policies
- Enforces what the protocol SHOULD have enforced from day one
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable


class InvariantType(Enum):
    """Types of security invariants."""
    FIELD_ABSENT = "field_absent"        # Field must NOT exist
    FIELD_PRESENT = "field_present"      # Field MUST exist
    VALUE_MATCHES = "value_matches"      # Field value matches regex
    VALUE_NOT_MATCHES = "value_not_matches"  # Field value must NOT match
    VALUE_IN_SET = "value_in_set"        # Field value in allowed set
    VALUE_NOT_IN_SET = "value_not_in_set"  # Field value NOT in blocked set
    MAX_LENGTH = "max_length"            # String field max length
    CUSTOM = "custom"                    # Custom predicate function


@dataclass
class Invariant:
    """A single security invariant (constraint) on tool calls."""

    name: str
    description: str
    invariant_type: InvariantType
    tool_pattern: str = ".*"  # Regex matching tool names this applies to
    field_path: str = ""      # Dot-notation path into arguments/output
    value: Any = None         # Expected value, regex pattern, set, or max length
    predicate: Callable[[dict], bool] | None = None  # For CUSTOM type
    severity: int = 80        # How critical is a violation (0-100)
    applies_to: str = "arguments"  # "arguments" or "output" or "both"


@dataclass
class InvariantViolation:
    """A detected invariant violation."""

    invariant_name: str
    description: str
    severity: int
    tool_name: str
    field_path: str
    actual_value: Any = None
    expected: str = ""


# Pre-built invariants for common MCP security policies
BUILTIN_INVARIANTS: list[Invariant] = [
    Invariant(
        name="no_bcc_in_email",
        description="Email tools must NEVER have a BCC field (Postmark attack prevention)",
        invariant_type=InvariantType.FIELD_ABSENT,
        tool_pattern=r"(email|mail|send|postmark|smtp|sendgrid)",
        field_path="bcc",
        severity=95,
        applies_to="both",
    ),
    Invariant(
        name="no_hidden_recipients",
        description="No hidden/blind recipients in any communication tool",
        invariant_type=InvariantType.FIELD_ABSENT,
        tool_pattern=r"(email|mail|send|message|chat)",
        field_path="hidden_recipients",
        severity=90,
        applies_to="both",
    ),
    Invariant(
        name="no_sql_drop",
        description="Database tools must not contain DROP statements",
        invariant_type=InvariantType.VALUE_NOT_MATCHES,
        tool_pattern=r"(db|database|sql|query|postgres|mysql)",
        field_path="query",
        value=r"(?i)\b(DROP|TRUNCATE|DELETE\s+FROM)\b",
        severity=95,
        applies_to="arguments",
    ),
    Invariant(
        name="no_raw_ip_urls",
        description="Tools must not use raw IP addresses as URLs",
        invariant_type=InvariantType.VALUE_NOT_MATCHES,
        tool_pattern=r".*",
        field_path="url",
        value=r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        severity=70,
        applies_to="both",
    ),
    Invariant(
        name="no_shell_execution",
        description="No shell command execution via tool arguments",
        invariant_type=InvariantType.VALUE_NOT_MATCHES,
        tool_pattern=r".*",
        field_path="command",
        value=r"(;|\||\$\(|`).*(rm|curl|wget|nc|bash|sh\s)",
        severity=95,
        applies_to="arguments",
    ),
]



class InvariantEnforcer:
    """Evaluates security invariants against MCP tool calls and outputs.

    This is the enforcement layer that the MCP protocol should have had.
    Instead of hoping deployers manually check everything, we provide
    declarative policies that are evaluated computationally.
    """

    def __init__(self, *, include_builtins: bool = True) -> None:
        self._invariants: list[Invariant] = []
        if include_builtins:
            self._invariants.extend(BUILTIN_INVARIANTS)

    def add_invariant(self, invariant: Invariant) -> None:
        """Add a custom invariant to the enforcer."""
        self._invariants.append(invariant)

    def add_invariants(self, invariants: list[Invariant]) -> None:
        """Add multiple invariants."""
        self._invariants.extend(invariants)

    def check_call(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> tuple[bool, list[InvariantViolation]]:
        """Check tool call arguments against all applicable invariants.

        Returns
        -------
        tuple of (all_passed: bool, violations: list[InvariantViolation])
        """
        violations: list[InvariantViolation] = []
        for inv in self._invariants:
            if inv.applies_to not in ("arguments", "both"):
                continue
            if not re.search(inv.tool_pattern, tool_name, re.IGNORECASE):
                continue
            violation = self._evaluate(inv, tool_name, arguments)
            if violation:
                violations.append(violation)
        return (len(violations) == 0, violations)

    def check_output(
        self, tool_name: str, output: dict[str, Any]
    ) -> tuple[bool, list[InvariantViolation]]:
        """Check tool output against all applicable invariants."""
        violations: list[InvariantViolation] = []
        for inv in self._invariants:
            if inv.applies_to not in ("output", "both"):
                continue
            if not re.search(inv.tool_pattern, tool_name, re.IGNORECASE):
                continue
            violation = self._evaluate(inv, tool_name, output)
            if violation:
                violations.append(violation)
        return (len(violations) == 0, violations)

    @property
    def invariants(self) -> list[Invariant]:
        return list(self._invariants)

    # ------------------------------------------------------------------
    # Evaluation engine
    # ------------------------------------------------------------------

    def _evaluate(
        self, inv: Invariant, tool_name: str, data: dict[str, Any]
    ) -> InvariantViolation | None:
        """Evaluate a single invariant against data."""

        if inv.invariant_type == InvariantType.CUSTOM:
            if inv.predicate and not inv.predicate(data):
                return InvariantViolation(
                    invariant_name=inv.name,
                    description=inv.description,
                    severity=inv.severity,
                    tool_name=tool_name,
                    field_path="<custom>",
                    expected="custom predicate to return True",
                )
            return None

        # Resolve field path (supports nested dot-notation)
        value = self._resolve_path(data, inv.field_path)
        field_exists = value is not _MISSING

        if inv.invariant_type == InvariantType.FIELD_ABSENT:
            if field_exists and value:  # Exists and is truthy
                return InvariantViolation(
                    invariant_name=inv.name,
                    description=inv.description,
                    severity=inv.severity,
                    tool_name=tool_name,
                    field_path=inv.field_path,
                    actual_value=value,
                    expected=f"field '{inv.field_path}' must not exist",
                )

        elif inv.invariant_type == InvariantType.FIELD_PRESENT:
            if not field_exists:
                return InvariantViolation(
                    invariant_name=inv.name,
                    description=inv.description,
                    severity=inv.severity,
                    tool_name=tool_name,
                    field_path=inv.field_path,
                    expected=f"field '{inv.field_path}' must exist",
                )

        elif inv.invariant_type == InvariantType.VALUE_MATCHES:
            if field_exists and isinstance(value, str):
                if not re.search(str(inv.value), value):
                    return InvariantViolation(
                        invariant_name=inv.name,
                        description=inv.description,
                        severity=inv.severity,
                        tool_name=tool_name,
                        field_path=inv.field_path,
                        actual_value=value,
                        expected=f"must match: {inv.value}",
                    )

        elif inv.invariant_type == InvariantType.VALUE_NOT_MATCHES:
            if field_exists and isinstance(value, str):
                if re.search(str(inv.value), value):
                    return InvariantViolation(
                        invariant_name=inv.name,
                        description=inv.description,
                        severity=inv.severity,
                        tool_name=tool_name,
                        field_path=inv.field_path,
                        actual_value=value[:100],
                        expected=f"must NOT match: {inv.value}",
                    )

        elif inv.invariant_type == InvariantType.VALUE_IN_SET:
            if field_exists and value not in inv.value:
                return InvariantViolation(
                    invariant_name=inv.name,
                    description=inv.description,
                    severity=inv.severity,
                    tool_name=tool_name,
                    field_path=inv.field_path,
                    actual_value=value,
                    expected=f"must be one of: {inv.value}",
                )

        elif inv.invariant_type == InvariantType.VALUE_NOT_IN_SET:
            if field_exists and value in inv.value:
                return InvariantViolation(
                    invariant_name=inv.name,
                    description=inv.description,
                    severity=inv.severity,
                    tool_name=tool_name,
                    field_path=inv.field_path,
                    actual_value=value,
                    expected=f"must NOT be one of: {inv.value}",
                )

        elif inv.invariant_type == InvariantType.MAX_LENGTH:
            if field_exists and isinstance(value, str):
                if len(value) > int(inv.value):
                    return InvariantViolation(
                        invariant_name=inv.name,
                        description=inv.description,
                        severity=inv.severity,
                        tool_name=tool_name,
                        field_path=inv.field_path,
                        actual_value=f"length={len(value)}",
                        expected=f"max length: {inv.value}",
                    )

        return None

    def _resolve_path(self, data: dict[str, Any], path: str) -> Any:
        """Resolve a dot-notation path in nested dict."""
        if not path:
            return data
        parts = path.split(".")
        current: Any = data
        for part in parts:
            if isinstance(current, dict):
                if part in current:
                    current = current[part]
                else:
                    return _MISSING
            else:
                return _MISSING
        return current


class _MissingSentinel:
    """Sentinel for 'field does not exist'."""
    pass


_MISSING = _MissingSentinel()
