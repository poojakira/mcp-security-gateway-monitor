"""Cross-tool correlation engine for multi-step attack detection.

WHY THIS EXISTS:
MCP treats every tool call as independent. But real attacks are SEQUENCES:
  1. read_secret() -> gets API key
  2. email.send(bcc=attacker) -> exfiltrates it

No single-call detector catches this. The MCP spec has no concept of
tool-call sequencing constraints. OpenAI/Anthropic left this entirely
to deployers.

WHAT THIS MODULE DOES:
- Maintains a sliding window of recent tool calls per session
- Defines correlation rules that flag dangerous SEQUENCES
- Detects data flow between tools (output of tool A appearing in input of tool B)
- Computes chain-level risk scores that single-call analysis misses
"""

from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class ToolCallEvent:
    """Record of a single tool call in the correlation window."""

    tool_name: str
    server_id: str
    arguments: dict[str, Any]
    output: dict[str, Any] | None = None
    timestamp: float = field(default_factory=time.time)
    call_id: str = ""


@dataclass
class CorrelationRule:
    """A rule that defines a dangerous multi-tool sequence."""

    name: str
    description: str
    tool_sequence: list[str]  # Tool name patterns (regex)
    condition: Callable[[list[ToolCallEvent]], bool] | None = None
    severity: int = 80  # 0-100
    window_seconds: float = 300.0  # Time window for the sequence


@dataclass
class CorrelationAlert:
    """Alert generated when a correlation rule matches."""

    rule_name: str
    description: str
    severity: int
    matched_calls: list[ToolCallEvent]
    timestamp: float = field(default_factory=time.time)
    data_flow: str = ""  # Description of detected data flow



# Built-in correlation rules for known attack patterns
def _data_read_then_exfil(events: list[ToolCallEvent]) -> bool:
    """Detect: secret/sensitive data read followed by outbound send."""
    read_outputs: list[str] = []
    for evt in events:
        if evt.output:
            read_outputs.append(str(evt.output))
    # Check if any read output content appears in later send arguments
    for i, evt in enumerate(events):
        if any(kw in evt.tool_name.lower() for kw in ("send", "email", "post", "upload")):
            args_str = str(evt.arguments)
            for earlier_output in read_outputs[:i]:
                # Check for substring matches (data flowing from read to send)
                if len(earlier_output) > 20:
                    # Check if significant chunks of read data appear in send
                    chunks = [earlier_output[j:j+20] for j in range(0, min(len(earlier_output), 200), 20)]
                    for chunk in chunks:
                        if chunk in args_str and chunk.strip():
                            return True
    return False


DEFAULT_RULES: list[CorrelationRule] = [
    CorrelationRule(
        name="read_then_exfil",
        description="Sensitive data read followed by outbound transmission",
        tool_sequence=[r"(read|get|fetch|query|secret|key|token)", r"(send|email|post|upload|webhook)"],
        condition=_data_read_then_exfil,
        severity=90,
        window_seconds=120.0,
    ),
    CorrelationRule(
        name="credential_harvest",
        description="Multiple credential/secret reads in rapid succession",
        tool_sequence=[r"(secret|credential|key|token|password)", r"(secret|credential|key|token|password)"],
        severity=70,
        window_seconds=60.0,
    ),
    CorrelationRule(
        name="recon_then_exploit",
        description="Information gathering followed by privileged action",
        tool_sequence=[r"(list|scan|discover|enumerate)", r"(delete|modify|admin|execute|shell)"],
        severity=85,
        window_seconds=180.0,
    ),
    CorrelationRule(
        name="shadow_pivot",
        description="Call to registered server followed by unregistered server",
        tool_sequence=[r".*", r".*"],  # Any tools, condition checks server_id
        condition=lambda events: (
            len(events) >= 2 and
            events[0].server_id != events[-1].server_id and
            events[-1].server_id not in {"", events[0].server_id}
        ),
        severity=75,
        window_seconds=60.0,
    ),
]



class CrossToolCorrelationEngine:
    """Detects multi-step attacks by correlating sequences of tool calls.

    The MCP spec treats each tool call as stateless and independent.
    Attackers exploit this by splitting attacks across multiple calls
    that individually look benign.
    """

    def __init__(
        self,
        *,
        window_size: int = 100,
        rules: list[CorrelationRule] | None = None,
    ) -> None:
        self._window: deque[ToolCallEvent] = deque(maxlen=window_size)
        self._rules = rules if rules is not None else list(DEFAULT_RULES)
        self._alerts: list[CorrelationAlert] = []

    def record_call(
        self,
        tool_name: str,
        server_id: str,
        arguments: dict[str, Any],
        output: dict[str, Any] | None = None,
        call_id: str = "",
    ) -> list[CorrelationAlert]:
        """Record a tool call and check for correlation matches.

        Returns any new alerts generated by this call.
        """
        event = ToolCallEvent(
            tool_name=tool_name,
            server_id=server_id,
            arguments=arguments,
            output=output,
            call_id=call_id,
        )
        self._window.append(event)

        # Check all rules against current window
        new_alerts = self._evaluate_rules(event)
        self._alerts.extend(new_alerts)
        return new_alerts

    def add_rule(self, rule: CorrelationRule) -> None:
        """Add a custom correlation rule."""
        self._rules.append(rule)

    def get_alerts(self) -> list[CorrelationAlert]:
        """Get all generated alerts."""
        return list(self._alerts)

    def get_recent_calls(self, n: int = 10) -> list[ToolCallEvent]:
        """Get the last n tool calls from the window."""
        calls = list(self._window)
        return calls[-n:]

    def clear_window(self) -> None:
        """Clear the correlation window (e.g., on session reset)."""
        self._window.clear()

    def detect_data_flow(
        self, source_output: dict, target_arguments: dict
    ) -> list[str]:
        """Detect if data from one tool's output flows into another's input.

        Returns list of field paths where data flow was detected.
        """
        flows: list[str] = []
        source_values = self._extract_values(source_output)
        target_str = str(target_arguments)

        for path, value in source_values:
            if isinstance(value, str) and len(value) > 8:
                if value in target_str:
                    flows.append(f"{path} -> target_arguments")
        return flows

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _evaluate_rules(self, latest: ToolCallEvent) -> list[CorrelationAlert]:
        alerts: list[CorrelationAlert] = []
        now = time.time()

        for rule in self._rules:
            # Get events within the rule's time window
            window_events = [
                e for e in self._window
                if now - e.timestamp <= rule.window_seconds
            ]
            if len(window_events) < len(rule.tool_sequence):
                continue

            # Check if the sequence pattern matches
            matched = self._match_sequence(window_events, rule.tool_sequence)
            if not matched:
                continue

            # Check custom condition if present
            if rule.condition and not rule.condition(matched):
                continue

            # Generate alert
            alert = CorrelationAlert(
                rule_name=rule.name,
                description=rule.description,
                severity=rule.severity,
                matched_calls=matched,
            )

            # Check for data flow between matched calls
            if len(matched) >= 2:
                for i in range(len(matched) - 1):
                    if matched[i].output:
                        flows = self.detect_data_flow(
                            matched[i].output, matched[i + 1].arguments
                        )
                        if flows:
                            alert.data_flow = "; ".join(flows)

            alerts.append(alert)

        return alerts

    def _match_sequence(
        self, events: list[ToolCallEvent], patterns: list[str]
    ) -> list[ToolCallEvent] | None:
        """Find a subsequence of events matching the pattern list."""
        matched: list[ToolCallEvent] = []
        pattern_idx = 0

        for event in events:
            if pattern_idx >= len(patterns):
                break
            pattern = patterns[pattern_idx]
            if re.search(pattern, event.tool_name, re.IGNORECASE):
                matched.append(event)
                pattern_idx += 1

        if pattern_idx >= len(patterns):
            return matched
        return None

    def _extract_values(
        self, obj: Any, prefix: str = ""
    ) -> list[tuple[str, Any]]:
        """Extract all leaf values with their paths."""
        values: list[tuple[str, Any]] = []
        if isinstance(obj, dict):
            for key, val in obj.items():
                path = f"{prefix}.{key}" if prefix else key
                if isinstance(val, (dict, list)):
                    values.extend(self._extract_values(val, path))
                else:
                    values.append((path, val))
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                values.extend(self._extract_values(item, f"{prefix}[{i}]"))
        return values
