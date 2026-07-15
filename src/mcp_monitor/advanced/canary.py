"""Tool canary system for active behavioral verification.

WHY THIS EXISTS:
Static analysis and signing only verify what a tool SAYS it does.
The Postmark attack proved that a tool can claim one behavior while
executing another. Anthropic/OpenAI provide no mechanism for runtime
verification that a tool actually does what it claims.

WHAT THIS MODULE DOES:
- Defines "canary probes": known-good inputs with expected outputs
- Periodically sends probes to tools to verify they still behave correctly
- Compares probe results against expected baselines
- Flags tools that have silently changed behavior between checks
- Functions as a "health check" for behavioral integrity

ANALOGY: Like a canary in a coal mine — if the canary dies (probe fails),
the mine (tool) is compromised even if everything looks fine on the surface.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class CanaryStatus(Enum):
    """Status of a canary probe result."""

    PASS = "pass"
    FAIL = "fail"
    DRIFT = "drift"  # Output changed but not critically
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class CanaryProbe:
    """A known-good test input for a tool with expected output."""

    probe_id: str
    tool_name: str
    input_data: dict[str, Any]
    expected_output: dict[str, Any] | None = None
    expected_fields: list[str] = field(default_factory=list)
    forbidden_fields: list[str] = field(default_factory=list)
    output_validator: Callable[[dict], bool] | None = None
    description: str = ""
    max_response_size: int = 0  # 0 = no limit


@dataclass
class CanaryResult:
    """Result of executing a canary probe."""

    probe_id: str
    tool_name: str
    status: CanaryStatus
    actual_output: dict[str, Any] | None = None
    violations: list[str] = field(default_factory=list)
    execution_time_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)
    output_hash: str = ""

    @property
    def passed(self) -> bool:
        return self.status == CanaryStatus.PASS


class ToolCanary:
    """Active behavioral verification for MCP tools.

    Sends known-good inputs to tools and verifies outputs haven't changed.
    This catches supply-chain compromise that static analysis misses.
    """

    def __init__(self) -> None:
        self._probes: dict[str, list[CanaryProbe]] = {}  # tool_name -> probes
        self._history: dict[str, list[CanaryResult]] = {}  # probe_id -> results
        self._baselines: dict[str, str] = {}  # probe_id -> expected output hash

    def register_probe(self, probe: CanaryProbe) -> None:
        """Register a canary probe for a tool."""
        self._probes.setdefault(probe.tool_name, []).append(probe)
        # If expected_output is set, compute baseline hash
        if probe.expected_output is not None:
            canonical = json.dumps(
                probe.expected_output, sort_keys=True, separators=(",", ":")
            )
            self._baselines[probe.probe_id] = hashlib.sha256(
                canonical.encode()
            ).hexdigest()

    def evaluate_response(
        self,
        probe_id: str,
        actual_output: dict[str, Any],
        execution_time_ms: float = 0.0,
    ) -> CanaryResult:
        """Evaluate a tool's response against the canary probe expectations.

        Parameters
        ----------
        probe_id:
            ID of the probe that was sent.
        actual_output:
            The tool's actual response.
        execution_time_ms:
            How long the tool took to respond.

        Returns
        -------
        CanaryResult with pass/fail status and any violations.
        """
        probe = self._find_probe(probe_id)
        if probe is None:
            return CanaryResult(
                probe_id=probe_id,
                tool_name="unknown",
                status=CanaryStatus.ERROR,
                violations=[f"Unknown probe_id: {probe_id}"],
            )

        violations: list[str] = []
        output_canonical = json.dumps(
            actual_output, sort_keys=True, separators=(",", ":")
        )
        output_hash = hashlib.sha256(output_canonical.encode()).hexdigest()

        # 1. Check expected output (exact match)
        if probe.expected_output is not None:
            baseline_hash = self._baselines.get(probe_id, "")
            if output_hash != baseline_hash:
                violations.append(
                    f"output_mismatch: expected hash {baseline_hash[:16]}..., "
                    f"got {output_hash[:16]}..."
                )

        # 2. Check expected fields present
        for field_name in probe.expected_fields:
            if not self._field_exists(actual_output, field_name):
                violations.append(f"missing_field: '{field_name}' not in output")

        # 3. Check forbidden fields absent
        for field_name in probe.forbidden_fields:
            if self._field_exists(actual_output, field_name):
                violations.append(
                    f"forbidden_field: '{field_name}' PRESENT in output "
                    f"(potential behavioral drift!)"
                )

        # 4. Check response size
        if probe.max_response_size > 0:
            if len(output_canonical) > probe.max_response_size:
                violations.append(
                    f"size_exceeded: response {len(output_canonical)} bytes > "
                    f"max {probe.max_response_size}"
                )

        # 5. Custom validator
        if probe.output_validator:
            try:
                if not probe.output_validator(actual_output):
                    violations.append(
                        "custom_validator: probe validator returned False"
                    )
            except Exception as e:
                violations.append(f"validator_error: {e}")

        # Determine status
        if not violations:
            status = CanaryStatus.PASS
        elif any("forbidden_field" in v for v in violations):
            status = CanaryStatus.FAIL  # Critical: new fields = likely compromise
        elif any("output_mismatch" in v for v in violations):
            status = CanaryStatus.DRIFT  # Output changed but might be benign
        else:
            status = CanaryStatus.FAIL

        result = CanaryResult(
            probe_id=probe_id,
            tool_name=probe.tool_name,
            status=status,
            actual_output=actual_output,
            violations=violations,
            execution_time_ms=execution_time_ms,
            output_hash=output_hash,
        )

        # Store in history
        self._history.setdefault(probe_id, []).append(result)
        return result

    def get_probes_for_tool(self, tool_name: str) -> list[CanaryProbe]:
        """Get all registered probes for a tool."""
        return self._probes.get(tool_name, [])

    def get_history(self, probe_id: str) -> list[CanaryResult]:
        """Get historical results for a probe."""
        return self._history.get(probe_id, [])

    def get_tool_health(self, tool_name: str) -> dict[str, Any]:
        """Get overall health summary for a tool based on canary results."""
        probes = self._probes.get(tool_name, [])
        if not probes:
            return {"status": "no_probes", "tool_name": tool_name}

        total = 0
        passed = 0
        failed = 0
        drifted = 0

        for probe in probes:
            history = self._history.get(probe.probe_id, [])
            for result in history:
                total += 1
                if result.status == CanaryStatus.PASS:
                    passed += 1
                elif result.status == CanaryStatus.FAIL:
                    failed += 1
                elif result.status == CanaryStatus.DRIFT:
                    drifted += 1

        health_score = (passed / total * 100) if total > 0 else 100
        return {
            "status": "healthy" if failed == 0 else "compromised",
            "tool_name": tool_name,
            "health_score": round(health_score, 1),
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "drifted": drifted,
            "probe_count": len(probes),
        }

    def update_baseline(self, probe_id: str, new_expected: dict[str, Any]) -> None:
        """Update the expected output for a probe (after approved changes)."""
        canonical = json.dumps(new_expected, sort_keys=True, separators=(",", ":"))
        self._baselines[probe_id] = hashlib.sha256(canonical.encode()).hexdigest()
        # Update the probe's expected_output
        probe = self._find_probe(probe_id)
        if probe:
            probe.expected_output = new_expected

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _find_probe(self, probe_id: str) -> CanaryProbe | None:
        for probes in self._probes.values():
            for probe in probes:
                if probe.probe_id == probe_id:
                    return probe
        return None

    def _field_exists(self, data: dict[str, Any], field_path: str) -> bool:
        """Check if a dot-notation field path exists in data."""
        parts = field_path.split(".")
        current: Any = data
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return False
        return True
