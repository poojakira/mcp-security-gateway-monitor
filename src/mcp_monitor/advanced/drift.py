"""Behavioral drift detection for MCP tools.

WHY THIS EXISTS:
The Postmark attack pattern: 15 clean versions that built trust, then a single
line of code changed behavior silently. No schema changed. No capabilities
changed. The BEHAVIOR changed.

Existing solutions (manifest signing, schema diffing) cannot catch this because
the interface stayed identical — only the runtime behavior drifted.

WHAT THIS MODULE DOES:
- Records behavioral fingerprints: what a tool actually DOES given known inputs
- Detects when outputs deviate from established baselines
- Tracks statistical anomalies in output structure, field presence, and data flow
- Flags "silent additions" — new fields appearing in outputs that weren't there before
  (exactly how BCC was added: the tool started returning/using a field it never had)
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class BehaviorSample:
    """Single observation of a tool's input->output behavior."""

    tool_name: str
    input_hash: str  # SHA-256 of canonical input
    output_fields: frozenset  # set of field paths in output
    output_hash: str  # SHA-256 of canonical output
    timestamp: float = field(default_factory=time.time)
    payload_size: int = 0


@dataclass
class DriftAlert:
    """A detected behavioral drift event."""

    tool_name: str
    drift_type: str  # new_field, field_removed, output_changed, size_anomaly
    details: str
    severity: int  # 0-100
    timestamp: float = field(default_factory=time.time)
    baseline_sample: BehaviorSample | None = None
    current_sample: BehaviorSample | None = None


class BehavioralDriftDetector:
    """Detects when MCP tools silently change runtime behavior.

    This is THE critical gap: Anthropic refused to enforce behavioral
    consistency at the protocol level. We enforce it by maintaining
    behavioral baselines and flagging deviations.
    """

    def __init__(self, *, baseline_window: int = 50, sensitivity: float = 0.8) -> None:
        """
        Parameters
        ----------
        baseline_window:
            Number of recent samples to keep per tool for baselining.
        sensitivity:
            0.0 to 1.0, how sensitive drift detection is (higher = more alerts).
        """
        self._baseline_window = baseline_window
        self._sensitivity = sensitivity
        # tool_name -> list of BehaviorSample
        self._baselines: dict[str, list[BehaviorSample]] = defaultdict(list)
        # tool_name -> set of known output field paths
        self._known_fields: dict[str, set[str]] = defaultdict(set)
        # tool_name -> list of payload sizes for anomaly detection
        self._size_history: dict[str, list[int]] = defaultdict(list)
        # Alerts generated
        self._alerts: list[DriftAlert] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_baseline(
        self, tool_name: str, input_data: dict, output_data: dict
    ) -> BehaviorSample:
        """Record a known-good input/output pair as baseline behavior."""
        sample = self._create_sample(tool_name, input_data, output_data)
        self._baselines[tool_name].append(sample)
        # Maintain window size
        if len(self._baselines[tool_name]) > self._baseline_window:
            self._baselines[tool_name] = self._baselines[tool_name][
                -self._baseline_window :
            ]

        # Update known fields
        output_fields = self._extract_field_paths(output_data)
        self._known_fields[tool_name].update(output_fields)

        # Update size history
        self._size_history[tool_name].append(sample.payload_size)
        if len(self._size_history[tool_name]) > self._baseline_window:
            self._size_history[tool_name] = self._size_history[tool_name][
                -self._baseline_window :
            ]

        return sample

    def check_drift(
        self, tool_name: str, input_data: dict, output_data: dict
    ) -> tuple[bool, list[DriftAlert]]:
        """Check if a tool's current behavior has drifted from baseline.

        Returns
        -------
        tuple of (drifted: bool, alerts: list[DriftAlert])
        """
        alerts: list[DriftAlert] = []
        current = self._create_sample(tool_name, input_data, output_data)
        current_fields = self._extract_field_paths(output_data)

        # No baseline yet — can't detect drift
        if tool_name not in self._baselines or not self._baselines[tool_name]:
            return (False, [])

        # 1. NEW FIELD DETECTION (the Postmark pattern)
        # If a tool suddenly starts outputting fields it never had before,
        # that's the #1 indicator of silent behavioral change.
        known = self._known_fields.get(tool_name, set())
        new_fields = current_fields - known
        if new_fields:
            alert = DriftAlert(
                tool_name=tool_name,
                drift_type="new_field",
                details=f"New fields in output: {sorted(new_fields)}",
                severity=self._compute_new_field_severity(new_fields),
                current_sample=current,
            )
            alerts.append(alert)

        # 2. FIELD DISAPPEARANCE (capability removal/hiding)
        if known:
            # Only alert if fields that were ALWAYS present are now missing
            always_present = self._get_always_present_fields(tool_name)
            missing = always_present - current_fields
            if missing:
                alert = DriftAlert(
                    tool_name=tool_name,
                    drift_type="field_removed",
                    details=f"Expected fields missing: {sorted(missing)}",
                    severity=50,
                    current_sample=current,
                )
                alerts.append(alert)

        # 3. PAYLOAD SIZE ANOMALY
        if self._size_history[tool_name]:
            size_alert = self._check_size_anomaly(tool_name, current.payload_size)
            if size_alert:
                alerts.append(size_alert)

        # 4. OUTPUT DETERMINISM CHECK
        # For same input, did the output structure fundamentally change?
        matching_inputs = [
            s for s in self._baselines[tool_name] if s.input_hash == current.input_hash
        ]
        if matching_inputs:
            baseline_fields = matching_inputs[-1].output_fields
            if current.output_fields != baseline_fields:
                added = current.output_fields - baseline_fields
                removed = baseline_fields - current.output_fields
                alert = DriftAlert(
                    tool_name=tool_name,
                    drift_type="output_changed",
                    details=f"Same input, different output structure. Added: {sorted(added)}, Removed: {sorted(removed)}",
                    severity=75,
                    baseline_sample=matching_inputs[-1],
                    current_sample=current,
                )
                alerts.append(alert)

        # Store alerts
        self._alerts.extend(alerts)
        return (bool(alerts), alerts)

    def get_alerts(self, tool_name: str | None = None) -> list[DriftAlert]:
        """Retrieve drift alerts, optionally filtered by tool."""
        if tool_name:
            return [a for a in self._alerts if a.tool_name == tool_name]
        return list(self._alerts)

    def get_baseline_stats(self, tool_name: str) -> dict[str, Any]:
        """Get statistical summary of a tool's baseline behavior."""
        samples = self._baselines.get(tool_name, [])
        sizes = self._size_history.get(tool_name, [])
        fields = self._known_fields.get(tool_name, set())

        if not samples:
            return {"status": "no_baseline", "sample_count": 0}

        avg_size = sum(sizes) / len(sizes) if sizes else 0
        return {
            "status": "active",
            "sample_count": len(samples),
            "known_fields": sorted(fields),
            "avg_payload_size": round(avg_size, 1),
            "min_payload_size": min(sizes) if sizes else 0,
            "max_payload_size": max(sizes) if sizes else 0,
            "first_seen": min(s.timestamp for s in samples),
            "last_seen": max(s.timestamp for s in samples),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _create_sample(
        self, tool_name: str, input_data: dict, output_data: dict
    ) -> BehaviorSample:
        input_canonical = json.dumps(input_data, sort_keys=True, separators=(",", ":"))
        output_canonical = json.dumps(
            output_data, sort_keys=True, separators=(",", ":")
        )
        return BehaviorSample(
            tool_name=tool_name,
            input_hash=hashlib.sha256(input_canonical.encode()).hexdigest(),
            output_fields=frozenset(self._extract_field_paths(output_data)),
            output_hash=hashlib.sha256(output_canonical.encode()).hexdigest(),
            payload_size=len(output_canonical),
        )

    def _extract_field_paths(self, obj: Any, prefix: str = "") -> set[str]:
        """Recursively extract all field paths from a nested dict."""
        paths: set[str] = set()
        if isinstance(obj, dict):
            for key, value in obj.items():
                path = f"{prefix}.{key}" if prefix else key
                paths.add(path)
                paths.update(self._extract_field_paths(value, path))
        elif isinstance(obj, list) and obj:
            # Track that this path contains a list
            paths.add(f"{prefix}[]")
            if isinstance(obj[0], dict):
                paths.update(self._extract_field_paths(obj[0], f"{prefix}[]"))
        return paths

    def _get_always_present_fields(self, tool_name: str) -> set[str]:
        """Get fields that appear in every baseline sample for this tool."""
        samples = self._baselines.get(tool_name, [])
        if not samples:
            return set()
        always = set(samples[0].output_fields)
        for sample in samples[1:]:
            always &= sample.output_fields
        return always

    def _check_size_anomaly(
        self, tool_name: str, current_size: int
    ) -> DriftAlert | None:
        """Detect if payload size is anomalous relative to history."""
        sizes = self._size_history[tool_name]
        if len(sizes) < 5:
            return None  # Not enough data

        avg = sum(sizes) / len(sizes)
        if avg == 0:
            return None

        # Flag if size is >3x or <0.1x the average (scaled by sensitivity)
        threshold_high = avg * (3.0 / self._sensitivity)
        threshold_low = avg * (0.1 * self._sensitivity)

        if current_size > threshold_high:
            return DriftAlert(
                tool_name=tool_name,
                drift_type="size_anomaly",
                details=f"Payload size {current_size} is {current_size/avg:.1f}x the average ({avg:.0f})",
                severity=60,
            )
        if current_size < threshold_low and avg > 10:
            return DriftAlert(
                tool_name=tool_name,
                drift_type="size_anomaly",
                details=f"Payload size {current_size} is unusually small vs average ({avg:.0f})",
                severity=30,
            )
        return None

    def _compute_new_field_severity(self, new_fields: set[str]) -> int:
        """Score severity of new fields based on how dangerous they look."""
        high_risk_patterns = {
            "bcc",
            "cc",
            "forward",
            "redirect",
            "exfil",
            "hidden",
            "secret",
        }
        severity = 60  # Base severity for any new field
        for field_path in new_fields:
            field_lower = field_path.lower()
            for pattern in high_risk_patterns:
                if pattern in field_lower:
                    severity = 95  # Critical: this looks like the Postmark attack
                    break
        return min(severity, 100)
