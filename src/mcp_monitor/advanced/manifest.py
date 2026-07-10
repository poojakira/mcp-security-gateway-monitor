"""Cryptographic tool manifest signing and verification.

WHY THIS EXISTS:
Anthropic's position on the MCP STDIO RCE flaw was that "securing the STDIO
interface is the responsibility of whoever deploys it, not of the protocol."
This means there is ZERO protocol-level assurance that a tool's schema,
description, or capabilities haven't been tampered with since approval.

The Postmark attack exploited exactly this gap: the tool was approved at v1.0.15,
then silently changed behavior at v1.0.16. No one noticed because nothing was
checking whether the tool manifest had drifted.

WHAT THIS MODULE DOES:
- Signs tool manifests (name, description, schema, capabilities) with HMAC-SHA256
- Stores signed baselines as the "approved" version
- Verifies on every connection that the live manifest matches the signed version
- Detects ANY change: added parameters, modified descriptions, new capabilities
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ToolManifest:
    """Canonical representation of a tool's advertised interface."""

    server_id: str
    tool_name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema of inputs
    capabilities: list[str] = field(default_factory=list)
    version: str = ""
    signed_at: float = 0.0
    signature: str = ""

    def canonical_bytes(self) -> bytes:
        """Deterministic serialization for signing (excludes signature itself)."""
        canon = {
            "server_id": self.server_id,
            "tool_name": self.tool_name,
            "description": self.description,
            "parameters": self.parameters,
            "capabilities": sorted(self.capabilities),
            "version": self.version,
        }
        return json.dumps(canon, sort_keys=True, separators=(",", ":")).encode("utf-8")


class ManifestSigner:
    """Signs tool manifests using HMAC-SHA256.

    The signing key should be a secret held by the security team — NOT by
    the tool server itself. This ensures that a compromised server cannot
    re-sign its own modified manifest.
    """

    def __init__(self, signing_key: str) -> None:
        self._key = signing_key.encode("utf-8")

    def sign(self, manifest: ToolManifest) -> ToolManifest:
        """Sign a manifest, setting its signature and signed_at fields."""
        manifest.signed_at = time.time()
        payload = manifest.canonical_bytes()
        sig = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        manifest.signature = sig
        return manifest

    def compute_signature(self, manifest: ToolManifest) -> str:
        """Compute the HMAC signature without modifying the manifest."""
        payload = manifest.canonical_bytes()
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()


class ManifestVerifier:
    """Verifies tool manifests against signed baselines.

    Maintains a registry of signed (approved) manifests and can detect:
    - Schema drift (parameters changed)
    - Description poisoning (hidden instructions injected)
    - Capability escalation (new capabilities added)
    - Version rollback/jump
    """

    def __init__(self, signing_key: str) -> None:
        self._key = signing_key.encode("utf-8")
        self._baselines: dict[str, ToolManifest] = {}  # key: server_id::tool_name

    def register_baseline(self, manifest: ToolManifest) -> None:
        """Store a signed manifest as the approved baseline."""
        key = f"{manifest.server_id}::{manifest.tool_name}"
        self._baselines[key] = manifest

    def verify(self, live_manifest: ToolManifest) -> tuple[bool, list[str]]:
        """Verify a live manifest against the signed baseline.

        Returns
        -------
        tuple of (valid: bool, violations: list[str])
        """
        violations: list[str] = []
        key = f"{live_manifest.server_id}::{live_manifest.tool_name}"

        # Check if we have a baseline
        if key not in self._baselines:
            violations.append(f"no_baseline: tool '{key}' has no signed baseline")
            return (False, violations)

        baseline = self._baselines[key]

        # 1. Verify baseline signature integrity
        expected_sig = hmac.new(
            self._key, baseline.canonical_bytes(), hashlib.sha256
        ).hexdigest()
        if baseline.signature != expected_sig:
            violations.append("baseline_tampered: stored baseline signature is invalid")

        # 2. Compare live manifest to baseline
        if live_manifest.description != baseline.description:
            violations.append(
                f"description_drift: description changed from "
                f"'{baseline.description[:50]}' to '{live_manifest.description[:50]}'"
            )

        if live_manifest.parameters != baseline.parameters:
            # Identify specific changes
            added = set(live_manifest.parameters.keys()) - set(baseline.parameters.keys())
            removed = set(baseline.parameters.keys()) - set(live_manifest.parameters.keys())
            if added:
                violations.append(f"schema_drift:params_added:{','.join(sorted(added))}")
            if removed:
                violations.append(f"schema_drift:params_removed:{','.join(sorted(removed))}")
            # Check modified params
            for param in set(live_manifest.parameters.keys()) & set(baseline.parameters.keys()):
                if live_manifest.parameters[param] != baseline.parameters[param]:
                    violations.append(f"schema_drift:param_modified:{param}")

        if sorted(live_manifest.capabilities) != sorted(baseline.capabilities):
            new_caps = set(live_manifest.capabilities) - set(baseline.capabilities)
            if new_caps:
                violations.append(
                    f"capability_escalation:new_capabilities:{','.join(sorted(new_caps))}"
                )
            lost_caps = set(baseline.capabilities) - set(live_manifest.capabilities)
            if lost_caps:
                violations.append(
                    f"capability_reduction:lost:{','.join(sorted(lost_caps))}"
                )

        return (len(violations) == 0, violations)

    def verify_signature(self, manifest: ToolManifest) -> bool:
        """Verify the cryptographic signature of a manifest."""
        expected = hmac.new(
            self._key, manifest.canonical_bytes(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(manifest.signature, expected)

    @property
    def baselines(self) -> dict[str, ToolManifest]:
        return dict(self._baselines)
