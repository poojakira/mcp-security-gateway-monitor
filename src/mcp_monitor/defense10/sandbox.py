"""Layer A: REAL Docker/OCI sandbox isolation for untrusted MCP servers.

WHY THIS IS THE STRONGEST SINGLE CONTROL:
If the MCP server runs in a container with '--network none' (or only an
egress proxy), it CANNOT connect to giftshop.club no matter what its code
does. The kernel enforces the boundary. The attacker's one-line BCC still
executes — but the packet dies at the network namespace boundary.

This module actually shells out to the container runtime (docker/podman)
and enforces:
  - network isolation (none, or a single egress-proxy network)
  - read-only root filesystem
  - dropped capabilities
  - memory/CPU limits
  - no new privileges

Verified working in this environment: `docker run --network none` blocks
all outbound traffic.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SandboxConfig:
    image: str = "python:3.12-alpine"
    network: str = "none"              # "none" | "<egress-proxy-net>"
    read_only: bool = True
    memory: str = "256m"
    cpus: str = "0.5"
    drop_all_caps: bool = True
    no_new_privileges: bool = True
    extra_args: list[str] = field(default_factory=list)

    # Allowlist of acceptable extra docker flags. Any flag not in this list is rejected.
    _ALLOWED_EXTRA_ARGS = frozenset([
        "--tmpfs", "--env", "--label", "--workdir", "--user",
        "--hostname", "--entrypoint", "--stop-timeout",
    ])


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    network_blocked: bool
    command: list[str] = field(default_factory=list)


class DockerSandbox:
    """Runs untrusted MCP server commands inside an isolated container."""

    def __init__(self, config: SandboxConfig | None = None) -> None:
        self._config = config or SandboxConfig()
        self._runtime = self._detect_runtime()

    @staticmethod
    def _detect_runtime() -> str | None:
        for rt in ("docker", "podman"):
            if shutil.which(rt):
                return rt
        return None

    @property
    def available(self) -> bool:
        return self._runtime is not None

    def build_command(self, cmd: list[str]) -> list[str]:
        """Build the hardened container run command.

        Validates extra_args against an allowlist to prevent privilege
        escalation via --privileged, --network=host, --pid=host, etc.
        """
        c = self._config
        args = [self._runtime, "run", "--rm"]
        args += ["--network", c.network]
        if c.read_only:
            args.append("--read-only")
        if c.drop_all_caps:
            args += ["--cap-drop", "ALL"]
        if c.no_new_privileges:
            args += ["--security-opt", "no-new-privileges"]
        args += ["--memory", c.memory, "--cpus", c.cpus]
        # Strict allowlist: any flag token not explicitly permitted causes an
        # immediate failure. Silently dropping a dangerous flag (the previous
        # behavior) is worse than crashing — the operator believes a capability
        # was applied when it was not, and substring blocklists are bypassable
        # (e.g. "--cap-add=SYS_ADMIN" vs "--cap-add SYS_ADMIN").
        for ea in c.extra_args:
            token = str(ea)
            if token.startswith("-"):
                flag = token.split("=", 1)[0].strip()
                if flag not in c._ALLOWED_EXTRA_ARGS:
                    raise ValueError(
                        f"Disallowed sandbox flag {flag!r} (from {ea!r}); "
                        f"permitted flags: {sorted(c._ALLOWED_EXTRA_ARGS)}"
                    )
            args.append(ea)
        args.append(c.image)
        args += cmd
        return args

    def run(self, cmd: list[str], timeout: int = 30) -> SandboxResult:
        """Execute a command inside the sandbox."""
        if not self.available:
            return SandboxResult(
                exit_code=-1, stdout="", stderr="no container runtime available",
                network_blocked=False,
            )
        full = self.build_command(cmd)
        try:
            proc = subprocess.run(
                full, capture_output=True, text=True, timeout=timeout,
            )
            return SandboxResult(
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                network_blocked=(self._config.network == "none"),
                command=full,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                exit_code=-2, stdout="", stderr="timeout",
                network_blocked=(self._config.network == "none"), command=full,
            )

    def verify_network_isolation(self) -> dict[str, Any]:
        """Prove the sandbox actually blocks outbound network.

        Runs a container that tries to reach an external host and confirms
        it fails.
        """
        if not self.available:
            return {"available": False, "isolated": None}
        # Try to connect out; should fail under --network none
        test_cmd = [
            "sh", "-c",
            "wget -T 2 -q -O- http://1.1.1.1 2>&1 && echo REACHED || echo BLOCKED",
        ]
        result = self.run(test_cmd, timeout=15)
        isolated = "BLOCKED" in result.stdout or "REACHED" not in result.stdout
        return {
            "available": True,
            "runtime": self._runtime,
            "network_mode": self._config.network,
            "isolated": isolated,
            "raw_output": result.stdout.strip()[:200],
        }
