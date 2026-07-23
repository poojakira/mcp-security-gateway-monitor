"""CLI entry point for mcp-security-gateway-monitor."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcp_monitor import AuditLog, MCPSecurityMonitor, WriteAheadLog


def _load_allowed_servers(path: Path) -> set[str]:
    if path.suffix == ".json":
        return set(json.loads(path.read_text()))
    return {line.strip() for line in path.read_text().splitlines() if line.strip()}


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-monitor",
        description="MCP Security Gateway Monitor — inspect tool calls for prompt injection, PII, shadow servers, exfiltration",
    )
    parser.add_argument(
        "--allowed-servers",
        type=Path,
        required=True,
        help="Path to JSON list or newline-separated list of allowed server IDs",
    )
    parser.add_argument(
        "--audit-dir",
        type=Path,
        default=Path("./audit_logs"),
        help="Directory for audit log (WAL + index)",
    )
    parser.add_argument(
        "--max-payload-kb",
        type=float,
        default=100.0,
        help="Max payload size in KB before exfiltration flag",
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="JSON file with tool calls to inspect (one per line). If omitted, read from stdin.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output file for results (JSONL). If omitted, print to stdout.",
    )
    args = parser.parse_args()

    allowed_servers = _load_allowed_servers(args.allowed_servers)
    audit_log = AuditLog(WriteAheadLog(args.audit_dir))

    monitor = MCPSecurityMonitor(
        allowed_servers=allowed_servers,
        audit_log=audit_log,
        max_payload_kb=args.max_payload_kb,
    )

    # Read tool calls
    if args.input:
        lines = args.input.read_text().strip().splitlines()
    else:
        lines = sys.stdin.read().strip().splitlines()

    if not lines:
        return 0

    out_fh = args.output.open("w") if args.output else sys.stdout

    try:
        for line in lines:
            if not line.strip():
                continue
            tool_call = json.loads(line)
            result = monitor.inspect_call(tool_call)
            out_fh.write(json.dumps(result) + "\n")
    finally:
        if args.output:
            out_fh.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())