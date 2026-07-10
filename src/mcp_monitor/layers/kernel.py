"""Layer 3: Kernel-level monitoring for MCP server behavior."""
from __future__ import annotations
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class SyscallType(Enum):
    NETWORK_CONNECT = "network_connect"
    DNS_RESOLVE = "dns_resolve"
    FILE_OPEN = "file_open"
    FILE_WRITE = "file_write"
    PROCESS_SPAWN = "process_spawn"
    SOCKET_SEND = "socket_send"

@dataclass
class SyscallEvent:
    server_id: str
    syscall_type: SyscallType
    details: dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    pid: int = 0

@dataclass
class KernelAlert:
    server_id: str
    alert_type: str
    description: str
    severity: int
    syscall_event: SyscallEvent | None = None
    timestamp: float = field(default_factory=time.time)

@dataclass
class ServerPolicy:
    server_id: str
    allowed_destinations: set[str] = field(default_factory=set)
    allowed_ports: set[int] = field(default_factory=set)
    allowed_paths: set[str] = field(default_factory=set)
    blocked_destinations: set[str] = field(default_factory=set)
    max_connections_per_minute: int = 100
    allow_subprocess: bool = False
    allow_dns: bool = True

class KernelMonitor:
    def __init__(self) -> None:
        self._policies: dict[str, ServerPolicy] = {}
        self._events: dict[str, list[SyscallEvent]] = defaultdict(list)
        self._alerts: list[KernelAlert] = []
        self._connection_counts: dict[str, list[float]] = defaultdict(list)

    def register_policy(self, policy: ServerPolicy) -> None:
        self._policies[policy.server_id] = policy

    def process_event(self, event: SyscallEvent) -> list[KernelAlert]:
        self._events[event.server_id].append(event)
        alerts: list[KernelAlert] = []
        policy = self._policies.get(event.server_id)
        if policy is None:
            alerts.append(KernelAlert(server_id=event.server_id, alert_type="no_policy", description=f"Syscall from server with no policy: {event.syscall_type.value}", severity=70, syscall_event=event))
            self._alerts.extend(alerts)
            return alerts
        if event.syscall_type == SyscallType.NETWORK_CONNECT:
            alerts.extend(self._check_network(event, policy))
        elif event.syscall_type == SyscallType.DNS_RESOLVE:
            if not policy.allow_dns:
                alerts.append(KernelAlert(server_id=event.server_id, alert_type="unauthorized_dns", description=f"DNS not allowed: {event.details.get('domain', '')}", severity=60, syscall_event=event))
            domain = event.details.get("domain", "")
            if domain in policy.blocked_destinations:
                alerts.append(KernelAlert(server_id=event.server_id, alert_type="blocked_dns", description=f"Blocked domain DNS: {domain}", severity=90, syscall_event=event))
        elif event.syscall_type == SyscallType.FILE_OPEN:
            path = event.details.get("path", "")
            if policy.allowed_paths and not any(path.startswith(p) for p in policy.allowed_paths):
                alerts.append(KernelAlert(server_id=event.server_id, alert_type="unauthorized_file_access", description=f"File outside allowed: {path}", severity=70, syscall_event=event))
        elif event.syscall_type == SyscallType.PROCESS_SPAWN:
            if not policy.allow_subprocess:
                alerts.append(KernelAlert(server_id=event.server_id, alert_type="unauthorized_subprocess", description=f"Subprocess: {event.details.get('command', '')}", severity=90, syscall_event=event))
        elif event.syscall_type == SyscallType.SOCKET_SEND:
            size = event.details.get("bytes", 0)
            dest = event.details.get("destination", "")
            if size > 10240 and dest not in policy.allowed_destinations:
                alerts.append(KernelAlert(server_id=event.server_id, alert_type="large_send_unknown_dest", description=f"Large send ({size}B) to {dest}", severity=80, syscall_event=event))
        # Rate limit
        if event.syscall_type == SyscallType.NETWORK_CONNECT:
            now = time.time()
            self._connection_counts[event.server_id].append(now)
            self._connection_counts[event.server_id] = [t for t in self._connection_counts[event.server_id] if now - t <= 60]
            if len(self._connection_counts[event.server_id]) > policy.max_connections_per_minute:
                alerts.append(KernelAlert(server_id=event.server_id, alert_type="rate_limit_exceeded", description=f"Rate: {len(self._connection_counts[event.server_id])}/min > {policy.max_connections_per_minute}", severity=65, syscall_event=event))
        self._alerts.extend(alerts)
        return alerts

    def _check_network(self, event: SyscallEvent, policy: ServerPolicy) -> list[KernelAlert]:
        alerts = []
        dest = event.details.get("destination", "")
        port = event.details.get("port", 0)
        if dest in policy.blocked_destinations:
            alerts.append(KernelAlert(server_id=event.server_id, alert_type="blocked_destination", description=f"Blocked: {dest}:{port}", severity=95, syscall_event=event))
            return alerts
        if policy.allowed_destinations and dest not in policy.allowed_destinations:
            alerts.append(KernelAlert(server_id=event.server_id, alert_type="unknown_destination", description=f"Unapproved: {dest}:{port}", severity=80, syscall_event=event))
        if policy.allowed_ports and port not in policy.allowed_ports:
            alerts.append(KernelAlert(server_id=event.server_id, alert_type="unauthorized_port", description=f"Port {port} not allowed", severity=75, syscall_event=event))
        if self.detect_hidden_smtp(event):
            alerts.append(KernelAlert(server_id=event.server_id, alert_type="hidden_smtp", description=f"Hidden SMTP on port {port} to {dest}", severity=95, syscall_event=event))
        return alerts

    def detect_hidden_smtp(self, event: SyscallEvent) -> bool:
        if event.syscall_type != SyscallType.NETWORK_CONNECT:
            return False
        port = event.details.get("port", 0)
        if port in {25, 465, 587, 2525}:
            policy = self._policies.get(event.server_id)
            if policy and port not in policy.allowed_ports:
                return True
        return False

    def get_alerts(self, server_id: str | None = None) -> list[KernelAlert]:
        if server_id:
            return [a for a in self._alerts if a.server_id == server_id]
        return list(self._alerts)

    def get_server_activity(self, server_id: str) -> dict[str, Any]:
        events = self._events.get(server_id, [])
        by_type: dict[str, int] = defaultdict(int)
        for e in events:
            by_type[e.syscall_type.value] += 1
        return {"server_id": server_id, "total_events": len(events), "by_type": dict(by_type), "has_policy": server_id in self._policies, "alert_count": len([a for a in self._alerts if a.server_id == server_id])}
