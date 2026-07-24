"""Layer C: REAL network monitor — sees what the server ACTUALLY connects to.

TWO MODES:
1. /proc/net/tcp parser (works TODAY, in any container, no root/eBPF needed):
   Reads the kernel's own connection table. If an MCP server opens a socket
   to giftshop.club, it appears here — regardless of what the server tells
   the agent. This is ground truth from the kernel's perspective.

2. eBPF C program (embedded below, for host deployment with CAP_BPF):
   Attaches to the connect() syscall and streams every outbound connection
   with the owning PID. This is the unforgeable version — the application
   cannot make a network call without the kernel seeing it.

The /proc approach is what makes this REAL and runnable here today. The eBPF
program is provided verbatim for production host deployment.
"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass, field


@dataclass
class Connection:
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    inode: int = 0


@dataclass
class NetworkAlert:
    remote_addr: str
    remote_port: int
    reason: str
    severity: int
    timestamp: float = field(default_factory=time.time)


# TCP states from the kernel
_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
    "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
    "0A": "LISTEN", "0B": "CLOSING",
}

_SMTP_PORTS = {25, 465, 587, 2525}


class NetworkMonitor:
    """Live outbound-connection monitor using the kernel's /proc/net table."""

    def __init__(self) -> None:
        self._allowed_remotes: set[str] = set()
        self._allowed_ports: set[int] = set()
        self._blocked_remotes: set[str] = set()
        self._alerts: list[NetworkAlert] = []

    def allow(self, addr: str, port: int | None = None) -> None:
        self._allowed_remotes.add(addr)
        if port is not None:
            self._allowed_ports.add(port)

    def block(self, addr: str) -> None:
        self._blocked_remotes.add(addr)

    def read_connections(self) -> list[Connection]:
        """Parse /proc/net/tcp (+tcp6) into a list of live connections."""
        conns: list[Connection] = []
        for path in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(path, "r") as f:
                    lines = f.readlines()[1:]
            except OSError:
                continue
            for line in lines:
                parts = line.split()
                if len(parts) < 10:
                    continue
                local = self._parse_addr(parts[1])
                remote = self._parse_addr(parts[2])
                state = _TCP_STATES.get(parts[3], parts[3])
                if not local or not remote:
                    continue
                try:
                    inode = int(parts[9])
                except (ValueError, IndexError):
                    inode = 0
                conns.append(Connection(
                    local_addr=local[0], local_port=local[1],
                    remote_addr=remote[0], remote_port=remote[1],
                    state=state, inode=inode,
                ))
        return conns

    def scan(self) -> list[NetworkAlert]:
        """Scan current connections against policy. Returns new alerts."""
        alerts: list[NetworkAlert] = []
        for c in self.read_connections():
            if c.remote_port == 0 or c.remote_addr in ("0.0.0.0", "::"):
                continue  # listening / not a real outbound
            # Blocked destination
            if c.remote_addr in self._blocked_remotes:
                alerts.append(NetworkAlert(
                    c.remote_addr, c.remote_port,
                    "connection to explicitly blocked host", 95))
                continue
            # Hidden SMTP (the Postmark server-side attack signature)
            if c.remote_port in _SMTP_PORTS and c.remote_port not in self._allowed_ports:
                alerts.append(NetworkAlert(
                    c.remote_addr, c.remote_port,
                    f"hidden SMTP connection on port {c.remote_port}", 95))
                continue
            # Unapproved destination (only if a whitelist is configured)
            if self._allowed_remotes and c.remote_addr not in self._allowed_remotes:
                if not self._is_local(c.remote_addr):
                    alerts.append(NetworkAlert(
                        c.remote_addr, c.remote_port,
                        "connection to unapproved destination", 80))
        self._alerts.extend(alerts)
        return alerts

    def all_alerts(self) -> list[NetworkAlert]:
        return list(self._alerts)

    @staticmethod
    def _parse_addr(hexaddr: str) -> tuple[str, int] | None:
        """Parse 'HEXADDR:HEXPORT' from /proc/net/tcp."""
        try:
            addr_part, port_part = hexaddr.split(":")
            port = int(port_part, 16)
            if len(addr_part) == 8:  # IPv4
                addr_bytes = struct.pack("<I", int(addr_part, 16))
                addr = socket.inet_ntoa(addr_bytes)
            else:  # IPv6 — compact representation
                addr = "ipv6:" + addr_part.lower()
            return (addr, port)
        except (ValueError, struct.error, OSError):
            return None

    @staticmethod
    def _is_local(addr: str) -> bool:
        if addr.startswith("127.") or addr.startswith("10."):
            return True
        if addr.startswith("192.168."):
            return True
        # RFC 1918: 172.16.0.0/12 = 172.16.x.x through 172.31.x.x only
        if addr.startswith("172."):
            parts = addr.split(".")
            if len(parts) >= 2:
                try:
                    second = int(parts[1])
                    if 16 <= second <= 31:
                        return True
                except ValueError:
                    pass
        if addr in ("0.0.0.0", "::") or addr.startswith("ipv6:"):
            return True
        return False


# ---------------------------------------------------------------------------
# eBPF program for PRODUCTION HOST deployment (requires CAP_BPF / root on host).
# Load with bcc: BPF(text=EBPF_CONNECT_MONITOR). Streams every connect() with
# PID + destination. This is the unforgeable, kernel-level version.
# ---------------------------------------------------------------------------

EBPF_CONNECT_MONITOR = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct conn_event {
    u32 pid;
    u32 daddr;
    u16 dport;
    char comm[16];
};
BPF_PERF_OUTPUT(connect_events);

int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    struct conn_event evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.daddr = sk->__sk_common.skc_daddr;
    evt.dport = sk->__sk_common.skc_dport;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    connect_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""
