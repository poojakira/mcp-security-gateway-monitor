"""Write-Ahead Log (WAL) for crash-safe audit persistence.

Ensures that audit entries survive process crashes by writing them to a WAL
file *before* they are considered committed. On startup, ``recover()`` replays
any uncommitted entries from the WAL so the caller can re-apply them to the
main audit log.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any

from mcp_monitor.audit.log import AuditEntry

try:  # POSIX advisory locking for cross-process safety
    import fcntl

    _HAVE_FCNTL = True
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore
    _HAVE_FCNTL = False


class WriteAheadLog:
    """Crash-safe persistence layer for audit entries."""

    def __init__(self, wal_path: str) -> None:
        self._wal_path = Path(wal_path)
        self._wal_path.parent.mkdir(parents=True, exist_ok=True)
        # In-process serialization of concurrent writers.
        self._lock = threading.Lock()
        # Track committed position
        self._committed_count: int = 0
        self._entries_written: int = self._count_existing_entries()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(self, entry: AuditEntry) -> None:
        """Append an entry to the WAL durably and without a TOCTOU window.

        A single ``O_APPEND`` write is atomic for line-sized payloads on POSIX,
        so there is no temp file to read back (the previous temp-file +
        double-read pattern was racy and left Windows debris). We additionally:
          * take an in-process lock to serialize threads,
          * take an advisory file lock (``flock``) to serialize processes,
          * ``fsync`` the file, and
          * ``fsync`` the parent directory so the append is truly durable.
        """
        line = (json.dumps(asdict(entry)) + "\n").encode("utf-8")
        with self._lock:
            # Open in append+binary; O_APPEND makes each write atomic at the OS
            # level so interleaved lines never corrupt each other.
            fd = os.open(
                str(self._wal_path),
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            try:
                if _HAVE_FCNTL:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                os.write(fd, line)
                os.fsync(fd)
            finally:
                if _HAVE_FCNTL:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
                os.close(fd)
            self._fsync_dir()
            self._entries_written += 1

    def _fsync_dir(self) -> None:
        """fsync the parent directory so the file append/metadata is durable."""
        if not _HAVE_FCNTL:  # directory fsync is a POSIX concept
            return
        try:
            dfd = os.open(str(self._wal_path.parent), os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:  # pragma: no cover - platform dependent
            pass

    def recover(self) -> list[AuditEntry]:
        """Replay uncommitted entries from the WAL.

        Returns entries written after the last checkpoint.
        """
        if not self._wal_path.exists():
            return []

        all_entries: list[AuditEntry] = []
        with self._wal_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                entry = AuditEntry(
                    entry_id=raw["entry_id"],
                    timestamp=raw["timestamp"],
                    event_type=raw["event_type"],
                    data=raw["data"],
                    prev_hash=raw["prev_hash"],
                    entry_hash=raw["entry_hash"],
                )
                all_entries.append(entry)

        # Return only uncommitted entries (those after the checkpoint)
        uncommitted = all_entries[self._committed_count:]
        return uncommitted

    def checkpoint(self) -> None:
        """Mark all current WAL entries as committed.

        After checkpoint, those entries will not be returned by recover().
        """
        self._committed_count = self._entries_written

    def truncate(self) -> None:
        """Remove the WAL file entirely (e.g., after full recovery)."""
        if self._wal_path.exists():
            self._wal_path.unlink()
        self._committed_count = 0
        self._entries_written = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _count_existing_entries(self) -> int:
        """Count entries already present in WAL file."""
        if not self._wal_path.exists():
            return 0
        count = 0
        with self._wal_path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    count += 1
        return count
