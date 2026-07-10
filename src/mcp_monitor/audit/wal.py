"""Write-Ahead Log (WAL) for crash-safe audit persistence.

Ensures that audit entries survive process crashes by writing them to a WAL
file *before* they are considered committed. On startup, ``recover()`` replays
any uncommitted entries from the WAL so the caller can re-apply them to the
main audit log.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from mcp_monitor.audit.log import AuditEntry


class WriteAheadLog:
    """Crash-safe persistence layer for audit entries."""

    def __init__(self, wal_path: str) -> None:
        self._wal_path = Path(wal_path)
        self._wal_path.parent.mkdir(parents=True, exist_ok=True)
        # Track committed position
        self._committed_count: int = 0
        self._entries_written: int = self._count_existing_entries()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(self, entry: AuditEntry) -> None:
        """Atomically write an entry to the WAL.

        Uses write-to-temp + append pattern to minimize corruption risk.
        """
        data = json.dumps(asdict(entry))
        # Atomic-ish append: write to temp then append
        dir_path = str(self._wal_path.parent)
        fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".wal.tmp")
        try:
            os.write(fd, (data + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

        # Append temp content to WAL
        with open(tmp_path, "r", encoding="utf-8") as tmp_f:
            content = tmp_f.read()
        with self._wal_path.open("a", encoding="utf-8") as wal_f:
            wal_f.write(content)
            wal_f.flush()
            os.fsync(wal_f.fileno())

        os.unlink(tmp_path)
        self._entries_written += 1

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
