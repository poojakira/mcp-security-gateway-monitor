"""SHA-256 hash-chained immutable audit log.

Every MCP tool-call decision is recorded as an AuditEntry whose hash depends
on the previous entry's hash, creating a tamper-evident chain. If any
historical entry is modified, ``verify_chain()`` reports the first broken
index.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AuditEntry:
    """Single entry in the hash-chained audit log."""

    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    event_type: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    entry_hash: str = ""

    def compute_hash(self) -> str:
        """Compute SHA-256 hash from prev_hash + timestamp + event_type + data."""
        content = (
            str(self.prev_hash)
            + str(self.timestamp)
            + str(self.event_type)
            + str(self.data)
        )
        return hashlib.sha256(content.encode("utf-8")).hexdigest()


class AuditLog:
    """SHA-256 hash-chained immutable audit log."""

    def __init__(self, log_file: str) -> None:
        self._log_file = Path(log_file)
        self._entries: list[AuditEntry] = []
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(self, event_type: str, data: dict[str, Any]) -> AuditEntry:
        """Append a new entry to the log, chaining its hash to the previous."""
        prev_hash = self._entries[-1].entry_hash if self._entries else "0" * 64

        entry = AuditEntry(
            event_type=event_type,
            data=data,
            prev_hash=prev_hash,
        )
        entry.entry_hash = entry.compute_hash()
        self._entries.append(entry)
        self._persist(entry)
        return entry

    def verify_chain(self) -> tuple[bool, int | None]:
        """Verify integrity of the full hash chain.

        Returns
        -------
        tuple of (intact: bool, broken_at_index: int | None)
            If intact is False, broken_at_index is the first index whose
            hash does not match the expected value.
        """
        for i, entry in enumerate(self._entries):
            expected_prev = (
                self._entries[i - 1].entry_hash if i > 0 else "0" * 64
            )
            if entry.prev_hash != expected_prev:
                return (False, i)
            expected_hash = entry.compute_hash()
            if entry.entry_hash != expected_hash:
                return (False, i)
        return (True, None)

    def tail(self, n: int = 10) -> list[AuditEntry]:
        """Return the last *n* entries."""
        return self._entries[-n:]

    def export_json(self) -> str:
        """Export the full log as a JSON string."""
        return json.dumps(
            [asdict(entry) for entry in self._entries], indent=2
        )

    @property
    def entries(self) -> list[AuditEntry]:
        """Read-only access to all entries."""
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _persist(self, entry: AuditEntry) -> None:
        """Append a single entry to the log file."""
        self._log_file.parent.mkdir(parents=True, exist_ok=True)
        with self._log_file.open("a", encoding="utf-8") as f:
            f.write(self._serialize_entry(entry) + "\n")

    @staticmethod
    def _serialize_entry(entry: AuditEntry) -> str:
        """Serialize an entry to a JSON line, never crashing on malformed data.

        Arbitrary tool-call data may contain non-JSON-serializable values
        (bytes, sets, custom objects), non-string dict keys, or even circular
        references. Since the audit path sits inline with every decision, a
        serialization failure here would be a denial-of-service. We therefore
        fall back to a repr of the offending payload rather than raising.

        Note: ``dataclasses.asdict`` is intentionally avoided because it deep
        copies recursively and would raise ``RecursionError`` on a cyclic
        ``data`` payload before serialization even begins.
        """
        record: dict[str, Any] = {
            "entry_id": entry.entry_id,
            "timestamp": entry.timestamp,
            "event_type": entry.event_type,
            "data": entry.data,
            "prev_hash": entry.prev_hash,
            "entry_hash": entry.entry_hash,
        }
        try:
            return json.dumps(record, default=str)
        except (TypeError, ValueError, RecursionError):
            try:
                data_repr = repr(entry.data)
            except Exception:
                data_repr = "<unrepresentable audit data>"
            record["data"] = {"_unserializable_repr": data_repr}
            return json.dumps(record, default=str)

    def _load(self) -> None:
        """Load existing entries from the log file."""
        if not self._log_file.exists():
            return
        with self._log_file.open("r", encoding="utf-8") as f:
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
                self._entries.append(entry)
