"""SHA-256 hash-chained immutable audit log.

Every MCP tool-call decision is recorded as an AuditEntry whose hash depends
on the previous entry's hash, creating a tamper-evident chain. If any
historical entry is modified, ``verify_chain()`` reports the first broken
index.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Optional server-side key. When set, entry hashes are HMAC-SHA256 keyed, so an
# attacker with only filesystem access cannot recompute a self-consistent chain
# (plain SHA-256 can be fully re-forged by anyone who can write the file).
# Unset -> plain SHA-256 (backwards compatible with existing logs).
_HMAC_KEY = os.environ.get("MCP_AUDIT_HMAC_KEY")


def _digest(content: str) -> str:
    """Keyed (HMAC) or plain SHA-256 hex digest for *content*."""
    data = content.encode("utf-8")
    if _HMAC_KEY:
        return hmac.new(_HMAC_KEY.encode("utf-8"), data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


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
        """Compute the (optionally HMAC-keyed) chain hash for this entry."""
        content = (
            self.prev_hash
            + str(self.timestamp)
            + self.event_type
            + str(self.data)
        )
        return _digest(content)


class AuditLog:
    """SHA-256 hash-chained immutable audit log."""

    def __init__(self, log_file: str) -> None:
        self._log_file = Path(log_file)
        # Append-only anchor of (count, tip_hash). On load we check the chain's
        # tip against the last anchor to detect wholesale replacement/rollback
        # even when the attacker recomputed internal hashes. For true external
        # anchoring set MCP_AUDIT_ANCHOR_CMD to a command that publishes the tip
        # to a write-once store (AWS QLDB / S3 Object-Lock / a transparency log).
        self._anchor_file = self._log_file.with_suffix(
            self._log_file.suffix + ".anchor"
        )
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
        self._write_anchor(len(self._entries), entry.entry_hash)
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
        """Append a single entry to the log file, durably (flush + fsync)."""
        self._log_file.parent.mkdir(parents=True, exist_ok=True)
        with self._log_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry)) + "\n")
            # Ensure the tamper-evident entry hits disk before we proceed, so a
            # crash immediately after append cannot lose the last record.
            f.flush()
            os.fsync(f.fileno())

        # Optionally mirror to stdout as structured JSON so a cluster log
        # aggregator persists the audit trail off-pod. On ephemeral storage
        # (k8s emptyDir) the on-disk file is lost on restart; stdout shipping is
        # what actually preserves the trail. Enable with MCP_AUDIT_STDOUT=1.
        if os.environ.get("MCP_AUDIT_STDOUT", "").lower() in ("1", "true", "yes"):
            print(json.dumps({"audit_entry": asdict(entry)}), flush=True)

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

        # Verify the hash chain immediately after loading. A tampered or
        # truncated on-disk log must raise a loud alert at startup rather than
        # being trusted silently until someone happens to call verify_chain().
        intact, broken_at = self.verify_chain()
        if not intact:
            log.critical(
                "AUDIT LOG INTEGRITY FAILURE: hash chain broken at index %s in %s",
                broken_at,
                self._log_file,
            )

        # Cross-check the tip against the external/append-only anchor to catch
        # rollback or wholesale chain replacement (where internal hashes were
        # recomputed to look self-consistent).
        self._verify_against_anchor()

    def _write_anchor(self, count: int, tip_hash: str) -> None:
        """Record and (optionally) externally publish the current chain tip."""
        record = {"count": count, "tip": tip_hash, "ts": time.time()}
        try:
            self._anchor_file.parent.mkdir(parents=True, exist_ok=True)
            with self._anchor_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:  # pragma: no cover - IO dependent
            log.error("Failed to write audit anchor: %s", e)

        # Optional external anchoring to a write-once store.
        cmd = os.environ.get("MCP_AUDIT_ANCHOR_CMD")
        if cmd:
            try:
                subprocess.run(
                    [cmd, str(count), tip_hash],
                    check=True,
                    timeout=10,
                    capture_output=True,
                )
            except Exception as e:  # pragma: no cover - env dependent
                log.error("External audit anchor publish failed: %s", e)

    def _verify_against_anchor(self) -> None:
        """Alert if the loaded chain contradicts the last recorded anchor."""
        if not self._anchor_file.exists():
            return
        last = None
        try:
            with self._anchor_file.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last = json.loads(line)
        except (OSError, json.JSONDecodeError) as e:  # pragma: no cover
            log.error("Failed to read audit anchor: %s", e)
            return
        if not last:
            return

        anchored_count = int(last.get("count", 0))
        anchored_tip = last.get("tip", "")
        if len(self._entries) < anchored_count:
            log.critical(
                "AUDIT LOG ROLLBACK: on-disk has %d entries but anchor recorded "
                "%d (entries were removed) in %s",
                len(self._entries),
                anchored_count,
                self._log_file,
            )
            return
        if 0 < anchored_count <= len(self._entries):
            actual_tip = self._entries[anchored_count - 1].entry_hash
            if actual_tip != anchored_tip:
                log.critical(
                    "AUDIT LOG REPLACED: tip at index %d does not match anchor "
                    "in %s (chain was rewritten)",
                    anchored_count - 1,
                    self._log_file,
                )
