"""Tests for AuditLog and WriteAheadLog — 20 tests."""

import json
import os

import pytest

from mcp_monitor.audit.log import AuditLog
from mcp_monitor.audit.wal import WriteAheadLog


@pytest.fixture
def tmp_log(tmp_path):
    return AuditLog(str(tmp_path / "audit.log"))


@pytest.fixture
def tmp_wal(tmp_path):
    return WriteAheadLog(str(tmp_path / "audit.wal"))


# --- AuditLog hash chain tests ---


class TestAuditLog:
    def test_append_creates_entry(self, tmp_log):
        entry = tmp_log.append("test_event", {"key": "value"})
        assert entry.event_type == "test_event"
        assert entry.entry_hash != ""

    def test_chain_single_entry_valid(self, tmp_log):
        tmp_log.append("evt", {"x": 1})
        intact, broken = tmp_log.verify_chain()
        assert intact
        assert broken is None

    def test_chain_multiple_entries_valid(self, tmp_log):
        for i in range(10):
            tmp_log.append("evt", {"i": i})
        intact, broken = tmp_log.verify_chain()
        assert intact

    def test_hash_chain_tamper_detection(self, tmp_log):
        """Core test: tampering with a log entry breaks the chain."""
        for i in range(5):
            tmp_log.append("evt", {"i": i})
        # Tamper: modify entry 2's data
        tmp_log._entries[2].data = {"i": 999}
        intact, broken = tmp_log.verify_chain()
        assert not intact
        assert broken == 2

    def test_tamper_prev_hash_detected(self, tmp_log):
        for i in range(3):
            tmp_log.append("evt", {"i": i})
        tmp_log._entries[1].prev_hash = "deadbeef" * 8
        intact, broken = tmp_log.verify_chain()
        assert not intact
        assert broken == 1

    def test_prev_hash_links_entries(self, tmp_log):
        e1 = tmp_log.append("a", {})
        e2 = tmp_log.append("b", {})
        assert e2.prev_hash == e1.entry_hash

    def test_first_entry_prev_hash_is_zeros(self, tmp_log):
        entry = tmp_log.append("first", {})
        assert entry.prev_hash == "0" * 64

    def test_tail_returns_last_n(self, tmp_log):
        for i in range(20):
            tmp_log.append("evt", {"i": i})
        tail = tmp_log.tail(5)
        assert len(tail) == 5
        assert tail[-1].data == {"i": 19}

    def test_tail_fewer_than_n(self, tmp_log):
        tmp_log.append("only", {})
        tail = tmp_log.tail(10)
        assert len(tail) == 1

    def test_export_json_valid(self, tmp_log):
        tmp_log.append("evt", {"k": "v"})
        exported = tmp_log.export_json()
        parsed = json.loads(exported)
        assert len(parsed) == 1
        assert parsed[0]["event_type"] == "evt"

    def test_log_persists_to_file(self, tmp_path):
        path = str(tmp_path / "persist.log")
        log1 = AuditLog(path)
        log1.append("saved", {"x": 42})
        # Reload from same file
        log2 = AuditLog(path)
        assert len(log2) == 1
        assert log2.entries[0].data == {"x": 42}

    def test_len_reflects_entries(self, tmp_log):
        assert len(tmp_log) == 0
        tmp_log.append("a", {})
        tmp_log.append("b", {})
        assert len(tmp_log) == 2

    def test_entry_has_uuid(self, tmp_log):
        entry = tmp_log.append("evt", {})
        assert len(entry.entry_id) == 36  # UUID format


# --- WriteAheadLog tests ---


class TestWriteAheadLog:
    def test_wal_write_and_recover(self, tmp_wal, tmp_log):
        entry = tmp_log.append("evt", {"k": 1})
        tmp_wal.write(entry)
        recovered = tmp_wal.recover()
        assert len(recovered) == 1
        assert recovered[0].event_type == "evt"

    def test_wal_recovery_after_crash(self, tmp_path):
        """Core test: WAL entries survive simulated crash (no checkpoint)."""
        wal_path = str(tmp_path / "crash.wal")
        log = AuditLog(str(tmp_path / "main.log"))

        # Write entries to WAL without checkpoint
        wal1 = WriteAheadLog(wal_path)
        e1 = log.append("pre_crash_1", {"data": "important"})
        e2 = log.append("pre_crash_2", {"data": "critical"})
        wal1.write(e1)
        wal1.write(e2)
        # Simulate crash: no checkpoint called

        # New WAL instance (simulating restart)
        wal2 = WriteAheadLog(wal_path)
        recovered = wal2.recover()
        assert len(recovered) == 2
        assert recovered[0].event_type == "pre_crash_1"
        assert recovered[1].event_type == "pre_crash_2"

    def test_wal_checkpoint_clears_uncommitted(self, tmp_wal, tmp_log):
        entry = tmp_log.append("evt", {})
        tmp_wal.write(entry)
        tmp_wal.checkpoint()
        recovered = tmp_wal.recover()
        assert len(recovered) == 0

    def test_wal_partial_checkpoint(self, tmp_path):
        wal_path = str(tmp_path / "partial.wal")
        log = AuditLog(str(tmp_path / "p.log"))
        wal = WriteAheadLog(wal_path)

        e1 = log.append("committed", {})
        wal.write(e1)
        wal.checkpoint()

        e2 = log.append("uncommitted", {})
        wal.write(e2)

        recovered = wal.recover()
        assert len(recovered) == 1
        assert recovered[0].event_type == "uncommitted"

    def test_wal_truncate_removes_file(self, tmp_path):
        wal_path = str(tmp_path / "trunc.wal")
        wal = WriteAheadLog(wal_path)
        log = AuditLog(str(tmp_path / "t.log"))
        entry = log.append("x", {})
        wal.write(entry)
        wal.truncate()
        assert not os.path.exists(wal_path)

    def test_wal_recover_empty_returns_empty(self, tmp_wal):
        recovered = tmp_wal.recover()
        assert recovered == []

    def test_wal_multiple_writes(self, tmp_wal, tmp_log):
        for i in range(5):
            entry = tmp_log.append("multi", {"i": i})
            tmp_wal.write(entry)
        recovered = tmp_wal.recover()
        assert len(recovered) == 5
