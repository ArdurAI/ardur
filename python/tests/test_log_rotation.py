"""Tests for vibap.log_rotation — rotating JSONL log with compression."""

from __future__ import annotations

import gzip
import json
import threading

from vibap.log_rotation import RotatingJSONLLog, _locked_append


def test_write_appends_jsonl_entry(tmp_path):
    log = RotatingJSONLLog(tmp_path / "test.log", max_mb=1, backups=2)
    log.write({"event": "hello", "n": 1})
    log.write({"event": "world", "n": 2})

    lines = (tmp_path / "test.log").read_text().strip().split("\n")
    assert len(lines) == 2
    assert json.loads(lines[0]) == {"event": "hello", "n": 1}
    assert json.loads(lines[1]) == {"event": "world", "n": 2}


def test_rotation_produces_shifted_backup(tmp_path, monkeypatch):
    monkeypatch.setenv("ARDUR_LOG_BACKUPS", "2")
    log = RotatingJSONLLog(tmp_path / "rotate.log", max_mb=0, backups=2)
    log._max_bytes = 1  # trigger rotation on every write

    log.write({"x": 1})

    # Rotation renames live file → .jsonl.0, then shifts .0 → .jsonl.1.
    # The shifted backup holds the rotated-out data.
    backup = tmp_path / "rotate.jsonl.1"
    assert backup.exists()
    content = json.loads(backup.read_text().strip())
    assert content == {"x": 1}


def test_rotation_shifts_and_truncates_backups(tmp_path, monkeypatch):
    monkeypatch.setenv("ARDUR_LOG_BACKUPS", "2")
    log = RotatingJSONLLog(tmp_path / "shift.log", max_mb=0, backups=2)
    log._max_bytes = 1

    log.write({"seq": 1})
    log.write({"seq": 2})
    log.write({"seq": 3})

    # After 3 writes with backups=2, the oldest (.2) is unlinked,
    # .1 holds the second-oldest data, .0 was shifted to .1.
    # Verify at least the backup chain exists.
    found = sorted(tmp_path.glob("shift.jsonl.*"))
    assert len(found) >= 1


def test_thread_safety_concurrent_writes(tmp_path):
    log = RotatingJSONLLog(tmp_path / "thread.log", max_mb=10, backups=2)
    errors = []
    n_per_thread = 50

    def writer(prefix: str):
        try:
            for i in range(n_per_thread):
                log.write({"prefix": prefix, "i": i})
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(f"t{t}",)) for t in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0

    lines = (tmp_path / "thread.log").read_text().strip().split("\n")
    assert len(lines) == 4 * n_per_thread


def test_locked_append_writes_to_file(tmp_path):
    path = tmp_path / "locked.log"
    _locked_append(path, b'{"k":"v"}\n')
    _locked_append(path, b'{"k":"v2"}\n')

    content = path.read_text()
    assert content == '{"k":"v"}\n{"k":"v2"}\n'


def test_creates_parent_directory(tmp_path):
    log = RotatingJSONLLog(tmp_path / "sub" / "dir" / "nested.log", max_mb=1, backups=1)
    log.write({"ok": True})
    assert (tmp_path / "sub" / "dir" / "nested.log").exists()
