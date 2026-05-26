"""Rotating JSONL log for governance and receipt logs."""

from __future__ import annotations

import fcntl
import gzip
import json
import os
import shutil
import threading
from pathlib import Path


class RotatingJSONLLog:
    """Thread-safe rotating JSONL log with max-size rotation and gz compression.

    Configurable via environment variables:
      ARDUR_LOG_MAX_MB   — max file size in MB before rotation (default 100)
      ARDUR_LOG_BACKUPS  — number of compressed backup files to keep (default 5)
    """

    def __init__(
        self,
        log_path: str | Path,
        max_mb: int | None = None,
        backups: int | None = None,
    ):
        self._path = Path(log_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._max_bytes = (max_mb or int(os.environ.get("ARDUR_LOG_MAX_MB", "100"))) * 1024 * 1024
        self._backups = backups or int(os.environ.get("ARDUR_LOG_BACKUPS", "5"))
        self._lock = threading.Lock()

    def write(self, entry: dict) -> None:
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        with self._lock:
            _locked_append(self._path, line.encode("utf-8"))
            if self._path.stat().st_size > self._max_bytes:
                self._rotate_locked()

    def _rotate_locked(self) -> None:
        self._path.rename(self._path.with_suffix(".jsonl.0"))
        # Shift existing backups
        for i in range(self._backups - 1, -1, -1):
            src = self._path.with_suffix(f".jsonl.{i}")
            if src.exists():
                if i >= self._backups - 1:
                    src.unlink()
                else:
                    src.rename(self._path.with_suffix(f".jsonl.{i + 1}"))
        # Compress the oldest
        oldest = self._path.with_suffix(".jsonl.0")
        if oldest.exists():
            gz_path = oldest.with_suffix(".jsonl.0.gz")
            with open(oldest, "rb") as fin, gzip.open(gz_path, "wb") as fout:
                shutil.copyfileobj(fin, fout)
            oldest.unlink()


def _locked_append(path: Path, data: bytes) -> None:
    with open(path, "ab") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        try:
            fh.write(data)
            fh.flush()
        finally:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
