"""File-backed PolicyStore that persists to Ardur's state directory.

Sits alongside session state so that policies seeded by `ardur protect
claude-code` survive proxy restarts and are consumed at session-start
time. Uses atomic writes (write-to-tmp + os.replace) for crash safety.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from vibap.policy_store import PolicySpec


class FileBackedPolicyStore:
    """PolicyStore backed by a JSON file in the Ardur state directory.

    File format::

        {"mission_id": [{"backend": "cedar", ...}, ...], ...}

    Thread-safe. Policies with an empty-string mission_id are matched
    against any mission_id that has no explicit entry.
    """

    def __init__(self, state_dir: Path) -> None:
        self._path = state_dir / "policies.json"
        self._lock = threading.Lock()
        self._cache: dict[str, list[dict[str, Any]]] | None = None

    def _load(self) -> dict[str, list[dict[str, Any]]]:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text("utf-8"))
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save(self, data: dict[str, Any]) -> None:
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), "utf-8")
        os.replace(tmp, self._path)

    # ------------------------------------------------------------------
    # PolicyStore protocol
    # ------------------------------------------------------------------

    def get_policies(
        self, *, mission_id: str, agent_id: str | None = None
    ) -> list[PolicySpec] | None:
        with self._lock:
            if self._cache is None:
                self._cache = self._load()
            if mission_id in self._cache:
                return [dict(spec) for spec in self._cache[mission_id]]
            if "" in self._cache:
                return [dict(spec) for spec in self._cache[""]]
            return None

    def put_policies(
        self,
        *,
        mission_id: str,
        policies: list[PolicySpec],
        agent_id: str | None = None,
    ) -> None:
        with self._lock:
            if self._cache is None:
                self._cache = self._load()
            self._cache[mission_id] = [dict(spec) for spec in policies]
            self._save(self._cache)
