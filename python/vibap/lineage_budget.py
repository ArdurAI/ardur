"""Lineage-wide budget reservation ledger.

The proxy stores a denormalized ``delegated_budget_reserved`` counter on each
session for hot-path policy checks. This module is the durable reservation
ledger behind that counter: it gives sibling delegations a transactional place
to reserve child budgets and makes duplicate client retries idempotent.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import threading
import uuid
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class LineageBudgetConflictError(ValueError):
    """Raised when a duplicate reservation id carries different semantics."""


@dataclass(frozen=True)
class ReservationResult:
    accepted: bool
    parent_jti: str
    request_id: str
    amount: int
    reserved_total: int
    remaining_before: int
    remaining_after: int
    idempotent: bool = False


@dataclass(frozen=True)
class ReleaseResult:
    """Result of :meth:`LineageBudgetLedger.release_reservation` or
    :meth:`LineageBudgetLedger.reject`. ``operation`` is ``"release"`` or
    ``"reject"`` matching the schema's ``lineageBudgetDelta.operation`` enum."""

    parent_jti: str
    request_id: str
    amount: int
    reserved_total: int  # post-operation
    operation: str
    idempotent: bool = False


class LineageBudgetLedger:
    """Abstract lineage budget reservation ledger."""

    def reservation(self, parent_jti: str, request_id: str) -> dict[str, Any] | None:
        raise NotImplementedError

    def reserved_total(self, parent_jti: str, *, floor_reserved_total: int = 0) -> int:
        raise NotImplementedError

    def reserve(
        self,
        *,
        parent_jti: str,
        request_id: str,
        amount: int,
        ceiling: int,
        used_total: int,
        child_agent_id: str | None = None,
        child_jti: str | None = None,
        floor_reserved_total: int = 0,
    ) -> ReservationResult:
        raise NotImplementedError

    def release_reservation(
        self, *, parent_jti: str, request_id: str
    ) -> ReleaseResult:
        """Return a previously-held reservation to the parent's available pool.

        Use when a child delegation was prepared (budget reserved) but the
        child either never ran or completed without consuming its budget.
        Raises ``ValueError`` if the ``request_id`` was never reserved.
        Idempotent when called twice on the same ``request_id`` after the
        first call — second call returns ``idempotent=True``.
        """
        raise NotImplementedError

    def reject(
        self, *, parent_jti: str, request_id: str
    ) -> ReleaseResult:
        """Record that a reservation was rejected (child denied / failed).

        Budget is returned to the parent pool, same as :meth:`release_reservation`,
        but the ledger records the rejection separately so audit trails can
        distinguish "child didn't need it" from "child was denied".
        """
        raise NotImplementedError

    def snapshot(self, parent_jti: str) -> dict[str, Any]:
        raise NotImplementedError


class _ProcessLock:
    __slots__ = ("lock", "__weakref__")

    def __init__(self) -> None:
        self.lock = threading.RLock()


_LOCKS: weakref.WeakValueDictionary[str, _ProcessLock] = weakref.WeakValueDictionary()
_LOCKS_GUARD = threading.Lock()


class FileLineageBudgetLedger(LineageBudgetLedger):
    """File-backed lineage budget ledger rooted under a proxy ``state_dir``."""

    def __init__(self, state_dir: str | Path) -> None:
        self.state_dir = Path(state_dir).expanduser()
        self.ledger_dir = self.state_dir / "lineage_budgets"
        self.ledger_dir.mkdir(parents=True, exist_ok=True)

    def reserved_total(self, parent_jti: str, *, floor_reserved_total: int = 0) -> int:
        with self._locked(parent_jti):
            payload = self._load(parent_jti)
            return max(int(payload.get("reserved_total", 0)), int(floor_reserved_total))

    def reservation(self, parent_jti: str, request_id: str) -> dict[str, Any] | None:
        with self._locked(parent_jti):
            payload = self._load(parent_jti)
            reservations = payload.get("reservations", {})
            if not isinstance(reservations, dict):
                raise ValueError("ledger reservations must be a JSON object")
            existing = reservations.get(request_id)
            return dict(existing) if isinstance(existing, dict) else None

    def reserve(
        self,
        *,
        parent_jti: str,
        request_id: str,
        amount: int,
        ceiling: int,
        used_total: int,
        child_agent_id: str | None = None,
        child_jti: str | None = None,
        floor_reserved_total: int = 0,
    ) -> ReservationResult:
        if not request_id or not isinstance(request_id, str):
            raise ValueError("delegation_request_id must be a non-empty string")
        if amount < 0:
            raise ValueError("reservation amount must be non-negative")
        if ceiling < 0 or used_total < 0:
            raise ValueError("budget ceiling and used total must be non-negative")

        with self._locked(parent_jti):
            payload = self._load(parent_jti)
            reserved_total = max(
                int(payload.get("reserved_total", 0)),
                int(floor_reserved_total),
            )
            reservations = payload.setdefault("reservations", {})
            if not isinstance(reservations, dict):
                raise ValueError("ledger reservations must be a JSON object")

            existing = reservations.get(request_id)
            remaining_before = max(0, int(ceiling) - int(used_total) - reserved_total)
            if existing is not None:
                expected = {
                    "amount": int(amount),
                    "child_agent_id": child_agent_id,
                }
                actual = {
                    "amount": int(existing.get("amount", -1)),
                    "child_agent_id": existing.get("child_agent_id"),
                }
                if actual != expected:
                    raise LineageBudgetConflictError(
                        "delegation_request_id already used for a different reservation"
                    )
                return ReservationResult(
                    accepted=True,
                    parent_jti=parent_jti,
                    request_id=request_id,
                    amount=int(existing["amount"]),
                    reserved_total=reserved_total,
                    remaining_before=remaining_before,
                    remaining_after=remaining_before,
                    idempotent=True,
                )

            if amount > remaining_before:
                return ReservationResult(
                    accepted=False,
                    parent_jti=parent_jti,
                    request_id=request_id,
                    amount=amount,
                    reserved_total=reserved_total,
                    remaining_before=remaining_before,
                    remaining_after=remaining_before,
                )

            reserved_total += amount
            reservations[request_id] = {
                "amount": amount,
                "child_agent_id": child_agent_id,
                "child_jti": child_jti,
            }
            payload["reserved_total"] = reserved_total
            self._persist(parent_jti, payload)
            return ReservationResult(
                accepted=True,
                parent_jti=parent_jti,
                request_id=request_id,
                amount=amount,
                reserved_total=reserved_total,
                remaining_before=remaining_before,
                remaining_after=max(0, remaining_before - amount),
            )

    def release_reservation(
        self, *, parent_jti: str, request_id: str
    ) -> ReleaseResult:
        return self._close_reservation(
            parent_jti=parent_jti,
            request_id=request_id,
            operation="release",
        )

    def reject(
        self, *, parent_jti: str, request_id: str
    ) -> ReleaseResult:
        return self._close_reservation(
            parent_jti=parent_jti,
            request_id=request_id,
            operation="reject",
        )

    def _close_reservation(
        self,
        *,
        parent_jti: str,
        request_id: str,
        operation: str,
    ) -> ReleaseResult:
        if operation not in {"release", "reject"}:
            raise ValueError(f"unsupported close operation: {operation!r}")
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("request_id must be a non-empty string")

        with self._locked(parent_jti):
            payload = self._load(parent_jti)
            reservations = payload.setdefault("reservations", {})
            closed = payload.setdefault("closed_reservations", {})
            if not isinstance(reservations, dict) or not isinstance(closed, dict):
                raise ValueError(
                    "ledger reservations/closed_reservations must be JSON objects"
                )

            # Idempotent re-close: same request_id, same operation → no-op.
            prior = closed.get(request_id)
            if isinstance(prior, dict):
                if prior.get("operation") != operation:
                    raise LineageBudgetConflictError(
                        f"request_id {request_id!r} already closed as "
                        f"{prior.get('operation')!r}, cannot re-close as {operation!r}"
                    )
                return ReleaseResult(
                    parent_jti=parent_jti,
                    request_id=request_id,
                    amount=int(prior.get("amount", 0)),
                    reserved_total=int(payload.get("reserved_total", 0)),
                    operation=operation,
                    idempotent=True,
                )

            active = reservations.get(request_id)
            if not isinstance(active, dict):
                raise ValueError(
                    f"no active reservation for request_id={request_id!r}"
                )

            amount = int(active.get("amount", 0))
            reserved_total = max(
                0, int(payload.get("reserved_total", 0)) - amount
            )
            del reservations[request_id]
            closed[request_id] = {
                "operation": operation,
                "amount": amount,
                "child_agent_id": active.get("child_agent_id"),
                "child_jti": active.get("child_jti"),
            }
            payload["reserved_total"] = reserved_total
            self._persist(parent_jti, payload)
            return ReleaseResult(
                parent_jti=parent_jti,
                request_id=request_id,
                amount=amount,
                reserved_total=reserved_total,
                operation=operation,
            )

    def snapshot(self, parent_jti: str) -> dict[str, Any]:
        with self._locked(parent_jti):
            return self._load(parent_jti)

    def _path(self, parent_jti: str) -> Path:
        digest = hashlib.sha256(parent_jti.encode("utf-8")).hexdigest()
        return self.ledger_dir / f"{digest}.json"

    def _lock_path(self, parent_jti: str) -> Path:
        return self._path(parent_jti).with_suffix(".lock")

    @contextlib.contextmanager
    def _locked(self, parent_jti: str):
        lock_path = self._lock_path(parent_jti)
        lock_path.touch(exist_ok=True)
        key = str(lock_path.resolve())
        with _LOCKS_GUARD:
            process_lock = _LOCKS.get(key)
            if process_lock is None:
                process_lock = _ProcessLock()
                _LOCKS[key] = process_lock
        with process_lock.lock:
            with lock_path.open("a+b") as lock_handle:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    def _load(self, parent_jti: str) -> dict[str, Any]:
        path = self._path(parent_jti)
        if not path.exists():
            return {
                "version": 1,
                "parent_jti": parent_jti,
                "reserved_total": 0,
                "reservations": {},
                "closed_reservations": {},
            }
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("lineage budget ledger must contain a JSON object")
        payload.setdefault("version", 1)
        payload.setdefault("parent_jti", parent_jti)
        payload.setdefault("reserved_total", 0)
        payload.setdefault("reservations", {})
        payload.setdefault("closed_reservations", {})
        return payload

    def _persist(self, parent_jti: str, payload: dict[str, Any]) -> None:
        path = self._path(parent_jti)
        tmp = path.with_name(f"{path.stem}.{uuid.uuid4().hex}.tmp")
        try:
            tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            os.replace(tmp, path)
        except Exception:
            with contextlib.suppress(OSError):
                tmp.unlink()
            raise
