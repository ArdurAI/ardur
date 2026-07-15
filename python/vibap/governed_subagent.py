"""Framework-neutral governed subagent lifecycle adapter.

The adapter deliberately does not own credential or policy authority.  It
coordinates opaque, parent-bound handles with :class:`GovernanceProxy`, which
remains responsible for passport derivation, lineage budgets, signed receipts,
session persistence, and attestations.

Framework checkpoints may persist an opaque handle and their own result.  They
must never persist the child passport or treat a checkpoint as authority.  A
duplicate operation is therefore suppressed instead of re-executed; the
framework recovers the earlier result from its checkpoint.
"""

from __future__ import annotations

import base64
import contextlib
import copy
import fcntl
import hashlib
import json
import math
import os
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric import ec

from .proxy import Decision, GovernanceProxy, GovernanceSession


STATE_SCHEMA = "ardur.governed_subagent.state.v1"
HANDLE_PREFIX = "ardur_child_"
HANDLE_ENTROPY_BYTES = 32
MAX_STATE_BYTES = 8 * 1024 * 1024
MAX_HANDLE_RECORDS = 4096
MAX_OPERATIONS_PER_HANDLE = 1024
MAX_ARGUMENT_BYTES = 256 * 1024
MAX_RESULT_BYTES = 256 * 1024
MAX_RESULT_ITEMS = 4096
MAX_RESULT_DEPTH = 16
MAX_REQUEST_ID_BYTES = 256
MAX_AGENT_ID_BYTES = 256
MAX_MISSION_BYTES = 4096
MAX_TOOL_NAME_BYTES = 256
MAX_SCOPE_PATTERN_BYTES = 2048
MAX_TOOL_COUNT = 256
MAX_SCOPE_COUNT = 256
MIN_OPERATION_LEASE_S = 1.0
MAX_OPERATION_LEASE_S = 24 * 60 * 60.0
DEFAULT_OPERATION_LEASE_S = 5 * 60.0

_HANDLE_RE = re.compile(r"^ardur_child_[A-Za-z0-9_-]{43}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_INFLIGHT_OPERATION_STATES = frozenset({"evaluating", "authorized", "executing"})
_TERMINAL_HANDLE_STATES = frozenset({"closed", "cancelled", "expired"})
_HANDLE_STATES = frozenset(
    {"spawning", "active", "quarantined", "closing"} | _TERMINAL_HANDLE_STATES
)
_OPERATION_STATES = frozenset(
    _INFLIGHT_OPERATION_STATES | {"denied", "completed", "uncertain"}
)
_SENSITIVE_EVIDENCE_KEYS = frozenset(
    {
        "attestation_token",
        "child_token",
        "passport_token",
        "private_key",
        "token",
    }
)

# This registry coordinates threads that open the same flock file.  It carries
# no authority or lifecycle state; all durable truth stays in the locked JSON
# file.  A process-local mutex is still required because flock semantics alone
# do not provide a portable thread-level critical section for separately opened
# descriptors in one process.
_PROCESS_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, threading.RLock] = {}


class GovernedSubagentError(PermissionError):
    """A bounded, fail-closed governed-subagent error."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class GovernedSubagentConflictError(GovernedSubagentError):
    """A stable id was reused with different semantics."""


@dataclass(frozen=True)
class GovernedSubagentHandle:
    """Opaque framework-safe reference to one governed child lifecycle."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        _validate_handle_text(self.value)

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return "GovernedSubagentHandle(<opaque>)"


@dataclass(frozen=True)
class GovernedSubagentRequest:
    """Explicit attenuated child request.

    ``spend_cap`` and ``risk_cap`` are reserved integration points.  The
    adapter rejects non-``None`` values until their signed policy surfaces are
    present on the runtime it is built against; it never silently ignores a
    requested cap.
    """

    request_id: str
    child_agent_id: str
    mission: str
    allowed_tools: Sequence[str]
    resource_scope: Sequence[str]
    max_tool_calls: int
    ttl_s: int
    spend_cap: Mapping[str, Any] | None = None
    risk_cap: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        request_id = _bounded_text(
            "request_id", self.request_id, max_bytes=MAX_REQUEST_ID_BYTES
        )
        child_agent_id = _bounded_text(
            "child_agent_id", self.child_agent_id, max_bytes=MAX_AGENT_ID_BYTES
        )
        mission = _bounded_text("mission", self.mission, max_bytes=MAX_MISSION_BYTES)
        allowed_tools = _normalized_string_sequence(
            "allowed_tools",
            self.allowed_tools,
            max_items=MAX_TOOL_COUNT,
            max_item_bytes=MAX_TOOL_NAME_BYTES,
            require_non_empty=True,
        )
        resource_scope = _normalized_string_sequence(
            "resource_scope",
            self.resource_scope,
            max_items=MAX_SCOPE_COUNT,
            max_item_bytes=MAX_SCOPE_PATTERN_BYTES,
            require_non_empty=False,
        )
        if isinstance(self.max_tool_calls, bool) or not isinstance(
            self.max_tool_calls, int
        ):
            raise TypeError("max_tool_calls must be an integer")
        if self.max_tool_calls <= 0:
            raise ValueError("max_tool_calls must be positive")
        if isinstance(self.ttl_s, bool) or not isinstance(self.ttl_s, int):
            raise TypeError("ttl_s must be an integer")
        if self.ttl_s <= 0:
            raise ValueError("ttl_s must be positive")
        if self.spend_cap is not None and not isinstance(self.spend_cap, Mapping):
            raise TypeError("spend_cap must be an object when provided")
        if self.risk_cap is not None and not isinstance(self.risk_cap, Mapping):
            raise TypeError("risk_cap must be an object when provided")
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "child_agent_id", child_agent_id)
        object.__setattr__(self, "mission", mission)
        object.__setattr__(self, "allowed_tools", allowed_tools)
        object.__setattr__(self, "resource_scope", resource_scope)
        if self.spend_cap is not None:
            object.__setattr__(self, "spend_cap", copy.deepcopy(dict(self.spend_cap)))
        if self.risk_cap is not None:
            object.__setattr__(self, "risk_cap", copy.deepcopy(dict(self.risk_cap)))


@dataclass(frozen=True)
class GovernedToolResult:
    """Outcome of one child tool operation.

    ``value`` is never persisted by the adapter.  For a replay-suppressed
    result it is ``None`` and the framework must recover the prior value from
    its own checkpoint.
    """

    status: str
    decision: Decision | None
    reason: str
    executed: bool
    value: Any = field(default=None, repr=False)
    receipt_id: str | None = None
    result_sha256: str | None = None


@dataclass(frozen=True)
class GovernedSubagentCloseResult:
    """Credential-free result of monotonic child closure."""

    status: str
    attestation_id: str
    attestation_sha256: str
    idempotent: bool


@dataclass(frozen=True)
class GovernedSubagentRecovery:
    """Summary of conservative local-state recovery."""

    expired_handles: int
    quarantined_handles: int
    interrupted_operations: int


def _bounded_text(name: str, value: Any, *, max_bytes: int) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if not value or not value.strip():
        raise ValueError(f"{name} must be non-empty")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must be valid UTF-8") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{name} exceeds {max_bytes} bytes")
    if any(ord(character) < 0x20 for character in value):
        raise ValueError(f"{name} must not contain control characters")
    return value


def _normalized_string_sequence(
    name: str,
    values: Sequence[str],
    *,
    max_items: int,
    max_item_bytes: int,
    require_non_empty: bool,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise TypeError(f"{name} must be a sequence of strings")
    if len(values) > max_items:
        raise ValueError(f"{name} exceeds {max_items} entries")
    normalized = tuple(
        sorted(
            {
                _bounded_text(f"{name} entry", item, max_bytes=max_item_bytes)
                for item in values
            }
        )
    )
    if require_non_empty and not normalized:
        raise ValueError(f"{name} must be non-empty")
    return normalized


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("value must be bounded JSON data") from exc


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _validate_handle_text(value: Any) -> str:
    if not isinstance(value, str) or not _HANDLE_RE.fullmatch(value):
        raise GovernedSubagentError("HANDLE_INVALID", "child handle is malformed")
    return value


def _handle_text(handle: GovernedSubagentHandle | str) -> str:
    if isinstance(handle, GovernedSubagentHandle):
        return handle.value
    return _validate_handle_text(handle)


def _new_handle() -> str:
    encoded = base64.urlsafe_b64encode(secrets.token_bytes(HANDLE_ENTROPY_BYTES))
    return HANDLE_PREFIX + encoded.rstrip(b"=").decode("ascii")


def _is_hex_digest(value: Any, *, length: int = 64) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_finite_number(value: Any, *, positive: bool = False) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        number = float(value)
    except (OverflowError, ValueError):
        return False
    return math.isfinite(number) and (not positive or number > 0)


def _process_lock(path: Path) -> threading.RLock:
    key = str(path.resolve())
    with _PROCESS_LOCKS_GUARD:
        lock = _PROCESS_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _PROCESS_LOCKS[key] = lock
        return lock


def _redact_authority(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _redact_authority(item)
            for key, item in value.items()
            if str(key).lower() not in _SENSITIVE_EVIDENCE_KEYS
        }
    if isinstance(value, list):
        return [_redact_authority(item) for item in value]
    return copy.deepcopy(value)


class GovernedSubagentAdapter:
    """Durable parent-bound child lifecycle coordinator.

    Create one adapter per parent invocation and pass it through explicit
    dependency injection or immutable framework runtime context.  Do not place
    the adapter object, signer, or proxy session in framework state.
    """

    def __init__(
        self,
        *,
        proxy: GovernanceProxy,
        parent_session: GovernanceSession | str,
        delegation_private_key: ec.EllipticCurvePrivateKey,
        state_dir: str | Path | None = None,
        operation_lease_s: float = DEFAULT_OPERATION_LEASE_S,
    ) -> None:
        if not isinstance(proxy, GovernanceProxy):
            raise TypeError("proxy must be a GovernanceProxy")
        if not isinstance(delegation_private_key, ec.EllipticCurvePrivateKey):
            raise TypeError("delegation_private_key must be an EC private key")
        if isinstance(operation_lease_s, bool) or not isinstance(
            operation_lease_s, (int, float)
        ):
            raise TypeError("operation_lease_s must be numeric")
        operation_lease = float(operation_lease_s)
        if not MIN_OPERATION_LEASE_S <= operation_lease <= MAX_OPERATION_LEASE_S:
            raise ValueError(
                f"operation_lease_s must be between {MIN_OPERATION_LEASE_S:g} "
                f"and {MAX_OPERATION_LEASE_S:g} seconds"
            )

        parent_id = (
            parent_session.jti
            if isinstance(parent_session, GovernanceSession)
            else parent_session
        )
        if not isinstance(parent_id, str) or not _UUID_RE.fullmatch(parent_id):
            raise ValueError("parent session ID must be a UUID")

        self.proxy = proxy
        self.parent_session_id = parent_id
        self._delegation_private_key = delegation_private_key
        self._operation_lease_s = operation_lease
        self._instance_id = uuid.uuid4().hex
        self._state_dir = (
            Path(state_dir).expanduser()
            if state_dir is not None
            else proxy.state_dir / "governed_subagents"
        )
        proxy._ensure_private_state_directory(
            self._state_dir, label="governed subagent state_dir"
        )
        self._state_path = self._state_dir / "state.json"
        self._lock_path = self._state_dir / "state.lock"
        self._ensure_private_lock_file()
        self._assert_parent_active()
        # Validate existing state and conservatively recover only expired
        # leases.  A newly constructed adapter may coexist with a live adapter,
        # so unexpired in-flight operations remain busy rather than being
        # mistaken for a process crash.
        self.recover()

    @property
    def state_path(self) -> Path:
        """Private adapter state path, primarily for operator diagnostics."""

        return self._state_path

    def _ensure_private_lock_file(self) -> None:
        fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        os.close(fd)
        self._lock_path.chmod(0o600)

    @contextlib.contextmanager
    def _state_transaction(self):
        process_lock = _process_lock(self._lock_path)
        with process_lock:
            with self._lock_path.open("a+b") as lock_handle:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                state = self._load_state_locked()
                before = _canonical_json(state)
                try:
                    yield state
                finally:
                    after = _canonical_json(state)
                    if after != before:
                        self._persist_state_locked(state, encoded=after)
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    def _load_state_locked(self) -> dict[str, Any]:
        if not self._state_path.exists():
            return {
                "schema": STATE_SCHEMA,
                "handles": {},
                "requests": {},
            }
        try:
            size = self._state_path.stat().st_size
            if size <= 0 or size > MAX_STATE_BYTES:
                raise ValueError("state file size is invalid")
            payload = json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise GovernedSubagentError(
                "STATE_UNAVAILABLE", "governed subagent state is unavailable"
            ) from exc
        self._validate_state(payload)
        return payload

    def _validate_state(self, payload: Any) -> None:
        if (
            not isinstance(payload, dict)
            or set(payload) != {"schema", "handles", "requests"}
            or payload.get("schema") != STATE_SCHEMA
        ):
            raise GovernedSubagentError(
                "STATE_UNAVAILABLE", "governed subagent state schema is invalid"
            )
        handles = payload.get("handles")
        requests = payload.get("requests")
        if not isinstance(handles, dict) or not isinstance(requests, dict):
            raise GovernedSubagentError(
                "STATE_UNAVAILABLE", "governed subagent indexes are invalid"
            )
        if len(handles) > MAX_HANDLE_RECORDS or len(requests) > MAX_HANDLE_RECORDS:
            raise GovernedSubagentError(
                "STATE_CAPACITY", "governed subagent state exceeds its record bound"
            )
        record_fields = {
            "handle",
            "parent_jti",
            "child_jti",
            "request_key",
            "request_fingerprint",
            "status",
            "created_at",
            "expires_at",
            "operations",
            "terminal_code",
            "closed_at",
            "attestation_id",
            "attestation_sha256",
            "requested_final_status",
            "owner_id",
            "lease_expires_at",
        }
        operation_fields = {
            "fingerprint",
            "tool_name",
            "arguments_sha256",
            "status",
            "owner_id",
            "started_at",
            "lease_expires_at",
            "decision",
            "receipt_id",
            "result_sha256",
            "terminal_code",
            "finished_at",
        }
        for digest, record in handles.items():
            if (
                not _is_hex_digest(digest)
                or not isinstance(record, dict)
                or not set(record).issubset(record_fields)
                or not {
                    "handle",
                    "parent_jti",
                    "request_key",
                    "request_fingerprint",
                    "status",
                    "created_at",
                    "operations",
                }.issubset(record)
                or not isinstance(record.get("handle"), str)
                or not _UUID_RE.fullmatch(str(record.get("parent_jti", "")))
                or not _is_hex_digest(record.get("request_key"))
                or not _is_hex_digest(record.get("request_fingerprint"))
                or record.get("status") not in _HANDLE_STATES
                or not _is_finite_number(record.get("created_at"), positive=True)
                or not isinstance(record.get("operations"), dict)
            ):
                raise GovernedSubagentError(
                    "STATE_UNAVAILABLE", "governed subagent record is malformed"
                )
            try:
                _validate_handle_text(record["handle"])
            except GovernedSubagentError as exc:
                raise GovernedSubagentError(
                    "STATE_UNAVAILABLE", "governed subagent handle record is malformed"
                ) from exc
            if hashlib.sha256(record["handle"].encode("ascii")).hexdigest() != digest:
                raise GovernedSubagentError(
                    "STATE_UNAVAILABLE",
                    "governed subagent handle index is inconsistent",
                )
            status = str(record["status"])
            child_jti = record.get("child_jti")
            expires_at = record.get("expires_at")
            if status == "spawning":
                if child_jti is not None and not _UUID_RE.fullmatch(str(child_jti)):
                    raise GovernedSubagentError(
                        "STATE_UNAVAILABLE", "spawning child session id is malformed"
                    )
                if expires_at is not None and not _is_finite_number(
                    expires_at, positive=True
                ):
                    raise GovernedSubagentError(
                        "STATE_UNAVAILABLE", "spawning child expiry is malformed"
                    )
                if not _is_hex_digest(
                    record.get("owner_id"), length=32
                ) or not _is_finite_number(
                    record.get("lease_expires_at"), positive=True
                ):
                    raise GovernedSubagentError(
                        "STATE_UNAVAILABLE", "spawn lease metadata is malformed"
                    )
            elif not _UUID_RE.fullmatch(str(child_jti or "")) or not _is_finite_number(
                expires_at, positive=True
            ):
                raise GovernedSubagentError(
                    "STATE_UNAVAILABLE", "child session metadata is malformed"
                )
            if "closed_at" in record and not _is_finite_number(
                record["closed_at"], positive=True
            ):
                raise GovernedSubagentError(
                    "STATE_UNAVAILABLE", "child closure timestamp is malformed"
                )
            if "terminal_code" in record:
                try:
                    _bounded_text(
                        "terminal_code", record["terminal_code"], max_bytes=256
                    )
                except (TypeError, ValueError) as exc:
                    raise GovernedSubagentError(
                        "STATE_UNAVAILABLE", "child terminal code is malformed"
                    ) from exc
            requested_final = record.get("requested_final_status")
            if (
                requested_final is not None
                and requested_final not in _TERMINAL_HANDLE_STATES
            ):
                raise GovernedSubagentError(
                    "STATE_UNAVAILABLE", "requested child disposition is malformed"
                )
            attestation_id = record.get("attestation_id")
            attestation_sha256 = record.get("attestation_sha256")
            if (attestation_id is None) != (attestation_sha256 is None) or (
                attestation_id is not None
                and (
                    not _UUID_RE.fullmatch(str(attestation_id))
                    or not _is_hex_digest(attestation_sha256)
                )
            ):
                raise GovernedSubagentError(
                    "STATE_UNAVAILABLE", "child attestation metadata is malformed"
                )
            operations = record["operations"]
            if len(operations) > MAX_OPERATIONS_PER_HANDLE:
                raise GovernedSubagentError(
                    "STATE_CAPACITY",
                    "governed subagent operation history exceeds its bound",
                )
            for operation_key, operation in operations.items():
                if (
                    not _is_hex_digest(operation_key)
                    or not isinstance(operation, dict)
                    or not set(operation).issubset(operation_fields)
                    or not {
                        "fingerprint",
                        "tool_name",
                        "arguments_sha256",
                        "status",
                        "owner_id",
                        "started_at",
                        "lease_expires_at",
                    }.issubset(operation)
                    or not _is_hex_digest(operation.get("fingerprint"))
                    or not _is_hex_digest(operation.get("arguments_sha256"))
                    or operation.get("status") not in _OPERATION_STATES
                    or not _is_hex_digest(operation.get("owner_id"), length=32)
                    or not _is_finite_number(operation.get("started_at"), positive=True)
                    or not _is_finite_number(
                        operation.get("lease_expires_at"), positive=True
                    )
                ):
                    raise GovernedSubagentError(
                        "STATE_UNAVAILABLE", "governed subagent operation is malformed"
                    )
                try:
                    _bounded_text(
                        "tool_name",
                        operation["tool_name"],
                        max_bytes=MAX_TOOL_NAME_BYTES,
                    )
                except (TypeError, ValueError) as exc:
                    raise GovernedSubagentError(
                        "STATE_UNAVAILABLE", "operation tool name is malformed"
                    ) from exc
                decision = operation.get("decision")
                if decision is not None and decision not in {
                    item.value for item in Decision
                }:
                    raise GovernedSubagentError(
                        "STATE_UNAVAILABLE", "operation decision is malformed"
                    )
                for field_name in ("receipt_id", "terminal_code"):
                    if field_name not in operation:
                        continue
                    try:
                        _bounded_text(
                            field_name,
                            operation[field_name],
                            max_bytes=512,
                        )
                    except (TypeError, ValueError) as exc:
                        raise GovernedSubagentError(
                            "STATE_UNAVAILABLE",
                            f"operation {field_name} is malformed",
                        ) from exc
                if "finished_at" in operation and not _is_finite_number(
                    operation["finished_at"], positive=True
                ):
                    raise GovernedSubagentError(
                        "STATE_UNAVAILABLE", "operation completion time is malformed"
                    )
                if "result_sha256" in operation and not _is_hex_digest(
                    operation["result_sha256"]
                ):
                    raise GovernedSubagentError(
                        "STATE_UNAVAILABLE", "operation result digest is malformed"
                    )
                if (
                    operation["status"]
                    in {
                        "denied",
                        "completed",
                        "uncertain",
                    }
                    and "finished_at" not in operation
                ):
                    raise GovernedSubagentError(
                        "STATE_UNAVAILABLE",
                        "terminal operation has no completion timestamp",
                    )
            request_key = str(record["request_key"])
            if requests.get(request_key) != digest:
                raise GovernedSubagentError(
                    "STATE_UNAVAILABLE",
                    "governed subagent reverse request index is inconsistent",
                )
        if len(requests) != len(handles) or any(
            not _is_hex_digest(request_key)
            or not _is_hex_digest(handle_digest)
            or handle_digest not in handles
            for request_key, handle_digest in requests.items()
        ):
            raise GovernedSubagentError(
                "STATE_UNAVAILABLE", "governed subagent request index is inconsistent"
            )

    def _persist_state_locked(
        self, state: dict[str, Any], *, encoded: bytes | None = None
    ) -> None:
        self._validate_state(state)
        material = encoded if encoded is not None else _canonical_json(state)
        if len(material) > MAX_STATE_BYTES:
            raise GovernedSubagentError(
                "STATE_CAPACITY", "governed subagent state exceeds its size bound"
            )
        temporary = self._state_path.with_name(
            f"{self._state_path.stem}.{uuid.uuid4().hex}.tmp"
        )
        fd: int | None = None
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                fd = None
                handle.write(material)
                handle.write(b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            temporary.chmod(0o600)
            os.replace(temporary, self._state_path)
            self._state_path.chmod(0o600)
            directory_fd = os.open(self._state_dir, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            if fd is not None:
                os.close(fd)
            try:
                temporary.unlink()
            except OSError:
                pass
            raise

    def _fresh_session_snapshot(self, session_id: str) -> dict[str, Any]:
        try:
            with self.proxy._locked_persisted_session(session_id) as session:
                with session._lock:
                    return {
                        "claims": copy.deepcopy(session.passport_claims),
                        "start_time": float(session.start_time),
                        "ended": session.summary is not None
                        or session.end_time is not None,
                    }
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise GovernedSubagentError(
                "SESSION_UNAVAILABLE", "governance session state is unavailable"
            ) from exc

    @staticmethod
    def _session_expiry(snapshot: Mapping[str, Any]) -> float:
        claims = snapshot["claims"]
        try:
            credential_expiry = float(claims["exp"])
            duration_expiry = float(snapshot["start_time"]) + float(
                claims.get("max_duration_s", credential_expiry)
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GovernedSubagentError(
                "SESSION_INVALID", "session expiry metadata is invalid"
            ) from exc
        return min(credential_expiry, duration_expiry)

    def _assert_parent_active(self) -> dict[str, Any]:
        snapshot = self._fresh_session_snapshot(self.parent_session_id)
        if snapshot["ended"]:
            raise GovernedSubagentError("PARENT_CLOSED", "parent session is closed")
        if self._session_expiry(snapshot) <= time.time():
            raise GovernedSubagentError("PARENT_EXPIRED", "parent session is expired")
        return snapshot

    def _assert_child_active(
        self, child_jti: str, *, expected_expiry: float | None = None
    ) -> dict[str, Any]:
        snapshot = self._fresh_session_snapshot(child_jti)
        claims = snapshot["claims"]
        if str(claims.get("parent_jti")) != self.parent_session_id:
            raise GovernedSubagentError(
                "PARENT_MISMATCH", "child session is not bound to this parent"
            )
        if snapshot["ended"]:
            raise GovernedSubagentError("HANDLE_CLOSED", "child session is closed")
        expiry = self._session_expiry(snapshot)
        if expected_expiry is not None and abs(expiry - expected_expiry) > 1.0:
            raise GovernedSubagentError(
                "STATE_UNAVAILABLE", "child expiry disagrees with adapter state"
            )
        if expiry <= time.time():
            raise GovernedSubagentError("HANDLE_EXPIRED", "child session is expired")
        return snapshot

    def _request_fingerprint(self, request: GovernedSubagentRequest) -> str:
        return _sha256_json(
            {
                "parent_jti": self.parent_session_id,
                "child_agent_id": request.child_agent_id,
                "mission": request.mission,
                "allowed_tools": list(request.allowed_tools),
                "resource_scope": list(request.resource_scope),
                "max_tool_calls": request.max_tool_calls,
                "ttl_s": request.ttl_s,
                "spend_cap": request.spend_cap,
                "risk_cap": request.risk_cap,
            }
        )

    def _request_key(self, request_id: str) -> str:
        return hashlib.sha256(
            f"{self.parent_session_id}\0{request_id}".encode("utf-8")
        ).hexdigest()

    def _delegation_record_fingerprint(self, child_record: Mapping[str, Any]) -> str:
        metadata = child_record.get("delegation_request")
        if not isinstance(metadata, Mapping):
            raise GovernedSubagentError(
                "STATE_UNAVAILABLE", "delegation recovery metadata is unavailable"
            )
        try:
            return _sha256_json(
                {
                    "parent_jti": str(metadata["parent_jti"]),
                    "child_agent_id": str(metadata["child_agent_id"]),
                    "mission": str(metadata["child_mission"]),
                    "allowed_tools": sorted(metadata["child_allowed_tools"]),
                    "resource_scope": sorted(
                        metadata.get("child_resource_scope") or []
                    ),
                    "max_tool_calls": int(metadata["child_max_tool_calls"]),
                    "ttl_s": int(metadata["child_ttl_s"]),
                    "spend_cap": None,
                    "risk_cap": None,
                }
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise GovernedSubagentError(
                "STATE_UNAVAILABLE", "delegation recovery metadata is malformed"
            ) from exc

    def _delegated_child_record(self, request_key: str) -> dict[str, Any] | None:
        try:
            with self.proxy._locked_persisted_session(
                self.parent_session_id
            ) as parent_session:
                with parent_session._lock:
                    for child_record in parent_session.delegated_children:
                        if child_record.get("delegation_request_id") == request_key:
                            return copy.deepcopy(child_record)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise GovernedSubagentError(
                "SESSION_UNAVAILABLE", "parent delegation state is unavailable"
            ) from exc
        return None

    def _get_or_start_child_session(
        self, child_jti: str, child_token: str
    ) -> GovernanceSession:
        try:
            return self.proxy.get_session(child_jti)
        except ValueError:
            try:
                return self.proxy.start_session(child_token)
            except ValueError:
                # A concurrent idempotent spawn may have started the same
                # child between the lookup and start attempt.
                return self.proxy.get_session(child_jti)

    def _reconcile_spawning_record(self, record: dict[str, Any]) -> bool:
        child_record = self._delegated_child_record(str(record["request_key"]))
        if child_record is None:
            return False
        if not secrets.compare_digest(
            self._delegation_record_fingerprint(child_record),
            str(record["request_fingerprint"]),
        ):
            raise GovernedSubagentError(
                "STATE_UNAVAILABLE",
                "delegated child disagrees with the durable spawn intent",
            )
        child_jti = str(child_record.get("child_jti", ""))
        child_token = child_record.get("child_token")
        if not _UUID_RE.fullmatch(child_jti) or not isinstance(child_token, str):
            raise GovernedSubagentError(
                "STATE_UNAVAILABLE", "delegated child authority is malformed"
            )
        child_session = self._get_or_start_child_session(child_jti, child_token)
        if child_session.jti != child_jti:
            raise GovernedSubagentError(
                "STATE_UNAVAILABLE", "recovered child session id is inconsistent"
            )
        snapshot = self._fresh_session_snapshot(child_jti)
        claims = snapshot["claims"]
        if str(claims.get("parent_jti")) != self.parent_session_id:
            raise GovernedSubagentError(
                "PARENT_MISMATCH", "recovered child belongs to another parent"
            )
        record["child_jti"] = child_jti
        record["expires_at"] = self._session_expiry(snapshot)
        record.pop("owner_id", None)
        record.pop("lease_expires_at", None)
        if snapshot["ended"]:
            record["status"] = "quarantined"
            record["terminal_code"] = "CHILD_ENDED_DURING_SPAWN_RECOVERY"
        elif float(record["expires_at"]) <= time.time():
            record["status"] = "expired"
            record["terminal_code"] = "HANDLE_EXPIRED"
            record["closed_at"] = time.time()
        else:
            record["status"] = "active"
        return True

    @staticmethod
    def _handle_digest(handle: str) -> str:
        return hashlib.sha256(handle.encode("ascii")).hexdigest()

    def _recover_record(self, record: dict[str, Any], *, now: float) -> int:
        if record.get("status") == "spawning":
            self._reconcile_spawning_record(record)
        interrupted = 0
        for operation in record.get("operations", {}).values():
            if operation.get("status") not in _INFLIGHT_OPERATION_STATES:
                continue
            try:
                lease_expires_at = float(operation["lease_expires_at"])
            except (KeyError, TypeError, ValueError):
                lease_expires_at = 0.0
            if lease_expires_at > now:
                continue
            operation["status"] = "uncertain"
            operation["terminal_code"] = "OPERATION_LEASE_EXPIRED"
            operation["finished_at"] = now
            record["status"] = "quarantined"
            record["terminal_code"] = "OPERATION_UNCERTAIN"
            interrupted += 1
        if (
            record.get("status") == "active"
            and float(record.get("expires_at", 0)) <= now
        ):
            record["status"] = "expired"
            record["terminal_code"] = "HANDLE_EXPIRED"
            record["closed_at"] = now
        return interrupted

    def _resolve_record(
        self,
        state: dict[str, Any],
        handle: GovernedSubagentHandle | str,
        *,
        allow_terminal: bool = False,
        allow_quarantined: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        handle_value = _handle_text(handle)
        handle_digest = self._handle_digest(handle_value)
        record = state["handles"].get(handle_digest)
        if not isinstance(record, dict) or not secrets.compare_digest(
            str(record.get("handle", "")), handle_value
        ):
            raise GovernedSubagentError("HANDLE_UNKNOWN", "child handle is unknown")
        if record.get("parent_jti") != self.parent_session_id:
            raise GovernedSubagentError(
                "PARENT_MISMATCH", "child handle belongs to another parent"
            )
        self._recover_record(record, now=time.time())
        status = record.get("status")
        if status == "spawning":
            raise GovernedSubagentError(
                "HANDLE_SPAWNING", "child authority has not finished materializing"
            )
        if status in _TERMINAL_HANDLE_STATES and not allow_terminal:
            code = {
                "closed": "HANDLE_CLOSED",
                "cancelled": "HANDLE_CANCELLED",
                "expired": "HANDLE_EXPIRED",
            }[str(status)]
            raise GovernedSubagentError(code, f"child handle is {status}")
        if status in {"quarantined", "closing"} and not allow_quarantined:
            raise GovernedSubagentError(
                "HANDLE_QUARANTINED", "child handle requires explicit closure"
            )
        if status not in _HANDLE_STATES:
            raise GovernedSubagentError(
                "STATE_UNAVAILABLE", "child handle state is invalid"
            )
        return handle_digest, record

    def _complete_spawn(
        self,
        handle_value: str,
        request_key: str,
        fingerprint: str,
        request: GovernedSubagentRequest,
    ) -> GovernedSubagentHandle:
        parent_snapshot = self._assert_parent_active()
        parent_claims = parent_snapshot["claims"]
        parent_token = self.proxy.get_session(self.parent_session_id).passport_token
        child_token, child_claims, _remaining = self.proxy.delegate_passport(
            parent_token=parent_token,
            private_key=self._delegation_private_key,
            child_agent_id=request.child_agent_id,
            child_allowed_tools=list(request.allowed_tools),
            child_mission=request.mission,
            child_ttl_s=request.ttl_s,
            child_max_tool_calls=request.max_tool_calls,
            child_resource_scope=list(request.resource_scope),
            delegation_request_id=request_key,
        )
        child_jti = str(child_claims.get("jti", ""))
        if not _UUID_RE.fullmatch(child_jti):
            raise GovernedSubagentError(
                "CHILD_INVALID", "derived child session id is invalid"
            )
        child_session = self._get_or_start_child_session(child_jti, child_token)
        if child_session.jti != child_jti:
            raise GovernedSubagentError(
                "CHILD_INVALID",
                "started child session id does not match delegation",
            )
        child_snapshot = self._assert_child_active(child_jti)
        child_policy = child_snapshot["claims"]
        try:
            attenuation_valid = (
                str(child_policy.get("parent_jti")) == self.parent_session_id
                and str(child_policy.get("sub")) == request.child_agent_id
                and str(child_policy.get("mission")) == request.mission
                and tuple(sorted(child_policy.get("allowed_tools", [])))
                == request.allowed_tools
                and tuple(sorted(child_policy.get("resource_scope", [])))
                == request.resource_scope
                and int(child_policy.get("max_tool_calls", 0)) <= request.max_tool_calls
                and int(child_policy.get("max_tool_calls", 0))
                < int(parent_claims.get("max_tool_calls", 0))
            )
        except (TypeError, ValueError):
            attenuation_valid = False
        if not attenuation_valid:
            raise GovernedSubagentError(
                "CHILD_ATTENUATION_INVALID",
                "derived child authority does not match the attenuated request",
            )

        handle_digest = self._handle_digest(handle_value)
        with self._state_transaction() as state:
            record = state["handles"].get(handle_digest)
            if (
                not isinstance(record, dict)
                or not secrets.compare_digest(
                    str(record.get("handle", "")), handle_value
                )
                or record.get("request_key") != request_key
                or record.get("request_fingerprint") != fingerprint
            ):
                raise GovernedSubagentError(
                    "STATE_UNAVAILABLE", "spawn intent cannot be correlated"
                )
            if record.get("status") == "active":
                if record.get("child_jti") != child_jti:
                    raise GovernedSubagentError(
                        "STATE_UNAVAILABLE", "spawn retry resolved another child"
                    )
                return GovernedSubagentHandle(handle_value)
            if record.get("status") != "spawning":
                raise GovernedSubagentError(
                    "SPAWN_REPLAY_CLOSED",
                    "closed, expired, or uncertain child authority cannot be reopened",
                )
            record["child_jti"] = child_jti
            record["status"] = "active"
            record["expires_at"] = self._session_expiry(child_snapshot)
            record.pop("owner_id", None)
            record.pop("lease_expires_at", None)
        return GovernedSubagentHandle(handle_value)

    def spawn(self, request: GovernedSubagentRequest) -> GovernedSubagentHandle:
        """Derive/start a child and return only its opaque parent-bound handle."""

        if not isinstance(request, GovernedSubagentRequest):
            raise TypeError("request must be a GovernedSubagentRequest")
        if request.spend_cap is not None:
            raise GovernedSubagentError(
                "SPEND_CAP_UNSUPPORTED",
                "this runtime has no merged signed spend-cap delegation surface",
            )
        if request.risk_cap is not None:
            raise GovernedSubagentError(
                "RISK_CAP_UNSUPPORTED",
                "this runtime has no merged signed risk-cap delegation surface",
            )
        self._assert_parent_active()
        request_key = self._request_key(request.request_id)
        fingerprint = self._request_fingerprint(request)

        with self._state_transaction() as state:
            existing_digest = state["requests"].get(request_key)
            if existing_digest is not None:
                record = state["handles"].get(existing_digest)
                if not isinstance(record, dict):
                    raise GovernedSubagentError(
                        "STATE_UNAVAILABLE", "spawn request index is inconsistent"
                    )
                self._recover_record(record, now=time.time())
                if record.get("request_fingerprint") != fingerprint:
                    raise GovernedSubagentConflictError(
                        "SPAWN_CONFLICT",
                        "request_id was already used with different child semantics",
                    )
                if record.get("status") == "active":
                    self._assert_child_active(
                        str(record["child_jti"]),
                        expected_expiry=float(record["expires_at"]),
                    )
                    return GovernedSubagentHandle(str(record["handle"]))
                if record.get("status") != "spawning":
                    raise GovernedSubagentError(
                        "SPAWN_REPLAY_CLOSED",
                        "closed, expired, or uncertain child authority cannot be reopened",
                    )
                handle_value = str(record["handle"])
                record["owner_id"] = self._instance_id
                record["lease_expires_at"] = time.time() + self._operation_lease_s
            else:
                if len(state["handles"]) >= MAX_HANDLE_RECORDS:
                    raise GovernedSubagentError(
                        "STATE_CAPACITY",
                        "governed subagent handle capacity is exhausted",
                    )

                handle_value = _new_handle()
                handle_digest = self._handle_digest(handle_value)
                now = time.time()
                record = {
                    "handle": handle_value,
                    "parent_jti": self.parent_session_id,
                    "request_key": request_key,
                    "request_fingerprint": fingerprint,
                    "status": "spawning",
                    "created_at": now,
                    "owner_id": self._instance_id,
                    "lease_expires_at": now + self._operation_lease_s,
                    "operations": {},
                }
                state["handles"][handle_digest] = record
                state["requests"][request_key] = handle_digest
        return self._complete_spawn(handle_value, request_key, fingerprint, request)

    def _normalized_tool_call(
        self, tool_name: str, arguments: Mapping[str, Any]
    ) -> tuple[str, dict[str, Any], str]:
        tool = _bounded_text("tool_name", tool_name, max_bytes=MAX_TOOL_NAME_BYTES)
        if not isinstance(arguments, Mapping):
            raise TypeError("arguments must be an object")
        material = _canonical_json(dict(arguments))
        if len(material) > MAX_ARGUMENT_BYTES:
            raise ValueError(f"arguments exceed {MAX_ARGUMENT_BYTES} bytes")
        normalized = json.loads(material.decode("utf-8"))
        if not isinstance(normalized, dict):
            raise TypeError("arguments must encode a JSON object")
        return tool, normalized, hashlib.sha256(material).hexdigest()

    def _prepare_operation(
        self,
        handle: GovernedSubagentHandle | str,
        *,
        operation_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> tuple[str, str, str, dict[str, Any], GovernedToolResult | None]:
        operation = _bounded_text(
            "operation_id", operation_id, max_bytes=MAX_REQUEST_ID_BYTES
        )
        tool, normalized_arguments, arguments_sha256 = self._normalized_tool_call(
            tool_name, arguments
        )
        self._assert_parent_active()
        handle_value = _handle_text(handle)
        operation_key = hashlib.sha256(operation.encode("utf-8")).hexdigest()
        fingerprint = _sha256_json(
            {
                "handle_sha256": self._handle_digest(handle_value),
                "operation_id_sha256": operation_key,
                "tool_name": tool,
                "arguments_sha256": arguments_sha256,
            }
        )

        with self._state_transaction() as state:
            _handle_digest, record = self._resolve_record(state, handle_value)
            self._assert_child_active(
                str(record["child_jti"]),
                expected_expiry=float(record["expires_at"]),
            )
            operations = record["operations"]
            existing = operations.get(operation_key)
            if existing is not None:
                if existing.get("fingerprint") != fingerprint:
                    raise GovernedSubagentConflictError(
                        "OPERATION_CONFLICT",
                        "operation_id was already used with different tool semantics",
                    )
                if existing.get("status") in _INFLIGHT_OPERATION_STATES:
                    raise GovernedSubagentError(
                        "OPERATION_IN_PROGRESS", "operation is already in progress"
                    )
                stored_decision = existing.get("decision")
                decision = (
                    Decision(stored_decision)
                    if stored_decision in {item.value for item in Decision}
                    else None
                )
                return (
                    str(record["child_jti"]),
                    operation_key,
                    fingerprint,
                    normalized_arguments,
                    GovernedToolResult(
                        status="replay_suppressed",
                        decision=decision,
                        reason=(
                            "operation replay suppressed; recover the prior result "
                            "from the framework checkpoint"
                        ),
                        executed=False,
                        receipt_id=existing.get("receipt_id"),
                        result_sha256=existing.get("result_sha256"),
                    ),
                )
            if len(operations) >= MAX_OPERATIONS_PER_HANDLE:
                raise GovernedSubagentError(
                    "OPERATION_CAPACITY", "child operation history is full"
                )
            if any(
                item.get("status") in _INFLIGHT_OPERATION_STATES
                for item in operations.values()
            ):
                raise GovernedSubagentError(
                    "CHILD_BUSY", "another operation is active for this child"
                )
            now = time.time()
            operations[operation_key] = {
                "fingerprint": fingerprint,
                "tool_name": tool,
                "arguments_sha256": arguments_sha256,
                "status": "evaluating",
                "owner_id": self._instance_id,
                "started_at": now,
                "lease_expires_at": now + self._operation_lease_s,
            }
            return (
                str(record["child_jti"]),
                operation_key,
                fingerprint,
                normalized_arguments,
                None,
            )

    def _operation_transition(
        self,
        handle: GovernedSubagentHandle | str,
        operation_key: str,
        fingerprint: str,
        *,
        status: str,
        **updates: Any,
    ) -> dict[str, Any]:
        with self._state_transaction() as state:
            _handle_digest, record = self._resolve_record(
                state,
                handle,
                allow_quarantined=True,
            )
            operation = record["operations"].get(operation_key)
            if (
                not isinstance(operation, dict)
                or operation.get("fingerprint") != fingerprint
            ):
                raise GovernedSubagentError(
                    "STATE_UNAVAILABLE", "operation state cannot be correlated"
                )
            expected_previous = {
                "authorized": {"evaluating"},
                "denied": {"evaluating"},
                "executing": {"authorized"},
                "completed": {"executing"},
            }.get(status)
            if (
                expected_previous is None
                or operation.get("status") not in expected_previous
            ):
                raise GovernedSubagentError(
                    "OPERATION_UNCERTAIN",
                    "operation state changed before the requested transition",
                )
            operation["status"] = status
            operation.update(copy.deepcopy(updates))
            return copy.deepcopy(operation)

    def _quarantine_operation(
        self,
        handle: GovernedSubagentHandle | str,
        operation_key: str,
        fingerprint: str,
        *,
        terminal_code: str,
    ) -> None:
        with self._state_transaction() as state:
            _handle_digest, record = self._resolve_record(
                state,
                handle,
                allow_quarantined=True,
            )
            operation = record["operations"].get(operation_key)
            if (
                isinstance(operation, dict)
                and operation.get("fingerprint") == fingerprint
            ):
                operation["status"] = "uncertain"
                operation["terminal_code"] = terminal_code
                operation["finished_at"] = time.time()
            record["status"] = "quarantined"
            record["terminal_code"] = terminal_code

    @staticmethod
    def _bounded_result_value(
        value: Any,
        *,
        depth: int = 0,
        item_budget: list[int] | None = None,
    ) -> Any:
        if depth > MAX_RESULT_DEPTH:
            raise GovernedSubagentError(
                "RESULT_UNSERIALIZABLE", "executor result exceeds nesting bound"
            )
        budget = item_budget if item_budget is not None else [MAX_RESULT_ITEMS]
        budget[0] -= 1
        if budget[0] < 0:
            raise GovernedSubagentError(
                "RESULT_UNSERIALIZABLE", "executor result exceeds item bound"
            )
        value_type = type(value)
        if value is None or value_type in {bool, int, str}:
            return value
        if value_type is float:
            if not math.isfinite(value):
                raise GovernedSubagentError(
                    "RESULT_UNSERIALIZABLE", "executor result has non-finite number"
                )
            return value
        if value_type in {list, tuple}:
            return [
                GovernedSubagentAdapter._bounded_result_value(
                    item,
                    depth=depth + 1,
                    item_budget=budget,
                )
                for item in value
            ]
        if value_type is dict:
            normalized: dict[str, Any] = {}
            for key, item in value.items():
                if type(key) is not str:
                    raise GovernedSubagentError(
                        "RESULT_UNSERIALIZABLE",
                        "executor result object keys must be strings",
                    )
                normalized[key] = GovernedSubagentAdapter._bounded_result_value(
                    item,
                    depth=depth + 1,
                    item_budget=budget,
                )
            return normalized
        raise GovernedSubagentError(
            "RESULT_UNSERIALIZABLE",
            "executor result must contain only bounded JSON values",
        )

    @classmethod
    def _result_digest(cls, value: Any) -> str:
        try:
            material = _canonical_json(cls._bounded_result_value(value))
        except ValueError as exc:
            raise GovernedSubagentError(
                "RESULT_UNSERIALIZABLE", "executor result cannot be encoded"
            ) from exc
        if len(material) > MAX_RESULT_BYTES:
            raise GovernedSubagentError(
                "RESULT_UNSERIALIZABLE", "executor result exceeds byte bound"
            )
        return hashlib.sha256(material).hexdigest()

    def _record_result_serialization_failure(
        self,
        child_jti: str,
        duration_ms: float,
    ) -> None:
        try:
            self.proxy.record_tool_result(
                child_jti,
                response="executor_outcome:result_unserializable",
                duration_ms=duration_ms,
            )
        except Exception:
            pass

    def _evaluate_operation(
        self,
        handle: GovernedSubagentHandle | str,
        child_jti: str,
        operation_key: str,
        fingerprint: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[Decision, str, str | None]:
        receipt_ids: list[str] = []
        try:
            decision, reason = self.proxy.evaluate_tool_call(
                child_jti,
                tool_name,
                arguments,
                receipt_callback=receipt_ids.append,
            )
        except BaseException:
            self._quarantine_operation(
                handle,
                operation_key,
                fingerprint,
                terminal_code="POLICY_EVALUATION_UNCERTAIN",
            )
            raise
        receipt_id = receipt_ids[-1] if receipt_ids else None
        if decision != Decision.PERMIT:
            self._operation_transition(
                handle,
                operation_key,
                fingerprint,
                status="denied",
                decision=decision.value,
                receipt_id=receipt_id,
                finished_at=time.time(),
            )
            return decision, reason, receipt_id
        self._operation_transition(
            handle,
            operation_key,
            fingerprint,
            status="authorized",
            decision=decision.value,
            receipt_id=receipt_id,
            lease_expires_at=time.time() + self._operation_lease_s,
        )
        return decision, reason, receipt_id

    def _record_executor_failure(
        self,
        child_jti: str,
        duration_ms: float,
    ) -> None:
        try:
            self.proxy.record_tool_result(
                child_jti,
                response="executor_outcome:error_or_interruption",
                duration_ms=duration_ms,
            )
        except Exception:
            # The original executor exception remains primary.  Adapter state
            # is still quarantined below, so a failed evidence settlement can
            # never reopen or refund the child.
            pass

    def run_tool(
        self,
        handle: GovernedSubagentHandle | str,
        *,
        operation_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        executor: Callable[[], Any],
    ) -> GovernedToolResult:
        """Evaluate and, only on ``PERMIT``, synchronously invoke ``executor``."""

        if not callable(executor):
            raise TypeError("executor must be callable")
        child_jti, operation_key, fingerprint, normalized_arguments, replay = (
            self._prepare_operation(
                handle,
                operation_id=operation_id,
                tool_name=tool_name,
                arguments=arguments,
            )
        )
        if replay is not None:
            return replay
        decision, reason, receipt_id = self._evaluate_operation(
            handle,
            child_jti,
            operation_key,
            fingerprint,
            tool_name,
            normalized_arguments,
        )
        if decision != Decision.PERMIT:
            return GovernedToolResult(
                status="denied",
                decision=decision,
                reason=reason,
                executed=False,
                receipt_id=receipt_id,
            )

        self._operation_transition(
            handle,
            operation_key,
            fingerprint,
            status="executing",
            lease_expires_at=time.time() + self._operation_lease_s,
        )
        started = time.perf_counter()
        try:
            value = executor()
        except BaseException:
            duration_ms = (time.perf_counter() - started) * 1000.0
            self._record_executor_failure(child_jti, duration_ms)
            self._quarantine_operation(
                handle,
                operation_key,
                fingerprint,
                terminal_code="EXECUTOR_OUTCOME_UNCERTAIN",
            )
            raise

        duration_ms = (time.perf_counter() - started) * 1000.0
        try:
            result_sha256 = self._result_digest(value)
        except GovernedSubagentError:
            self._record_result_serialization_failure(child_jti, duration_ms)
            self._quarantine_operation(
                handle,
                operation_key,
                fingerprint,
                terminal_code="RESULT_SERIALIZATION_UNCERTAIN",
            )
            raise
        try:
            self.proxy.record_tool_result(
                child_jti,
                response=f"executor_result_sha256:{result_sha256}",
                duration_ms=duration_ms,
            )
        except BaseException:
            self._quarantine_operation(
                handle,
                operation_key,
                fingerprint,
                terminal_code="RESULT_EVIDENCE_UNCERTAIN",
            )
            raise
        self._operation_transition(
            handle,
            operation_key,
            fingerprint,
            status="completed",
            result_sha256=result_sha256,
            finished_at=time.time(),
        )
        return GovernedToolResult(
            status="completed",
            decision=decision,
            reason=reason,
            executed=True,
            value=value,
            receipt_id=receipt_id,
            result_sha256=result_sha256,
        )

    async def arun_tool(
        self,
        handle: GovernedSubagentHandle | str,
        *,
        operation_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        executor: Callable[[], Awaitable[Any]],
    ) -> GovernedToolResult:
        """Async counterpart to :meth:`run_tool` with identical state rules."""

        if not callable(executor):
            raise TypeError("executor must be callable")
        child_jti, operation_key, fingerprint, normalized_arguments, replay = (
            self._prepare_operation(
                handle,
                operation_id=operation_id,
                tool_name=tool_name,
                arguments=arguments,
            )
        )
        if replay is not None:
            return replay
        decision, reason, receipt_id = self._evaluate_operation(
            handle,
            child_jti,
            operation_key,
            fingerprint,
            tool_name,
            normalized_arguments,
        )
        if decision != Decision.PERMIT:
            return GovernedToolResult(
                status="denied",
                decision=decision,
                reason=reason,
                executed=False,
                receipt_id=receipt_id,
            )

        self._operation_transition(
            handle,
            operation_key,
            fingerprint,
            status="executing",
            lease_expires_at=time.time() + self._operation_lease_s,
        )
        started = time.perf_counter()
        try:
            awaitable = executor()
            if not isinstance(awaitable, Awaitable):
                raise TypeError("async executor must return an awaitable")
            value = await awaitable
        except BaseException:
            duration_ms = (time.perf_counter() - started) * 1000.0
            self._record_executor_failure(child_jti, duration_ms)
            self._quarantine_operation(
                handle,
                operation_key,
                fingerprint,
                terminal_code="EXECUTOR_OUTCOME_UNCERTAIN",
            )
            raise

        duration_ms = (time.perf_counter() - started) * 1000.0
        try:
            result_sha256 = self._result_digest(value)
        except GovernedSubagentError:
            self._record_result_serialization_failure(child_jti, duration_ms)
            self._quarantine_operation(
                handle,
                operation_key,
                fingerprint,
                terminal_code="RESULT_SERIALIZATION_UNCERTAIN",
            )
            raise
        try:
            self.proxy.record_tool_result(
                child_jti,
                response=f"executor_result_sha256:{result_sha256}",
                duration_ms=duration_ms,
            )
        except BaseException:
            self._quarantine_operation(
                handle,
                operation_key,
                fingerprint,
                terminal_code="RESULT_EVIDENCE_UNCERTAIN",
            )
            raise
        self._operation_transition(
            handle,
            operation_key,
            fingerprint,
            status="completed",
            result_sha256=result_sha256,
            finished_at=time.time(),
        )
        return GovernedToolResult(
            status="completed",
            decision=decision,
            reason=reason,
            executed=True,
            value=value,
            receipt_id=receipt_id,
            result_sha256=result_sha256,
        )

    def _close(
        self,
        handle: GovernedSubagentHandle | str,
        *,
        final_status: str,
    ) -> GovernedSubagentCloseResult:
        if final_status not in _TERMINAL_HANDLE_STATES:
            raise ValueError("final_status must be closed, cancelled, or expired")
        handle_value = _handle_text(handle)
        with self._state_transaction() as state:
            _handle_digest, record = self._resolve_record(
                state,
                handle_value,
                allow_terminal=True,
                allow_quarantined=True,
            )
            status = str(record["status"])
            if status in _TERMINAL_HANDLE_STATES and record.get("attestation_id"):
                return GovernedSubagentCloseResult(
                    status=status,
                    attestation_id=str(record["attestation_id"]),
                    attestation_sha256=str(record["attestation_sha256"]),
                    idempotent=True,
                )
            if status in _TERMINAL_HANDLE_STATES:
                final_status = status
            elif status == "closing":
                requested = str(record.get("requested_final_status", final_status))
                if requested != final_status:
                    raise GovernedSubagentConflictError(
                        "CLOSE_CONFLICT",
                        "child closure is already committed to another final status",
                    )
                final_status = requested
            if any(
                operation.get("status") in _INFLIGHT_OPERATION_STATES
                for operation in record["operations"].values()
            ):
                raise GovernedSubagentError(
                    "CHILD_BUSY", "child cannot close while an operation is active"
                )
            record["status"] = "closing"
            record["requested_final_status"] = final_status
            child_jti = str(record["child_jti"])

        token, claims = self.proxy.issue_attestation_for_session(
            child_jti,
            self._delegation_private_key,
        )
        attestation_id = str(claims.get("jti", ""))
        if not attestation_id:
            raise GovernedSubagentError(
                "ATTESTATION_INVALID", "child attestation has no identifier"
            )
        attestation_sha256 = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self._state_transaction() as state:
            _handle_digest, record = self._resolve_record(
                state,
                handle_value,
                allow_terminal=True,
                allow_quarantined=True,
            )
            stored_final = str(record.get("requested_final_status", final_status))
            record["status"] = stored_final
            record["closed_at"] = time.time()
            record["attestation_id"] = attestation_id
            record["attestation_sha256"] = attestation_sha256
            record.pop("requested_final_status", None)
        return GovernedSubagentCloseResult(
            status=stored_final,
            attestation_id=attestation_id,
            attestation_sha256=attestation_sha256,
            idempotent=False,
        )

    def close(
        self, handle: GovernedSubagentHandle | str
    ) -> GovernedSubagentCloseResult:
        """Close and attest a child. Repeated close is idempotent."""

        return self._close(handle, final_status="closed")

    def cancel(
        self, handle: GovernedSubagentHandle | str
    ) -> GovernedSubagentCloseResult:
        """Monotonically cancel and attest a non-running child."""

        return self._close(handle, final_status="cancelled")

    def close_all(
        self, *, cancelled: bool = False
    ) -> list[GovernedSubagentCloseResult]:
        """Boundedly close every non-attested child for this parent invocation.

        Framework exception/cancellation handlers should call this with
        ``cancelled=True`` after their active executor has unwound. A live
        in-flight operation remains ``CHILD_BUSY`` rather than being declared
        cancelled while it may still be producing effects.
        """

        if not isinstance(cancelled, bool):
            raise TypeError("cancelled must be a boolean")
        with self._state_transaction() as state:
            handles: list[str] = []
            now = time.time()
            abandoned: list[tuple[str, str]] = []
            for handle_digest, record in state["handles"].items():
                if record.get("parent_jti") != self.parent_session_id:
                    continue
                self._recover_record(record, now=now)
                if (
                    record.get("status") == "spawning"
                    and float(record["lease_expires_at"]) <= now
                ):
                    abandoned.append((handle_digest, str(record["request_key"])))
                    continue
                if record.get("status") in _TERMINAL_HANDLE_STATES and record.get(
                    "attestation_id"
                ):
                    continue
                handles.append(str(record["handle"]))
            for handle_digest, request_key in abandoned:
                del state["handles"][handle_digest]
                state["requests"].pop(request_key, None)
        close_one = self.cancel if cancelled else self.close
        results: list[GovernedSubagentCloseResult] = []
        first_error: Exception | None = None
        for handle in handles:
            try:
                results.append(close_one(handle))
            except Exception as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error
        return results

    def recover(self) -> GovernedSubagentRecovery:
        """Recover expired leases/handles without reopening or refunding them."""

        expired = 0
        quarantined = 0
        interrupted = 0
        now = time.time()
        with self._state_transaction() as state:
            for record in state["handles"].values():
                if record.get("parent_jti") != self.parent_session_id:
                    continue
                previous_status = record.get("status")
                interrupted += self._recover_record(record, now=now)
                current_status = record.get("status")
                if previous_status != "expired" and current_status == "expired":
                    expired += 1
                if previous_status != "quarantined" and current_status == "quarantined":
                    quarantined += 1
        return GovernedSubagentRecovery(
            expired_handles=expired,
            quarantined_handles=quarantined,
            interrupted_operations=interrupted,
        )

    def lifecycle_snapshot(
        self, handle: GovernedSubagentHandle | str
    ) -> dict[str, Any]:
        """Return bounded, credential-free lifecycle metadata."""

        with self._state_transaction() as state:
            _handle_digest, record = self._resolve_record(
                state,
                handle,
                allow_terminal=True,
                allow_quarantined=True,
            )
            return {
                "parent_jti": record["parent_jti"],
                "child_jti": record["child_jti"],
                "status": record["status"],
                "created_at": record["created_at"],
                "expires_at": record["expires_at"],
                "operation_count": len(record["operations"]),
                "attestation_id": record.get("attestation_id"),
                "attestation_sha256": record.get("attestation_sha256"),
            }

    def export_session_evidence(
        self, handle: GovernedSubagentHandle | str
    ) -> dict[str, Any]:
        """Return the child session projection without authority-bearing tokens."""

        snapshot = self.lifecycle_snapshot(handle)
        with self.proxy._locked_persisted_session(
            str(snapshot["child_jti"])
        ) as child_session:
            with child_session._lock:
                return _redact_authority(child_session.to_dict())

    def export_attestation_evidence(
        self, handle: GovernedSubagentHandle | str
    ) -> tuple[str, dict[str, Any]]:
        """Return signed non-authorizing attestation evidence for trusted export.

        This method is for offline evidence assembly, not framework state or
        model-visible tool output.  It rejects unclosed children.
        """

        snapshot = self.lifecycle_snapshot(handle)
        if snapshot["status"] not in _TERMINAL_HANDLE_STATES:
            raise GovernedSubagentError(
                "HANDLE_ACTIVE", "child must be closed before evidence export"
            )
        with self.proxy._locked_persisted_session(
            str(snapshot["child_jti"])
        ) as child_session:
            with child_session._lock:
                token = child_session.attestation_token
        if not isinstance(token, str) or not token:
            raise GovernedSubagentError(
                "ATTESTATION_UNAVAILABLE", "child attestation is unavailable"
            )
        from .attestation import verify_attestation

        claims = verify_attestation(token, self.proxy.public_key)
        token_sha256 = hashlib.sha256(token.encode("ascii")).hexdigest()
        if not secrets.compare_digest(
            token_sha256,
            str(snapshot.get("attestation_sha256", "")),
        ) or not secrets.compare_digest(
            str(claims.get("jti", "")),
            str(snapshot.get("attestation_id", "")),
        ):
            raise GovernedSubagentError(
                "STATE_UNAVAILABLE",
                "attestation disagrees with adapter closure state",
            )
        return token, claims


__all__ = [
    "GovernedSubagentAdapter",
    "GovernedSubagentCloseResult",
    "GovernedSubagentConflictError",
    "GovernedSubagentError",
    "GovernedSubagentHandle",
    "GovernedSubagentRecovery",
    "GovernedSubagentRequest",
    "GovernedToolResult",
]
