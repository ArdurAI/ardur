"""Durable child-passport binding for Claude Code CLI hooks.

Claude's blockable ``Agent`` ``PreToolUse`` event identifies a tool use but its
non-blocking ``SubagentStart`` event identifies only the created ``agent_id``
and ``agent_type``.  This module bridges that contract without treating prompt
text, transcript paths, timestamps, or model output as identity.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import math
import os
import stat
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric import ec

from .governed_subagent import (
    GovernedSubagentAdapter,
    GovernedSubagentError,
    GovernedSubagentHandle,
    GovernedSubagentRequest,
    GovernedToolResult,
)
from .passport import DEFAULT_HOME
from .proxy import GovernanceProxy


CHILD_POLICY_ENV_VAR = "ARDUR_CC_CHILD_POLICY_FILE"
CHILD_POLICY_FILENAME = "claude-code-child-policies.json"
CHILD_POLICY_SCHEMA = "ardur.claude_code.child_policies.v1"
CHILD_BINDING_SCHEMA = "ardur.claude_code.child_bindings.v1"
CHILD_BINDING_FILENAME = "child-bindings.json"
CHILD_BINDING_LOCK_FILENAME = ".child-bindings.lock"
MAX_POLICY_BYTES = 256 * 1024
MAX_BINDING_BYTES = 4 * 1024 * 1024
MAX_AGENT_TYPES = 128
MAX_RECORDS = 4096
MAX_LABEL_BYTES = 256
_HANDLE_STATES = frozenset({"pending", "bound", "closed", "quarantined", "expired"})
_BLOCKED_BINDING_REASONS = frozenset(
    {"expired", "missing_reservation", "ambiguous_policy", "stop_before_start"}
)

_PROCESS_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, threading.RLock] = {}


class ClaudeChildBindingError(PermissionError):
    """Stable fail-closed error raised at the CLI child-binding boundary."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class ClaudeChildPolicy:
    agent_type: str
    child_agent_id: str
    mission: str
    allowed_tools: tuple[str, ...]
    resource_scope: tuple[str, ...]
    max_tool_calls: int
    ttl_s: int
    fingerprint: str


@dataclass(frozen=True)
class ClaudeChildBindingOutcome:
    state: str
    reason: str
    handle: str | None = None
    policy_fingerprint: str | None = None


def _bounded_text(name: str, value: Any, *, max_bytes: int = MAX_LABEL_BYTES) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ClaudeChildBindingError("INPUT_INVALID", f"{name} must be non-empty")
    if len(value.encode("utf-8")) > max_bytes:
        raise ClaudeChildBindingError("INPUT_INVALID", f"{name} is too long")
    if any(ord(character) < 0x20 for character in value):
        raise ClaudeChildBindingError(
            "INPUT_INVALID", f"{name} contains control characters"
        )
    return value


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
        raise ClaudeChildBindingError(
            "STATE_INVALID", "child binding data is not canonical JSON"
        ) from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _is_hex_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_finite_positive(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) > 0
    )


def _string_list(name: str, value: Any, *, required: bool) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ClaudeChildBindingError(
            "CHILD_POLICY_INVALID", f"{name} must be a list of strings"
        )
    normalized = tuple(
        sorted({_bounded_text(name, item, max_bytes=2048) for item in value})
    )
    if required and not normalized:
        raise ClaudeChildBindingError(
            "CHILD_POLICY_INVALID", f"{name} must not be empty"
        )
    return normalized


def _policy_path() -> Path:
    configured = os.environ.get(CHILD_POLICY_ENV_VAR, "").strip()
    if configured:
        return Path(configured).expanduser()
    home = os.environ.get("VIBAP_HOME", "").strip()
    return (Path(home).expanduser() if home else DEFAULT_HOME) / CHILD_POLICY_FILENAME


def _read_private_json(path: Path, *, max_bytes: int, label: str) -> Any:
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            details = os.fstat(handle.fileno())
            if not stat.S_ISREG(details.st_mode):
                raise ClaudeChildBindingError(
                    "STATE_UNAVAILABLE", f"{label} is not a regular file"
                )
            if details.st_mode & 0o077:
                raise ClaudeChildBindingError(
                    "STATE_UNAVAILABLE", f"{label} must have mode 0600"
                )
            raw = handle.read(max_bytes + 1)
    except FileNotFoundError as exc:
        raise ClaudeChildBindingError(
            "CHILD_POLICY_UNAVAILABLE", f"{label} is not configured"
        ) from exc
    except OSError as exc:
        raise ClaudeChildBindingError(
            "STATE_UNAVAILABLE", f"{label} cannot be read safely"
        ) from exc
    if len(raw) > max_bytes:
        raise ClaudeChildBindingError(
            "STATE_UNAVAILABLE", f"{label} exceeds its size limit"
        )
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClaudeChildBindingError(
            "CHILD_POLICY_INVALID", f"{label} is not valid UTF-8 JSON"
        ) from exc


def load_claude_child_policy_registry(
    path: Path | None = None,
) -> dict[str, ClaudeChildPolicy]:
    """Load and validate every operator-authored agent-type policy."""

    payload = _read_private_json(
        path or _policy_path(),
        max_bytes=MAX_POLICY_BYTES,
        label="Claude child policy registry",
    )
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "agent_types"}
        or payload.get("schema_version") != CHILD_POLICY_SCHEMA
        or not isinstance(payload.get("agent_types"), dict)
        or len(payload["agent_types"]) > MAX_AGENT_TYPES
    ):
        raise ClaudeChildBindingError(
            "CHILD_POLICY_INVALID", "Claude child policy registry schema is invalid"
        )
    policies: dict[str, ClaudeChildPolicy] = {}
    for raw_agent_type, entry in payload["agent_types"].items():
        requested_type = _bounded_text("agent_type", raw_agent_type)
        if not isinstance(entry, dict):
            raise ClaudeChildBindingError(
                "CHILD_POLICY_INVALID", "child policy entry must be an object"
            )
        policies[requested_type] = _parse_claude_child_policy(requested_type, entry)
    if not policies:
        raise ClaudeChildBindingError(
            "CHILD_POLICY_INVALID", "Claude child policy registry must not be empty"
        )
    return dict(sorted(policies.items()))


def _parse_claude_child_policy(
    requested_type: str, entry: Mapping[str, Any]
) -> ClaudeChildPolicy:
    expected = {
        "child_agent_id",
        "mission",
        "allowed_tools",
        "resource_scope",
        "max_tool_calls",
        "ttl_s",
    }
    if set(entry) != expected:
        raise ClaudeChildBindingError(
            "CHILD_POLICY_INVALID", "child policy fields are invalid"
        )
    child_agent_id = _bounded_text("child_agent_id", entry["child_agent_id"])
    mission = _bounded_text("mission", entry["mission"], max_bytes=4096)
    allowed_tools = _string_list("allowed_tools", entry["allowed_tools"], required=True)
    if any(tool in {"*", "Agent", "Task"} for tool in allowed_tools):
        raise ClaudeChildBindingError(
            "CHILD_POLICY_INVALID",
            "wildcard, Agent, and Task authority are unsupported by the CLI binding profile",
        )
    resource_scope = _string_list(
        "resource_scope", entry["resource_scope"], required=False
    )
    max_tool_calls = entry["max_tool_calls"]
    ttl_s = entry["ttl_s"]
    if (
        isinstance(max_tool_calls, bool)
        or not isinstance(max_tool_calls, int)
        or max_tool_calls <= 0
    ):
        raise ClaudeChildBindingError(
            "CHILD_POLICY_INVALID", "max_tool_calls must be a positive integer"
        )
    if isinstance(ttl_s, bool) or not isinstance(ttl_s, int) or ttl_s <= 0:
        raise ClaudeChildBindingError(
            "CHILD_POLICY_INVALID", "ttl_s must be a positive integer"
        )
    normalized = {
        "agent_type": requested_type,
        "child_agent_id": child_agent_id,
        "mission": mission,
        "allowed_tools": list(allowed_tools),
        "resource_scope": list(resource_scope),
        "max_tool_calls": max_tool_calls,
        "ttl_s": ttl_s,
    }
    return ClaudeChildPolicy(
        agent_type=requested_type,
        child_agent_id=child_agent_id,
        mission=mission,
        allowed_tools=allowed_tools,
        resource_scope=resource_scope,
        max_tool_calls=max_tool_calls,
        ttl_s=ttl_s,
        fingerprint=_digest(normalized),
    )


def load_claude_child_policy(agent_type: str) -> ClaudeChildPolicy:
    """Load one exact operator-authored agent-type policy."""

    requested_type = _bounded_text("agent_type", agent_type)
    policies = load_claude_child_policy_registry()
    try:
        return policies[requested_type]
    except KeyError as exc:
        raise ClaudeChildBindingError(
            "CHILD_POLICY_MISSING",
            f"no child policy is registered for agent type {requested_type}",
        ) from exc


def _process_lock(path: Path) -> threading.RLock:
    key = str(path.resolve(strict=False))
    with _PROCESS_LOCKS_GUARD:
        lock = _PROCESS_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _PROCESS_LOCKS[key] = lock
        return lock


class _ClaudeChildBindingStore:
    def __init__(self, trace_dir: Path, parent_jti: str) -> None:
        self.parent_jti = parent_jti
        self.path = trace_dir / CHILD_BINDING_FILENAME
        self.lock_path = trace_dir / CHILD_BINDING_LOCK_FILENAME
        trace_dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        os.close(fd)
        self.lock_path.chmod(0o600)

    def _empty(self) -> dict[str, Any]:
        return {
            "schema": CHILD_BINDING_SCHEMA,
            "parent_jti": self.parent_jti,
            "reservations": {},
            "bindings": {},
            "blocked_bindings": {},
            "taint": None,
        }

    def _validate(self, state: Any) -> None:
        if (
            not isinstance(state, dict)
            or set(state)
            != {
                "schema",
                "parent_jti",
                "reservations",
                "bindings",
                "blocked_bindings",
                "taint",
            }
            or state.get("schema") != CHILD_BINDING_SCHEMA
            or state.get("parent_jti") != self.parent_jti
            or not isinstance(state.get("reservations"), dict)
            or not isinstance(state.get("bindings"), dict)
            or not isinstance(state.get("blocked_bindings"), dict)
            or len(state["reservations"]) > MAX_RECORDS
            or len(state["bindings"]) > MAX_RECORDS
            or len(state["blocked_bindings"]) > MAX_RECORDS
        ):
            raise ClaudeChildBindingError(
                "BINDING_STATE_UNAVAILABLE", "child binding state is invalid"
            )
        if state["taint"] is not None:
            try:
                _bounded_text("taint", state["taint"], max_bytes=512)
            except ClaudeChildBindingError as exc:
                raise ClaudeChildBindingError(
                    "BINDING_STATE_UNAVAILABLE", "child binding taint is invalid"
                ) from exc
        allowed_fields = {
            "handle",
            "agent_type",
            "policy_fingerprint",
            "status",
            "expires_at",
            "binding_key",
            "terminal_code",
        }
        for request_key, record in state["reservations"].items():
            if (
                not _is_hex_digest(request_key)
                or not isinstance(record, dict)
                or not set(record).issubset(allowed_fields)
                or not {
                    "handle",
                    "agent_type",
                    "policy_fingerprint",
                    "status",
                    "expires_at",
                }.issubset(record)
                or not _is_hex_digest(record["policy_fingerprint"])
                or record["status"] not in _HANDLE_STATES
                or not _is_finite_positive(record["expires_at"])
            ):
                raise ClaudeChildBindingError(
                    "BINDING_STATE_UNAVAILABLE", "child reservation is malformed"
                )
            try:
                GovernedSubagentHandle(record["handle"])
                _bounded_text("agent_type", record["agent_type"])
                if "terminal_code" in record:
                    _bounded_text(
                        "terminal_code", record["terminal_code"], max_bytes=256
                    )
            except (ClaudeChildBindingError, GovernedSubagentError, ValueError) as exc:
                raise ClaudeChildBindingError(
                    "BINDING_STATE_UNAVAILABLE", "child reservation is malformed"
                ) from exc
            binding_key = record.get("binding_key")
            if binding_key is not None and not _is_hex_digest(binding_key):
                raise ClaudeChildBindingError(
                    "BINDING_STATE_UNAVAILABLE",
                    "child reservation binding is malformed",
                )
            if record["status"] == "pending" and binding_key is not None:
                raise ClaudeChildBindingError(
                    "BINDING_STATE_UNAVAILABLE", "pending child has a binding index"
                )
        for binding_key, request_key in state["bindings"].items():
            if (
                not _is_hex_digest(binding_key)
                or request_key not in state["reservations"]
                or state["reservations"][request_key].get("binding_key") != binding_key
            ):
                raise ClaudeChildBindingError(
                    "BINDING_STATE_UNAVAILABLE", "child binding index is malformed"
                )
        for request_key, record in state["reservations"].items():
            binding_key = record.get("binding_key")
            if (
                binding_key is not None
                and state["bindings"].get(binding_key) != request_key
            ):
                raise ClaudeChildBindingError(
                    "BINDING_STATE_UNAVAILABLE",
                    "child binding reverse index is malformed",
                )
        for binding_key, reason in state["blocked_bindings"].items():
            if (
                not _is_hex_digest(binding_key)
                or reason not in _BLOCKED_BINDING_REASONS
                or binding_key in state["bindings"]
            ):
                raise ClaudeChildBindingError(
                    "BINDING_STATE_UNAVAILABLE", "blocked child binding is malformed"
                )

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._empty()
        payload = _read_private_json(
            self.path, max_bytes=MAX_BINDING_BYTES, label="Claude child binding state"
        )
        self._validate(payload)
        return payload

    def _persist(self, state: dict[str, Any]) -> None:
        self._validate(state)
        material = _canonical_json(state)
        if len(material) > MAX_BINDING_BYTES:
            raise ClaudeChildBindingError(
                "BINDING_STATE_UNAVAILABLE", "child binding state exceeds its limit"
            )
        temporary = self.path.with_name(f"{self.path.name}.{uuid.uuid4().hex}.tmp")
        fd: int | None = None
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                fd = None
                handle.write(material)
                handle.write(b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            self.path.chmod(0o600)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            if fd is not None:
                os.close(fd)
            with contextlib.suppress(OSError):
                temporary.unlink()
            raise

    @contextlib.contextmanager
    def transaction(self):
        with _process_lock(self.lock_path):
            with self.lock_path.open("a+b") as lock_handle:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                state = self._load()
                before = _canonical_json(state)
                try:
                    yield state
                finally:
                    after = _canonical_json(state)
                    if after != before:
                        self._persist(state)
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


class ClaudeChildRuntime:
    """Per-event facade over persisted proxy, adapter, and binding state."""

    def __init__(
        self,
        *,
        trace_dir: Path,
        parent_token: str,
        parent_claims: Mapping[str, Any],
        private_key: ec.EllipticCurvePrivateKey,
    ) -> None:
        self.parent_jti = str(parent_claims.get("jti", ""))
        _bounded_text("parent_jti", self.parent_jti)
        try:
            parsed_parent_jti = uuid.UUID(self.parent_jti)
        except ValueError as exc:
            raise ClaudeChildBindingError(
                "PARENT_SESSION_INVALID", "parent grant id is not a UUID"
            ) from exc
        if str(parsed_parent_jti) != self.parent_jti.lower():
            raise ClaudeChildBindingError(
                "PARENT_SESSION_INVALID", "parent grant id is not canonical"
            )
        authority_dir = trace_dir / ".child-authority"
        authority_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        authority_dir.chmod(0o700)
        self.proxy = GovernanceProxy(
            log_path=authority_dir / "governance.jsonl",
            receipts_log_path=authority_dir / "proxy-receipts.jsonl",
            state_dir=authority_dir / "proxy-state",
            public_key=private_key.public_key(),
            private_key=private_key,
        )
        try:
            parent_session = self.proxy.get_session(self.parent_jti)
        except ValueError:
            try:
                parent_session = self.proxy.start_session(parent_token)
            except ValueError:
                parent_session = self.proxy.get_session(self.parent_jti)
        if parent_session.jti != self.parent_jti:
            raise ClaudeChildBindingError(
                "PARENT_SESSION_INVALID", "persisted parent session does not match"
            )
        self.adapter = GovernedSubagentAdapter(
            proxy=self.proxy,
            parent_session=parent_session,
            delegation_private_key=private_key,
            state_dir=authority_dir / "adapter-state",
        )
        self.store = _ClaudeChildBindingStore(trace_dir, self.parent_jti)
        self._reconcile()

    @staticmethod
    def _request_key(parent_jti: str, session_id: str, tool_use_id: str) -> str:
        return hashlib.sha256(
            f"{parent_jti}\0{session_id}\0{tool_use_id}".encode("utf-8")
        ).hexdigest()

    def _binding_key(self, session_id: str, agent_id: str) -> str:
        return hashlib.sha256(
            f"{self.parent_jti}\0{session_id}\0{agent_id}".encode("utf-8")
        ).hexdigest()

    def _reconcile(self) -> None:
        self.adapter.recover()
        with self.store.transaction() as state:
            for record in state["reservations"].values():
                if record["status"] in {"closed", "expired"}:
                    continue
                try:
                    snapshot = self.adapter.lifecycle_snapshot(record["handle"])
                except GovernedSubagentError:
                    record["status"] = "quarantined"
                    record["terminal_code"] = "ADAPTER_STATE_UNAVAILABLE"
                    continue
                adapter_status = str(snapshot["status"])
                if adapter_status == "expired":
                    record["status"] = "expired"
                    record["terminal_code"] = "HANDLE_EXPIRED"
                elif adapter_status in {"quarantined", "cancelled"}:
                    record["status"] = "quarantined"
                    record["terminal_code"] = "ADAPTER_QUARANTINED"
                elif adapter_status == "closed":
                    record["status"] = "closed"

    def synchronize_parent_usage(
        self, *, tool_call_count: int, tool_call_count_by_class: Mapping[str, int]
    ) -> dict[str, Any]:
        return self.proxy.synchronize_external_tool_usage_floor(
            self.parent_jti,
            tool_call_count=tool_call_count,
            tool_call_count_by_class=tool_call_count_by_class,
        )

    def reserve_agent(
        self,
        *,
        session_id: str,
        tool_use_id: str,
        agent_type: str,
        parent_usage: Mapping[str, Any],
    ) -> ClaudeChildBindingOutcome:
        session = _bounded_text("session_id", session_id)
        operation = _bounded_text("tool_use_id", tool_use_id)
        policy = load_claude_child_policy(agent_type)
        request_key = self._request_key(self.parent_jti, session, operation)
        with self.store.transaction() as state:
            existing = state["reservations"].get(request_key)
            if existing is not None:
                if existing["policy_fingerprint"] != policy.fingerprint:
                    raise ClaudeChildBindingError(
                        "RESERVATION_CONFLICT",
                        "Agent tool_use_id was reused with a different child policy",
                    )
                if existing["status"] in {"pending", "bound"}:
                    return ClaudeChildBindingOutcome(
                        state=str(existing["status"]),
                        reason="existing child reservation recovered",
                        handle=str(existing["handle"]),
                        policy_fingerprint=policy.fingerprint,
                    )
                raise ClaudeChildBindingError(
                    "RESERVATION_CLOSED", "closed child reservation cannot be replayed"
                )
        used = int(parent_usage.get("tool_call_count", 0))
        reserved = int(parent_usage.get("delegated_budget_reserved", 0))
        ceiling = int(parent_usage.get("max_tool_calls", 0))
        available_after_dispatch = max(0, ceiling - used - reserved - 1)
        if policy.max_tool_calls > available_after_dispatch:
            raise ClaudeChildBindingError(
                "CHILD_BUDGET_DENIED",
                "child budget plus Agent dispatch exceeds parent budget",
            )
        try:
            handle = self.adapter.spawn(
                GovernedSubagentRequest(
                    request_id=request_key,
                    child_agent_id=policy.child_agent_id,
                    mission=policy.mission,
                    allowed_tools=policy.allowed_tools,
                    resource_scope=policy.resource_scope,
                    max_tool_calls=policy.max_tool_calls,
                    ttl_s=policy.ttl_s,
                )
            )
            snapshot = self.adapter.lifecycle_snapshot(handle)
        except (GovernedSubagentError, PermissionError, ValueError) as exc:
            raise ClaudeChildBindingError(
                "CHILD_RESERVATION_DENIED", "child authority could not be attenuated"
            ) from exc
        with self.store.transaction() as state:
            existing = state["reservations"].get(request_key)
            if existing is not None and (
                existing["handle"] != str(handle)
                or existing["policy_fingerprint"] != policy.fingerprint
            ):
                raise ClaudeChildBindingError(
                    "RESERVATION_CONFLICT", "concurrent child reservation disagrees"
                )
            state["reservations"][request_key] = {
                "handle": str(handle),
                "agent_type": policy.agent_type,
                "policy_fingerprint": policy.fingerprint,
                "status": "pending",
                "expires_at": float(snapshot["expires_at"]),
            }
        return ClaudeChildBindingOutcome(
            state="pending",
            reason="attenuated child authority reserved before Agent dispatch",
            handle=str(handle),
            policy_fingerprint=policy.fingerprint,
        )

    def _cancel_handles(self, handles: list[str]) -> None:
        for handle in handles:
            try:
                self.adapter.cancel(handle)
            except (GovernedSubagentError, PermissionError, ValueError):
                # State is already fail-closed. Recovery will preserve an
                # uncertain or expired adapter record rather than reopening it.
                continue

    def bind_start(
        self, *, session_id: str, agent_id: str, agent_type: str
    ) -> ClaudeChildBindingOutcome:
        session = _bounded_text("session_id", session_id)
        observed_type = _bounded_text("agent_type", agent_type)
        if not agent_id:
            handles: list[str] = []
            with self.store.transaction() as state:
                state["taint"] = "SubagentStart missing agent_id"
                for record in state["reservations"].values():
                    if (
                        record["status"] == "pending"
                        and record["agent_type"] == observed_type
                    ):
                        record["status"] = "quarantined"
                        record["terminal_code"] = "START_AGENT_ID_MISSING"
                        handles.append(str(record["handle"]))
            self._cancel_handles(handles)
            return ClaudeChildBindingOutcome(
                state="quarantined",
                reason="SubagentStart missing agent_id; trace has an unbound child",
            )
        observed_agent = _bounded_text("agent_id", agent_id)
        binding_key = self._binding_key(session, observed_agent)
        cancel: list[str] = []
        outcome: ClaudeChildBindingOutcome
        with self.store.transaction() as state:
            if binding_key in state["blocked_bindings"]:
                return ClaudeChildBindingOutcome(
                    state="observed_only",
                    reason=(
                        "subagent stopped before a binding could be established; "
                        "not bound"
                    ),
                )
            existing_request = state["bindings"].get(binding_key)
            if existing_request is not None:
                record = state["reservations"][existing_request]
                return ClaudeChildBindingOutcome(
                    state=str(record["status"]),
                    reason="existing child binding recovered",
                    handle=str(record["handle"])
                    if record["status"] == "bound"
                    else None,
                    policy_fingerprint=str(record["policy_fingerprint"]),
                )
            now = time.time()
            expired_for_type = False
            eligible: list[tuple[str, dict[str, Any]]] = []
            for request_key, record in state["reservations"].items():
                if record["agent_type"] != observed_type:
                    continue
                if record["status"] == "expired":
                    expired_for_type = True
                    continue
                if record["status"] != "pending":
                    continue
                if float(record["expires_at"]) <= now:
                    record["status"] = "expired"
                    record["terminal_code"] = "HANDLE_EXPIRED"
                    cancel.append(str(record["handle"]))
                    expired_for_type = True
                    continue
                eligible.append((request_key, record))
            if not eligible:
                state["blocked_bindings"][binding_key] = (
                    "expired" if expired_for_type else "missing_reservation"
                )
                outcome = ClaudeChildBindingOutcome(
                    state="expired" if expired_for_type else "observed_only",
                    reason=(
                        "eligible child reservation expired"
                        if expired_for_type
                        else "SubagentStart has no eligible pending child reservation; not bound"
                    ),
                )
            elif len({record["policy_fingerprint"] for _, record in eligible}) != 1:
                for _request_key, record in eligible:
                    record["status"] = "quarantined"
                    record["terminal_code"] = "SAME_TYPE_POLICY_AMBIGUOUS"
                    cancel.append(str(record["handle"]))
                state["blocked_bindings"][binding_key] = "ambiguous_policy"
                outcome = ClaudeChildBindingOutcome(
                    state="quarantined",
                    reason="same-type pending child policies are ambiguous; no binding adopted",
                )
            else:
                request_key, record = sorted(eligible, key=lambda item: item[0])[0]
                record["status"] = "bound"
                record["binding_key"] = binding_key
                state["bindings"][binding_key] = request_key
                outcome = ClaudeChildBindingOutcome(
                    state="bound",
                    reason="observed Claude child bound to attenuated authority",
                    handle=str(record["handle"]),
                    policy_fingerprint=str(record["policy_fingerprint"]),
                )
        self._cancel_handles(cancel)
        return outcome

    def resolve_child(
        self, *, session_id: str, agent_id: str
    ) -> ClaudeChildBindingOutcome | None:
        session = _bounded_text("session_id", session_id)
        if not agent_id:
            with self.store.transaction() as state:
                taint = state["taint"]
            if taint:
                raise ClaudeChildBindingError(
                    "UNBOUND_CHILD_TRACE", f"trace contains an unbound child: {taint}"
                )
            return None
        observed_agent = _bounded_text("agent_id", agent_id)
        binding_key = self._binding_key(session, observed_agent)
        with self.store.transaction() as state:
            request_key = state["bindings"].get(binding_key)
            if request_key is None:
                raise ClaudeChildBindingError(
                    "CHILD_BINDING_MISSING",
                    "child binding is missing; parent authority fallback is forbidden",
                )
            record = state["reservations"][request_key]
            status = str(record["status"])
            if status != "bound":
                raise ClaudeChildBindingError(
                    f"CHILD_BINDING_{status.upper()}",
                    f"child binding is {status}; parent authority fallback is forbidden",
                )
            if float(record["expires_at"]) <= time.time():
                record["status"] = "expired"
                record["terminal_code"] = "HANDLE_EXPIRED"
                raise ClaudeChildBindingError(
                    "CHILD_BINDING_EXPIRED", "child binding is expired"
                )
            return ClaudeChildBindingOutcome(
                state="bound",
                reason="child binding resolved",
                handle=str(record["handle"]),
                policy_fingerprint=str(record["policy_fingerprint"]),
            )

    def stop(
        self, *, session_id: str, agent_id: str, agent_type: str
    ) -> ClaudeChildBindingOutcome:
        session = _bounded_text("session_id", session_id)
        _bounded_text("agent_type", agent_type)
        if not agent_id:
            handles: list[str] = []
            with self.store.transaction() as state:
                state["taint"] = "SubagentStop missing agent_id"
                for record in state["reservations"].values():
                    if record["status"] in {"pending", "bound"}:
                        record["status"] = "quarantined"
                        record["terminal_code"] = "STOP_AGENT_ID_MISSING"
                        handles.append(str(record["handle"]))
            self._cancel_handles(handles)
            return ClaudeChildBindingOutcome(
                state="quarantined", reason="SubagentStop missing agent_id"
            )
        observed_agent = _bounded_text("agent_id", agent_id)
        binding_key = self._binding_key(session, observed_agent)
        with self.store.transaction() as state:
            request_key = state["bindings"].get(binding_key)
            if request_key is None:
                state["blocked_bindings"][binding_key] = "stop_before_start"
                return ClaudeChildBindingOutcome(
                    state="observed_only",
                    reason="SubagentStop observed before a child binding",
                )
            record = state["reservations"][request_key]
            if record["status"] == "closed":
                return ClaudeChildBindingOutcome(
                    state="closed",
                    reason="duplicate SubagentStop was idempotently suppressed",
                    policy_fingerprint=str(record["policy_fingerprint"]),
                )
            if record["status"] != "bound":
                return ClaudeChildBindingOutcome(
                    state=str(record["status"]),
                    reason="SubagentStop found no active child authority",
                    policy_fingerprint=str(record["policy_fingerprint"]),
                )
            handle = str(record["handle"])
        try:
            self.adapter.close(handle)
        except GovernedSubagentError as exc:
            with self.store.transaction() as state:
                record = state["reservations"][request_key]
                record["status"] = "quarantined"
                record["terminal_code"] = exc.code
            return ClaudeChildBindingOutcome(
                state="quarantined",
                reason="child close was uncertain and authority was quarantined",
            )
        with self.store.transaction() as state:
            record = state["reservations"][request_key]
            record["status"] = "closed"
        return ClaudeChildBindingOutcome(
            state="closed",
            reason="child authority closed and attested",
            policy_fingerprint=str(record["policy_fingerprint"]),
        )

    def child_policy(self, handle: str) -> dict[str, Any]:
        return self.adapter.child_policy(GovernedSubagentHandle(handle))

    def authorize_child_tool(
        self,
        *,
        handle: str,
        operation_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> GovernedToolResult:
        return self.adapter.authorize_external_tool(
            GovernedSubagentHandle(handle),
            operation_id=operation_id,
            tool_name=tool_name,
            arguments=arguments,
        )

    def settle_child_tool(
        self, *, handle: str, operation_id: str, result: Any
    ) -> GovernedToolResult:
        return self.adapter.settle_external_tool(
            GovernedSubagentHandle(handle),
            operation_id=operation_id,
            result=result,
        )

    def quarantine_child_tool(
        self, *, handle: str, operation_id: str, terminal_code: str
    ) -> None:
        self.adapter.quarantine_external_tool(
            GovernedSubagentHandle(handle),
            operation_id=operation_id,
            terminal_code=terminal_code,
        )

    def cancel_reservation(self, handle: str, *, terminal_code: str) -> None:
        with self.store.transaction() as state:
            for record in state["reservations"].values():
                if record["handle"] == handle and record["status"] in {
                    "pending",
                    "bound",
                }:
                    record["status"] = "quarantined"
                    record["terminal_code"] = terminal_code
        self._cancel_handles([handle])
