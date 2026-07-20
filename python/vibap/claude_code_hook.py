"""Ardur runtime governance adapter for Claude Code hooks.

Wires Claude Code's PreToolUse / PostToolUse hooks to Ardur's policy
backends and signed Execution Receipts. Default mode is stateless per call:
each invocation is a fresh `python -m vibap.claude_code_hook <phase>` process
that reads hook input from stdin, writes hook output to stdout, and appends
one receipt to the per-trace JSONL chain. The `pre` phase can optionally try
a local daemon fast path first, then fall back to the in-process handler.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import time
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import jwt

from .passport import (
    DEFAULT_HOME,
    _ensure_default_home_dir,
    generate_keypair,
    load_private_key,
    resolve_keys_dir,
    verify_passport,
)


PASSPORT_ENV_VAR = "ARDUR_MISSION_PASSPORT"

CHAIN_DIR_ENV_VAR = "ARDUR_CC_HOOK_DIR"
DEFAULT_CHAIN_DIR = DEFAULT_HOME / "claude-code-hook"
CHAIN_FILENAME = "receipts.jsonl"
SUBAGENT_REGISTRY_FILENAME = "subagents.jsonl"
CLAUDE_CODE_VISIBILITY_FULL = "full"
HOOK_INPUT_MAX_CHARS = 1024 * 1024
HOOK_STATE_MAX_BYTES = 16 * 1024 * 1024
HOOK_STATE_MAX_RECEIPTS = 8192
HOOK_SESSION_CACHE_MAX_ENTRIES = 128


def _coerce_mapping(value: Any) -> dict[str, Any]:
    """Return ``value`` as a dict, tolerating non-mapping JSON values.

    Claude Code hook payloads are externally controlled and may carry any JSON
    type for fields that are nominally objects (``tool_input``,
    ``tool_response``, nested ``measurements``/``lifecycle`` blocks). A bare
    ``dict(value or {})`` raises ``ValueError``/``TypeError`` for strings,
    ints, lists, or bools, which would crash the hook handler and emit a raw
    traceback on stderr instead of a structured decision. Coerce non-mappings
    to an empty dict so the handler fails safe with a normal deny/continue
    response.
    """
    if isinstance(value, Mapping):
        return dict(value)
    return {}


_SAFE_TRACE_ID_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")


def _read_hook_input(stream: Any, *, max_chars: int = HOOK_INPUT_MAX_CHARS) -> str:
    raw = stream.read(max_chars + 1)
    if len(raw) > max_chars:
        raise ValueError(f"hook input exceeds {max_chars} character limit")
    return raw


def _normalize_trace_id(value: Any) -> str | None:
    trace_id = str(value if value is not None else "").strip()
    if not trace_id:
        return None
    if trace_id in {".", ".."}:
        return None
    if "/" in trace_id or "\\" in trace_id:
        return None
    if _SAFE_TRACE_ID_RE.fullmatch(trace_id) is None:
        return None
    return trace_id


def _trace_id_or_stable_fallback(value: Any) -> str:
    normalized = _normalize_trace_id(value)
    if normalized is not None:
        return normalized
    raw = str(value if value is not None else "").strip()
    if not raw:
        return "trace-unknown"
    return "trace-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _contained_trace_dir(*, chain_dir: Path, trace_id: str) -> Path:
    safe_trace_id = _normalize_trace_id(trace_id)
    if safe_trace_id is None:
        raise ValueError(f"unsafe Claude Code trace id: {trace_id!r}")

    base = chain_dir.expanduser()
    candidate = base / safe_trace_id
    resolved_base = base.resolve(strict=False)
    resolved_candidate = candidate.resolve(strict=False)
    if resolved_candidate == resolved_base:
        raise ValueError(f"Claude Code trace id resolves to chain root: {trace_id!r}")
    try:
        resolved_candidate.relative_to(resolved_base)
    except ValueError as exc:
        raise ValueError(f"Claude Code trace id escapes chain dir: {trace_id!r}") from exc
    return candidate


@dataclass(frozen=True)
class ChainState:
    chain_dir: Path
    trace_id: str

    @property
    def trace_dir(self) -> Path:
        return _contained_trace_dir(chain_dir=self.chain_dir, trace_id=self.trace_id)

    @property
    def file(self) -> Path:
        return self.trace_dir / CHAIN_FILENAME

    @property
    def lock_file(self) -> Path:
        return self.trace_dir / ".lock"

    @property
    def subagents_file(self) -> Path:
        return self.trace_dir / SUBAGENT_REGISTRY_FILENAME


@dataclass
class _VerifiedSessionCacheEntry:
    passport_digest: str
    chain_hasher: Any
    chain_size: int
    tool_call_count: int
    by_class: dict[str, int]


_VERIFIED_SESSION_CACHE: "OrderedDict[str, _VerifiedSessionCacheEntry]" = OrderedDict()


def resolve_chain_state(*, trace_id: str) -> ChainState:
    base = Path(os.environ.get(CHAIN_DIR_ENV_VAR, str(DEFAULT_CHAIN_DIR))).expanduser()
    safe_trace_id = _normalize_trace_id(trace_id)
    if safe_trace_id is None:
        raise ValueError(f"unsafe Claude Code trace id: {trace_id!r}")
    # When the chain dir falls through to the DEFAULT_HOME-derived default,
    # materialise the home with 0o700 before creating trace directories.
    if CHAIN_DIR_ENV_VAR not in os.environ:
        _ensure_default_home_dir()
    state = ChainState(chain_dir=base, trace_id=safe_trace_id)
    state.trace_dir.mkdir(parents=True, exist_ok=True)
    _contained_trace_dir(chain_dir=state.chain_dir, trace_id=state.trace_id)
    return state


@contextmanager
def _locked(state: ChainState):
    # Mirror the proxy.py lock pattern: open the lock file in ``a+b`` so the
    # file is created on first use and we don't race against a stale-touch
    # being deleted between ``.touch()`` and ``open()``. POSIX flock is
    # advisory and per-process; that's sufficient for the per-call hook
    # process model — see the README for the threaded-host caveat.
    state.lock_file.parent.mkdir(parents=True, exist_ok=True)
    with open(state.lock_file, "a+b") as fd:
        fcntl.flock(fd.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd.fileno(), fcntl.LOCK_UN)


def append_receipt(state: ChainState, signed_jwt: str) -> None:
    """Atomically append a signed receipt JWT to the trace's chain log."""
    with _locked(state):
        _append_receipt_unlocked(state, signed_jwt)


def _append_receipt_unlocked(
    state: ChainState,
    signed_jwt: str,
    *,
    receipt_obj: Any | None = None,
) -> None:
    with open(state.file, "a", encoding="utf-8") as f:
        f.write(signed_jwt.strip() + "\n")
    from .transparency import queue_receipt_anchor_best_effort

    queue_receipt_anchor_best_effort(signed_jwt, state.file)
    if receipt_obj is not None:
        _advance_verified_session_cache_unlocked(state, signed_jwt, receipt_obj)


def _append_subagent_event_unlocked(state: ChainState, record: Mapping[str, Any]) -> None:
    with open(state.subagents_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(dict(record), sort_keys=True, separators=(",", ":")) + "\n")


def previous_receipt_hash(state: ChainState) -> str | None:
    """Return ``sha-256:<hex>`` of the last appended JWT, or None if empty.

    Returns None only when the chain file is genuinely absent or empty.
    Permission errors and other unexpected I/O failures propagate — a
    misconfigured chain directory should fail loudly, not silently emit
    unchained receipts.
    """
    with _locked(state):
        return _previous_receipt_hash_unlocked(state)


def _previous_receipt_hash_unlocked(state: ChainState) -> str | None:
    if not state.file.exists():
        return None
    with open(state.file, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        if size == 0:
            return None
        # Read the last 16KB to find the last full line. Receipt JWTs
        # are bounded well below this; if a single receipt exceeds 16KB
        # something has gone wrong upstream.
        read_size = min(size, 16 * 1024)
        f.seek(-read_size, os.SEEK_END)
        tail = f.read(read_size).decode("utf-8", errors="replace")
    lines = [line.strip() for line in tail.splitlines() if line.strip()]
    if not lines:
        return None
    last_jwt = lines[-1]
    return "sha-256:" + hashlib.sha256(last_jwt.encode("utf-8")).hexdigest()


class MissionLoadError(RuntimeError):
    """Raised when no usable Mission Passport can be located or verified."""


class HookInputNotObjectError(ValueError):
    """Raised when stdin parses but is not a hook-event JSON object."""


def _candidate_passport_sources() -> list[tuple[str, str]]:
    """Return a list of ``(source_label, raw_jwt)`` pairs to try in order.

    Priority (first hit wins, but every source is tried in turn until one
    verifies):

    1. ``ARDUR_MISSION_PASSPORT`` env var. Either a literal JWT (detected
       by ``startswith("eyJ") and "." in value``) or a path to a JWT file.
    2. ``$VIBAP_HOME/active_mission.jwt`` (or ``DEFAULT_HOME/...`` if
       VIBAP_HOME is unset or empty).
    3. ``~/.vibap/active_mission.jwt`` — the global fallback. Skipped when
       it resolves to the same path as priority 2.

    The ``"eyJ"`` heuristic is tighter than ``"ey"``: real ES256 passport
    headers always base64url-encode to start with ``eyJ`` (the bytes for
    ``{"``). A path like ``eya/relative/file.json`` would have falsely
    matched ``ey`` and been treated as a literal JWT.
    """
    sources: list[tuple[str, str]] = []
    env_value = os.environ.get(PASSPORT_ENV_VAR, "").strip()
    if env_value:
        if env_value.startswith("eyJ") and "." in env_value:
            sources.append((PASSPORT_ENV_VAR + " (literal JWT)", env_value))
        else:
            path = Path(env_value).expanduser()
            if path.is_file():
                sources.append(
                    (PASSPORT_ENV_VAR + f" ({path})", path.read_text(encoding="utf-8").strip())
                )

    # Priority 2: VIBAP_HOME (or DEFAULT_HOME when env is unset/empty).
    home_env = os.environ.get("VIBAP_HOME", "").strip()
    home_from_env = Path(home_env).expanduser() if home_env else DEFAULT_HOME
    default_path = home_from_env / "active_mission.jwt"
    if default_path.is_file():
        sources.append((str(default_path), default_path.read_text(encoding="utf-8").strip()))

    # Priority 3: ~/.vibap/active_mission.jwt (global default), only when
    # it resolves differently from priority 2.
    global_default = Path.home().expanduser() / ".vibap" / "active_mission.jwt"
    if global_default != default_path and global_default.is_file():
        sources.append((str(global_default), global_default.read_text(encoding="utf-8").strip()))

    return sources


def load_active_passport(*, keys_dir: Path | None = None) -> dict[str, Any]:
    """Load and verify the active Mission Passport.

    Returns the verified claims dict on success.

    Raises :class:`MissionLoadError` when:
      - no candidate passport source is discoverable;
      - every candidate passport fails signature/expiry/iat or
        delegation-chain validation.

    Priority order is documented on :func:`_candidate_passport_sources`.

    Side effect: if no Ardur keypair exists at ``keys_dir``, one will be
    generated on disk (per the existing :func:`passport.generate_keypair`
    convention). This is consistent with how ``ardur issue`` and the
    proxy bootstrap their key material; callers that want strict
    read-only behaviour should pre-create the keypair before invoking.
    """
    keys_path = resolve_keys_dir(keys_dir)
    _, public_key = generate_keypair(keys_dir=keys_path)

    sources = _candidate_passport_sources()
    if not sources:
        raise MissionLoadError(
            "no active mission passport found. "
            f"Set {PASSPORT_ENV_VAR} to a JWT file path (or literal JWT), "
            "or run `ardur issue --mission ...` first."
        )
    last_error: Exception | None = None
    for label, token in sources:
        try:
            return verify_passport(token, public_key)
        except (jwt.InvalidTokenError, ValueError, PermissionError) as exc:
            # PermissionError surfaces from delegation-chain validation
            # in passport.verify_passport. We re-raise it as
            # MissionLoadError to keep the public API contract narrow:
            # all token-validation failures become MissionLoadError
            # (with the specific cause preserved as ``last_error``).
            last_error = exc
            continue
    raise MissionLoadError(
        f"all candidate passports failed verification (last error: {last_error}); "
        f"sources tried: {[label for label, _ in sources]}"
    )


# ─── PreToolUse handler ───────────────────────────────────────────────────────

HOOK_VERIFIER_ID = "ardur-claude-code-hook"


def _pre_tool_use_deny_output(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _trace_id_from_claims(claims: dict[str, Any]) -> str:
    override = _normalize_trace_id(os.environ.get("ARDUR_TRACE_ID", ""))
    if override is not None:
        return override
    return _trace_id_or_stable_fallback(claims.get("jti", "trace-unknown"))


def _stable_child_id(*, trace_id: str, session_id: str, agent_id: str) -> str:
    payload = json.dumps(
        {
            "trace_id": trace_id,
            "session_id": session_id,
            "agent_id": agent_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "child:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_text(value: str) -> dict[str, str]:
    return {"alg": "sha-256", "value": hashlib.sha256(value.encode("utf-8")).hexdigest()}


def _without_empty_values(payload: Mapping[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in payload.items():
        if value is None or value == "":
            continue
        if isinstance(value, Mapping):
            nested = _without_empty_values(value)
            if nested:
                clean[key] = nested
            continue
        clean[key] = value
    return clean


def _common_claude_code_metadata(
    hook_input: Mapping[str, Any],
    *,
    trace_id: str,
    tool_name: str,
) -> dict[str, Any]:
    return _without_empty_values(
        {
            "schema_version": "ardur.claude_code.measurements.v0.1",
            "trace_id": trace_id,
            "hook_event_name": str(hook_input.get("hook_event_name", "")),
            "claude_session_id": str(hook_input.get("session_id", "")),
            "tool_use_id": str(hook_input.get("tool_use_id", "")),
            "transcript_path": str(hook_input.get("transcript_path", "")),
            "cwd": str(hook_input.get("cwd", "")),
            "permission_mode": str(hook_input.get("permission_mode", "")),
            "tool_name": tool_name,
        }
    )


def _tool_actor_metadata(
    hook_input: Mapping[str, Any],
    *,
    trace_id: str,
    tool_name: str,
) -> dict[str, Any]:
    metadata = _common_claude_code_metadata(
        hook_input,
        trace_id=trace_id,
        tool_name=tool_name,
    )
    agent_id = str(hook_input.get("agent_id", "") or "")
    session_id = str(hook_input.get("session_id", "") or "")
    if agent_id:
        metadata.update(
            {
                "actor_kind": "subagent",
                "claude_agent_id": agent_id,
                "ardur_child_id": _stable_child_id(
                    trace_id=trace_id,
                    session_id=session_id,
                    agent_id=agent_id,
                ),
                "attribution": {
                    "mode": "exact",
                    "source": "tool_hook.agent_id",
                },
            }
        )
    elif tool_name in {"Agent", "Task"}:
        metadata.update(
            {
                "actor_kind": "parent",
                "attribution": {
                    "mode": "exact",
                    "source": "parent_agent_dispatch_tool",
                },
            }
        )
    else:
        metadata.update(
            {
                "actor_kind": "unattributed",
                "attribution": {
                    "mode": "trace_only",
                    "source": "tool hook payload did not include agent_id",
                },
            }
        )
    return metadata


def _attach_claude_code_measurements(
    receipt_obj: Any,
    hook_input: Mapping[str, Any],
    *,
    trace_id: str,
    tool_name: str,
    metadata: Mapping[str, Any] | None = None,
) -> None:
    measurements = dict(receipt_obj.measurements or {})
    claude_code = (
        dict(metadata)
        if metadata is not None
        else _tool_actor_metadata(hook_input, trace_id=trace_id, tool_name=tool_name)
    )
    claude_code["verdict"] = receipt_obj.verdict
    claude_code["receipt_id"] = receipt_obj.receipt_id
    measurements["claude_code"] = _without_empty_values(claude_code)
    receipt_obj.measurements = measurements


def _build_policy_event(
    *,
    claims: dict[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
    trace_id: str,
    phase: str = "pre",
) -> Any:
    """Build a PolicyEvent for a PreToolUse or PostToolUse hook call.

    ``phase`` is appended to the
    deterministic step_id as ``":<phase>"`` so a Pre receipt and a Post
    receipt for the same tool call carry distinct step_ids — without
    this, the (passport_jti, timestamp, tool_name, arguments) key could
    collide when both calls fall in the same wall-clock second with
    identical arguments. Audit-correlation tooling can still pair them
    via ``parent_receipt_hash`` chain linkage.

    ``budget_delta`` on the event is intentionally None: the proxy treats
    the event-level ``budget_delta`` as a structured bookkeeping object
    (``{"bucket": ..., "delta": ...}``), distinct from the raw integer
    weight the telemetry mapper places in ``arguments["budget_delta"]``.
    The integer in arguments still feeds the receipt's argument hash so
    no information is lost; mission-bound budget tracking lives in the
    proxy session state, not in the hook adapter.
    """
    from .proxy import Decision, PolicyEvent, _receipt_step_id

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    base_step_id = _receipt_step_id(
        str(claims.get("jti", "")),
        timestamp,
        tool_name,
        arguments,
    )
    return PolicyEvent(
        timestamp=timestamp,
        # Reuse the proxy's deterministic step-id derivation, then
        # append the phase so Pre and Post receipts cannot collide on
        # step_id even if they hash the same base inputs.
        step_id=f"{base_step_id}:{phase}",
        actor=str(claims.get("sub", "unknown")),
        verifier_id=HOOK_VERIFIER_ID,
        tool_name=tool_name,
        arguments=arguments,
        action_class=arguments["action_class"],
        target=arguments["target"],
        resource_family=arguments["resource_family"],
        side_effect_class=arguments["side_effect_class"],
        decision=Decision.PERMIT,
        reason="pending policy evaluation",
        passport_jti=str(claims.get("jti", "")),
        trace_id=trace_id,
        budget_delta=None,
    )


def _backfill_telemetry_fields(receipt_obj: Any, arguments: Mapping[str, Any]) -> None:
    """Copy content-class telemetry fields from ``arguments`` onto the
    ``ExecutionReceipt`` first-class optional fields.

    Backfilled fields: ``content_class``, ``content_provenance``,
    ``instruction_bearing``. These are part of the 11 declared-telemetry
    fields the proxy's fail-closed gate reads from ``arguments``. They
    are NOT populated by ``build_receipt`` (which only knows the proxy-
    event fields). Without this backfill, they pass the gate but never
    land in the signed receipt payload that auditors verify.

    Intentionally NOT backfilled: ``sensitivity``. The mapper's
    ``sensitivity`` is a tool-risk level (``low``/``medium``/``high``);
    the receipt schema's ``sensitivity`` is a data-classification level
    (``public``/``internal``/``confidential``/``restricted``/
    ``regulated``/``unknown``). The two concepts overlap by name only.
    Conflating them would corrupt audit semantics. The mapper's value
    still satisfies the proxy gate via ``arguments``; deriving a true
    data-classification from a tool call is a separate concern that the
    hook adapter cannot answer in v0.1.

    Mutate-then-sign is safe because ``ExecutionReceipt`` is
    ``@dataclass(slots=True)`` without ``frozen=True`` — slot assignment
    is permitted post-construction. ``to_dict()`` includes these fields
    when non-None, landing them in the signed JWT via ``sign_receipt``.
    """
    content_class = arguments.get("content_class")
    if content_class:
        receipt_obj.content_class = str(content_class)

    provenance = arguments.get("content_provenance")
    if provenance:
        # The receipt schema models content_provenance as a dict; the mapper
        # emits a flat string (the source name). Wrap to match the schema.
        receipt_obj.content_provenance = {"source": str(provenance)}

    instruction_bearing = arguments.get("instruction_bearing")
    if instruction_bearing is not None:
        receipt_obj.instruction_bearing = bool(instruction_bearing)


def _evaluate_composed_policy(
    event: Any,
    claims: dict[str, Any],
    *,
    session_state: Mapping[str, Any] | None = None,
) -> "tuple[str, list[Any]]":
    """Evaluate native and mission-declared policy backends with deny-wins."""
    from .policy_backend import (
        PolicyDecision,
        compose_decisions,
        get_backend,
        timed_evaluate,
    )

    context = {
        "passport": claims,
        "session": dict(session_state or {}),
        "action_class": event.action_class,
        "resource_family": event.resource_family,
        "side_effect_class": event.side_effect_class,
        "policy_metadata": {
            "action_class": event.action_class,
            "resource_family": event.resource_family,
            "side_effect_class": event.side_effect_class,
        },
    }
    decisions: list[Any] = []
    additional = claims.get("additional_policies", [])
    if not isinstance(additional, list):
        additional = [{"backend": "invalid_additional_policies"}]
    specs: list[Mapping[str, Any]] = [
        {"backend": "native", "label": "ardur_builtin"}
    ]
    for item in additional:
        specs.append(
            item
            if isinstance(item, Mapping)
            else {"backend": "invalid_additional_policy_entry"}
        )
    for spec in specs:
        backend_name = str(spec.get("backend", ""))
        label = str(spec.get("label", ""))
        try:
            backend = get_backend(backend_name)
        except KeyError:
            decisions.append(
                PolicyDecision(
                    backend=backend_name or "unknown",
                    label=label,
                    decision="Deny",
                    reasons=(f"unknown policy backend: {backend_name or '<empty>'}",),
                    eval_ms=0.0,
                )
            )
            continue
        decisions.append(
            timed_evaluate(
                backend,
                tool_name=event.tool_name,
                arguments=event.arguments,
                principal=event.actor,
                target=event.target,
                context=context,
                policy_spec={} if backend_name == "native" else dict(spec),
            )
        )
    final, _denier = compose_decisions(decisions)
    return final, decisions


def _verified_pretool_session_state_unlocked(
    state: ChainState,
    public_key: Any,
    passport_claims: Mapping[str, Any],
) -> dict[str, Any]:
    """Return cumulative state from a verified chain, caching daemon hot paths."""
    from .receipt import verify_chain

    raw = b""
    tokens = []
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(state.file, flags)
    except FileNotFoundError:
        fd = None
    if fd is not None:
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ValueError("Claude Code receipt chain is not a regular file")
            raw = handle.read(HOOK_STATE_MAX_BYTES + 1)
        if len(raw) > HOOK_STATE_MAX_BYTES:
            raise ValueError("Claude Code receipt chain exceeds the verification limit")
        tokens = [line.strip() for line in raw.decode("utf-8").splitlines() if line.strip()]
        if len(tokens) > HOOK_STATE_MAX_RECEIPTS:
            raise ValueError("Claude Code receipt chain has too many receipts")

    passport_digest = _hook_session_passport_digest(public_key, passport_claims)
    chain_hasher = hashlib.sha256(raw)
    cache_key = str(state.file.resolve(strict=False))
    cached = _VERIFIED_SESSION_CACHE.get(cache_key)
    if (
        cached is not None
        and cached.passport_digest == passport_digest
        and cached.chain_size == len(raw)
        and cached.chain_hasher.digest() == chain_hasher.digest()
    ):
        _VERIFIED_SESSION_CACHE.move_to_end(cache_key)
        return _hook_session_state(
            passport_claims=passport_claims,
            tool_call_count=cached.tool_call_count,
            by_class=cached.by_class,
        )

    receipt_claims = verify_chain(tokens, public_key, verify_expiry=False) if tokens else []
    permitted_pre = [
        claim
        for claim in receipt_claims
        if str(claim.get("step_id", "")).endswith(":pre")
        and claim.get("verdict") == "compliant"
    ]
    by_class: dict[str, int] = {}
    for claim in permitted_pre:
        side_effect = str(claim.get("side_effect_class", "none"))
        by_class[side_effect] = by_class.get(side_effect, 0) + 1
    _VERIFIED_SESSION_CACHE[cache_key] = _VerifiedSessionCacheEntry(
        passport_digest=passport_digest,
        chain_hasher=chain_hasher,
        chain_size=len(raw),
        tool_call_count=len(permitted_pre),
        by_class=dict(by_class),
    )
    _VERIFIED_SESSION_CACHE.move_to_end(cache_key)
    while len(_VERIFIED_SESSION_CACHE) > HOOK_SESSION_CACHE_MAX_ENTRIES:
        _VERIFIED_SESSION_CACHE.popitem(last=False)
    return _hook_session_state(
        passport_claims=passport_claims,
        tool_call_count=len(permitted_pre),
        by_class=by_class,
    )


def _hook_session_passport_digest(
    public_key: Any,
    passport_claims: Mapping[str, Any],
) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    claims = json.dumps(
        dict(passport_claims),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    key = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(key + b"\x00" + claims).hexdigest()


def _hook_session_state(
    *,
    passport_claims: Mapping[str, Any],
    tool_call_count: int,
    by_class: Mapping[str, int],
) -> dict[str, Any]:
    try:
        issued_at = float(passport_claims.get("iat", time.time()))
    except (TypeError, ValueError):
        issued_at = time.time()
    return {
        "tool_call_count": tool_call_count,
        "tool_call_count_by_class": dict(by_class),
        "side_effect_counts": dict(by_class),
        "delegated_budget_reserved": 0,
        "elapsed_s": max(0.0, time.time() - issued_at),
    }


def _advance_verified_session_cache_unlocked(
    state: ChainState,
    signed_jwt: str,
    receipt_obj: Any,
) -> None:
    cache_key = str(state.file.resolve(strict=False))
    cached = _VERIFIED_SESSION_CACHE.get(cache_key)
    if cached is None:
        return

    line = (signed_jwt.strip() + "\n").encode("utf-8")
    chain_hasher = cached.chain_hasher.copy()
    chain_hasher.update(line)
    tool_call_count = cached.tool_call_count
    by_class = dict(cached.by_class)
    if (
        str(getattr(receipt_obj, "step_id", "")).endswith(":pre")
        and getattr(receipt_obj, "verdict", "") == "compliant"
    ):
        tool_call_count += 1
        side_effect = str(getattr(receipt_obj, "side_effect_class", "none"))
        by_class[side_effect] = by_class.get(side_effect, 0) + 1
    _VERIFIED_SESSION_CACHE[cache_key] = _VerifiedSessionCacheEntry(
        passport_digest=cached.passport_digest,
        chain_hasher=chain_hasher,
        chain_size=cached.chain_size + len(line),
        tool_call_count=tool_call_count,
        by_class=by_class,
    )
    _VERIFIED_SESSION_CACHE.move_to_end(cache_key)


def _hook_budget_evidence(
    *,
    passport_claims: Mapping[str, Any],
    session_state: Mapping[str, Any],
    event: Any,
    permitted: bool,
) -> tuple[dict[str, Any], dict[str, int]]:
    ceiling = max(0, int(passport_claims.get("max_tool_calls", 0)))
    used_before = max(0, int(session_state.get("tool_call_count", 0)))
    amount = 1 if permitted else 0
    remaining_before = max(0, ceiling - used_before)
    remaining_after = max(0, remaining_before - amount)
    return (
        {
            "operation": "consume" if permitted else "reject",
            "resource": "tool_call",
            "amount": amount,
            "unit": "tool_call",
            "remaining_for_parent": remaining_before,
            "remaining_after": remaining_after,
            "used_total": used_before,
            "reserved_total": 0,
            "side_effect_class": event.side_effect_class,
        },
        {"tool_calls": remaining_after},
    )


def _policy_decision_dicts(decisions: list[Any]) -> list[dict[str, Any]]:
    """Return receipt-normalisable per-backend decision dictionaries."""
    result: list[dict[str, Any]] = []
    for item in decisions:
        if hasattr(item, "to_dict"):
            result.append(dict(item.to_dict()))
        elif isinstance(item, Mapping):
            result.append(dict(item))
    return result


def _strip_hash_prefix(hash_value: str | None) -> str | None:
    """Strip the ``sha-256:`` prefix that ``previous_receipt_hash`` prepends.

    ``previous_receipt_hash`` returns ``"sha-256:<hex>"`` for human readability,
    but the receipt schema and ``verify_chain`` expect a bare 64-char hex digest.
    This shim bridges the two conventions without changing the public API of
    either helper.
    """
    if hash_value is None:
        return None
    if hash_value.startswith("sha-256:"):
        return hash_value[len("sha-256:"):]
    return hash_value


def _emit_chained_receipt(
    *,
    decision_enum: Any,
    event: Any,
    decisions: list,
    reason: str,
    trace_id: str,
    keys_dir: Path | None,
    hook_input: Mapping[str, Any] | None = None,
    measurements: Mapping[str, Any] | None = None,
    subagent_record: Mapping[str, Any] | None = None,
    budget_remaining: Mapping[str, int] | None = None,
) -> Any:
    """Build, sign, and append one receipt to the per-trace chain.

    Shared by the PreToolUse allow and deny paths so the chain semantics —
    parent-hash linking, signed-JWT serialisation, file-locked append —
    are written once. PostToolUse inlines this sequence rather than using
    the helper, because it must mutate ``receipt_obj.result_hash`` between
    ``build_receipt`` and ``sign_receipt`` to land the digest inside the
    signed payload.
    """
    private_key = load_private_key(keys_dir=keys_dir)
    state = resolve_chain_state(trace_id=trace_id)
    with _locked(state):
        return _emit_chained_receipt_unlocked(
            state=state,
            private_key=private_key,
            decision_enum=decision_enum,
            event=event,
            decisions=decisions,
            reason=reason,
            trace_id=trace_id,
            hook_input=hook_input,
            measurements=measurements,
            subagent_record=subagent_record,
            budget_remaining=budget_remaining,
        )


def _emit_chained_receipt_unlocked(
    *,
    state: ChainState,
    private_key: Any,
    decision_enum: Any,
    event: Any,
    decisions: list,
    reason: str,
    trace_id: str,
    hook_input: Mapping[str, Any] | None = None,
    measurements: Mapping[str, Any] | None = None,
    subagent_record: Mapping[str, Any] | None = None,
    budget_remaining: Mapping[str, int] | None = None,
) -> Any:
    """Append one receipt while the caller holds the trace lock."""
    from .receipt import build_receipt, sign_receipt

    parent_hash = _strip_hash_prefix(_previous_receipt_hash_unlocked(state))
    if decisions:
        event.policy_decisions = _policy_decision_dicts(decisions)
    receipt_obj = build_receipt(
        decision_enum,
        event,
        parent_hash,
        policy_decisions=None,
        reason=reason,
        budget_remaining=dict(budget_remaining or {}),
    )
    _backfill_telemetry_fields(receipt_obj, event.arguments)
    _attach_claude_code_measurements(
        receipt_obj,
        hook_input or {},
        trace_id=trace_id,
        tool_name=str(getattr(event, "tool_name", "")),
        metadata=measurements,
    )
    signed = sign_receipt(receipt_obj, private_key)
    if subagent_record is not None:
        record = dict(subagent_record)
        record["receipt_id"] = receipt_obj.receipt_id
        _append_subagent_event_unlocked(state, record)
    _append_receipt_unlocked(state, signed, receipt_obj=receipt_obj)
    return receipt_obj


def handle_pre_tool_use(
    hook_input: dict[str, Any],
    *,
    keys_dir: Path | None = None,
) -> dict[str, Any]:
    """PreToolUse hook handler.

    Returns a Claude-Code hook-protocol JSON dict:
      - on Permit: ``{"continue": True, "systemMessage": "..."}`` plus a
        signed Execution Receipt appended to the per-trace chain. This does
        not return ``permissionDecision=allow``; Claude Code's normal
        permission flow remains in charge.
      - on Deny / fail-closed: a ``hookSpecificOutput`` deny decision plus
        a non-compliant receipt appended to the chain;
      - on Mission-load failure (no passport, signature mismatch, …): a
        fail-closed ``hookSpecificOutput`` deny decision and NO receipt (no
        trace context to chain into).
    """
    from .claude_code_telemetry import map_tool_call
    from .proxy import Decision, PolicyEvent, _legacy_denial_reason

    try:
        claims = load_active_passport(keys_dir=keys_dir)
    except MissionLoadError as exc:
        return _pre_tool_use_deny_output(f"ardur: {exc}")

    tool_name = str(hook_input.get("tool_name", ""))
    tool_input_dict = _coerce_mapping(hook_input.get("tool_input"))
    arguments = map_tool_call(tool_name=tool_name, tool_input=tool_input_dict)

    trace_id = _trace_id_from_claims(claims)
    event = _build_policy_event(
        claims=claims,
        tool_name=tool_name,
        arguments=arguments,
        trace_id=trace_id,
    )
    private_key = load_private_key(keys_dir=keys_dir)
    state = resolve_chain_state(trace_id=trace_id)
    try:
        with _locked(state):
            session_state = _verified_pretool_session_state_unlocked(
                state,
                private_key.public_key(),
                claims,
            )
            final, decisions = _evaluate_composed_policy(
                event,
                claims,
                session_state=session_state,
            )
            budget_delta, budget_remaining = _hook_budget_evidence(
                passport_claims=claims,
                session_state=session_state,
                event=event,
                permitted=final == "Allow",
            )
            event.budget_delta = budget_delta

            if final == "Deny":
                denier = next(
                    (d for d in decisions if d.decision == "Deny"),
                    None,
                )
                reasons = list(denier.reasons) if denier else ["denied by composed policy"]
                reason_text = "; ".join(reasons)
                deny_event = PolicyEvent(
                    timestamp=event.timestamp,
                    step_id=event.step_id,
                    actor=event.actor,
                    verifier_id=event.verifier_id,
                    tool_name=event.tool_name,
                    arguments=event.arguments,
                    action_class=event.action_class,
                    target=event.target,
                    resource_family=event.resource_family,
                    side_effect_class=event.side_effect_class,
                    decision=Decision.DENY,
                    reason=reason_text,
                    passport_jti=event.passport_jti,
                    trace_id=event.trace_id,
                    denial_reason=_legacy_denial_reason(Decision.DENY, reason_text),
                    budget_delta=budget_delta,
                )
                _emit_chained_receipt_unlocked(
                    state=state,
                    private_key=private_key,
                    decision_enum=Decision.DENY,
                    event=deny_event,
                    decisions=decisions,
                    reason=reason_text,
                    trace_id=trace_id,
                    hook_input=hook_input,
                    budget_remaining=budget_remaining,
                )
                return _pre_tool_use_deny_output(f"ardur: blocked - {reason_text}")

            receipt_obj = _emit_chained_receipt_unlocked(
                state=state,
                private_key=private_key,
                decision_enum=Decision.PERMIT,
                event=event,
                decisions=decisions,
                reason="allowed by composed policy",
                trace_id=trace_id,
                hook_input=hook_input,
                budget_remaining=budget_remaining,
            )
    except Exception:  # noqa: BLE001 - hook boundary must deny on policy/chain failure
        return _pre_tool_use_deny_output(
            "ardur: blocked - signed receipt chain is unavailable or invalid"
        )
    return {
        "continue": True,
        "systemMessage": f"ardur: allowed (receipt {receipt_obj.receipt_id})",
    }


# ─── PostToolUse handler ──────────────────────────────────────────────────────


def _result_hash(tool_response: dict[str, Any]) -> dict[str, str]:
    # Match receipt._canonical_json: ``ensure_ascii=False`` keeps non-ASCII
    # bytes UTF-8 in the canonical form so the digest matches across
    # platforms / language boundaries. ``ensure_ascii=True`` (the default)
    # would escape non-ASCII characters and produce a different digest
    # than the verifier reconstructs.
    canonical = json.dumps(
        tool_response,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {"alg": "sha-256", "value": digest}


def handle_post_tool_use(
    hook_input: dict[str, Any],
    *,
    keys_dir: Path | None = None,
) -> dict[str, Any]:
    """PostToolUse hook handler.

    Emits a result-side Execution Receipt chained to the most recent
    receipt in the per-trace chain. The receipt carries a digest of the
    tool's response (``result_hash``) so an auditor can verify what came
    back without storing the raw response. Pre-receipt verdict was
    already classified by handle_pre_tool_use; PostToolUse is a
    post-execution observation, so the verdict here is always
    Decision.PERMIT (the call was permitted to run; whether it succeeded
    is reflected in the result_hash).

    Returns ``{"continue": True}``. PostToolUse cannot block — Claude
    Code only honours blocking from PreToolUse.

    Edge case: if there is no active mission passport (e.g. the user
    revoked it between Pre and Post, or the env was never configured),
    we silently no-op rather than emit an unchained receipt.
    """
    from .claude_code_telemetry import map_tool_call
    from .proxy import Decision
    from .receipt import build_receipt, sign_receipt

    try:
        claims = load_active_passport(keys_dir=keys_dir)
    except MissionLoadError:
        # No mission means no trace context to chain into. Silent no-op.
        return {"continue": True}

    tool_name = str(hook_input.get("tool_name", ""))
    tool_input_dict = _coerce_mapping(hook_input.get("tool_input"))
    tool_response = _coerce_mapping(hook_input.get("tool_response"))
    arguments = map_tool_call(tool_name=tool_name, tool_input=tool_input_dict)

    trace_id = _trace_id_from_claims(claims)
    event = _build_policy_event(
        claims=claims,
        tool_name=tool_name,
        arguments=arguments,
        trace_id=trace_id,
        # Phase suffix on step_id so Pre and Post receipts can never
        # share an identifier even if they hash the same base inputs.
        phase="post",
    )

    # Build receipt directly so we can populate result_hash BEFORE
    # sign_receipt. The shared _emit_chained_receipt helper signs and
    # appends in one shot, but we need result_hash in the signed payload.
    private_key = load_private_key(keys_dir=keys_dir)
    state = resolve_chain_state(trace_id=trace_id)
    with _locked(state):
        # Keep parent lookup/sign/append atomic for the same parallel-hook
        # reason documented in _emit_chained_receipt.
        parent_hash = _strip_hash_prefix(_previous_receipt_hash_unlocked(state))
        receipt_obj = build_receipt(
            Decision.PERMIT,
            event,
            parent_hash,
            policy_decisions=None,
            reason="post-call observation",
        )
        # Backfill the four content-class telemetry fields and the result digest
        # before signing, so all five fields land in the canonical signed payload.
        _backfill_telemetry_fields(receipt_obj, event.arguments)
        _attach_claude_code_measurements(
            receipt_obj,
            hook_input,
            trace_id=trace_id,
            tool_name=tool_name,
        )
        receipt_obj.result_hash = _result_hash(tool_response)
        signed = sign_receipt(receipt_obj, private_key)
        _append_receipt_unlocked(state, signed, receipt_obj=receipt_obj)
    return {"continue": True}


# ─── Subagent lifecycle handlers ──────────────────────────────────────────────


def _lifecycle_arguments(
    hook_input: Mapping[str, Any],
    *,
    lifecycle: str,
) -> dict[str, Any]:
    agent_id = str(hook_input.get("agent_id", "") or "")
    agent_type = str(hook_input.get("agent_type", "") or "<unknown>")
    target = f"{agent_type}:{agent_id or '<unknown>'}"
    return {
        "agent_id": agent_id,
        "agent_type": agent_type,
        "agent_transcript_path": str(hook_input.get("agent_transcript_path", "") or ""),
        "hook_event_name": str(hook_input.get("hook_event_name", "") or ""),
        "tool_name": str(hook_input.get("hook_event_name", "") or lifecycle),
        "action_class": "dispatch" if lifecycle == "start" else "observe",
        "target": target,
        "resource_family": "agent",
        "content_class": "user_instruction",
        "content_provenance": "claude_code_hook_input",
        "side_effect_class": "subagent_launch" if lifecycle == "start" else "none",
        "visibility": CLAUDE_CODE_VISIBILITY_FULL,
        "sensitivity": "medium",
        "instruction_bearing": lifecycle == "start",
        "budget_delta": 10 if lifecycle == "start" else 1,
    }


def _policy_inheritance_summary(claims: Mapping[str, Any]) -> dict[str, Any]:
    return _without_empty_values(
        {
            "grant_id": str(claims.get("jti", "") or ""),
            "agent_id": str(claims.get("sub", "") or ""),
            "allowed_tools": list(claims.get("allowed_tools", []) or []),
            "forbidden_tools": list(claims.get("forbidden_tools", []) or []),
            "resource_scope": list(claims.get("resource_scope", []) or []),
            "max_tool_calls": claims.get("max_tool_calls"),
            "max_duration_s": claims.get("max_duration_s"),
        }
    )


def _subagent_lifecycle_metadata(
    hook_input: Mapping[str, Any],
    *,
    claims: Mapping[str, Any],
    trace_id: str,
    lifecycle: str,
    observed_at: str,
    child_receipt_summary: Mapping[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    agent_id = str(hook_input.get("agent_id", "") or "")
    session_id = str(hook_input.get("session_id", "") or "")
    ardur_child_id = _stable_child_id(
        trace_id=trace_id,
        session_id=session_id,
        agent_id=agent_id or "<unknown>",
    )
    lifecycle_payload: dict[str, Any] = {"event": lifecycle}
    if lifecycle == "start":
        lifecycle_payload["started_at"] = observed_at
    else:
        lifecycle_payload["stopped_at"] = observed_at

    metadata = _common_claude_code_metadata(
        hook_input,
        trace_id=trace_id,
        tool_name=str(hook_input.get("hook_event_name", "") or f"Subagent{lifecycle.title()}"),
    )
    metadata.update(
        _without_empty_values(
            {
                "actor_kind": "subagent",
                "claude_agent_id": agent_id,
                "ardur_child_id": ardur_child_id,
                "agent_type": str(hook_input.get("agent_type", "") or ""),
                "agent_transcript_path": str(hook_input.get("agent_transcript_path", "") or ""),
                "final_response_hash": (
                    _hash_text(str(hook_input.get("last_assistant_message", "")))
                    if hook_input.get("last_assistant_message")
                    else None
                ),
                "lifecycle": lifecycle_payload,
                "inherited_policy": _policy_inheritance_summary(claims),
                "child_receipt_summary": {
                    **dict(child_receipt_summary or {}),
                    "integrity": "unverified",
                },
                "attribution": {
                    "mode": "exact" if agent_id else "trace_only",
                    "source": "Subagent lifecycle hook agent_id" if agent_id else "missing lifecycle agent_id",
                },
            }
        )
    )
    return ardur_child_id, metadata


def _decode_claims_unverified(token: str) -> dict[str, Any] | None:
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
    except jwt.InvalidTokenError:
        return None
    return decoded if isinstance(decoded, dict) else None


def _summarize_child_receipts_unverified(
    *,
    state: ChainState,
    agent_id: str,
    agent_transcript_path: str,
) -> dict[str, Any]:
    if not state.file.exists():
        return {"receipt_count": 0, "tools": {}, "violations": 0}
    tools: dict[str, int] = {}
    violations = 0
    receipt_count = 0
    with state.file.open("r", encoding="utf-8") as receipt_lines:
        for line in receipt_lines:
            token = line.strip()
            if not token:
                continue
            claims = _decode_claims_unverified(token)
            if not claims:
                continue
            if str(claims.get("tool", "")) in {"SubagentStart", "SubagentStop"}:
                continue
            meta = (
                _coerce_mapping(claims.get("measurements"))
                .get("claude_code", {})
            )
            if not isinstance(meta, dict):
                continue
            if agent_id and meta.get("claude_agent_id") == agent_id:
                matched = True
            elif agent_transcript_path and meta.get("transcript_path") == agent_transcript_path:
                matched = True
            else:
                matched = False
            if not matched:
                continue
            receipt_count += 1
            tool = str(claims.get("tool", ""))
            tools[tool] = tools.get(tool, 0) + 1
            if claims.get("verdict") == "violation":
                violations += 1
    return {"receipt_count": receipt_count, "tools": dict(sorted(tools.items())), "violations": violations}


def _subagent_registry_record(
    metadata: Mapping[str, Any],
    *,
    lifecycle: str,
    observed_at: str,
) -> dict[str, Any]:
    lifecycle_meta = _coerce_mapping(metadata.get("lifecycle"))
    return _without_empty_values(
        {
            "schema_version": "ardur.claude_code.subagents.v0.1",
            "event": lifecycle,
            "observed_at": observed_at,
            "trace_id": metadata.get("trace_id"),
            "claude_session_id": metadata.get("claude_session_id"),
            "claude_agent_id": metadata.get("claude_agent_id"),
            "ardur_child_id": metadata.get("ardur_child_id"),
            "agent_type": metadata.get("agent_type"),
            "transcript_path": metadata.get("transcript_path"),
            "agent_transcript_path": metadata.get("agent_transcript_path"),
            "cwd": metadata.get("cwd"),
            "started_at": lifecycle_meta.get("started_at"),
            "stopped_at": lifecycle_meta.get("stopped_at"),
            "attribution": metadata.get("attribution"),
        }
    )


def _handle_subagent_lifecycle(
    hook_input: dict[str, Any],
    *,
    keys_dir: Path | None,
    lifecycle: str,
) -> dict[str, Any]:
    from .proxy import Decision

    try:
        claims = load_active_passport(keys_dir=keys_dir)
    except MissionLoadError:
        return {"continue": True}

    trace_id = _trace_id_from_claims(claims)
    observed_at = _utc_timestamp()
    event_name = str(hook_input.get("hook_event_name", "") or ("SubagentStart" if lifecycle == "start" else "SubagentStop"))
    state = resolve_chain_state(trace_id=trace_id)
    agent_id = str(hook_input.get("agent_id", "") or "")
    agent_transcript_path = str(hook_input.get("agent_transcript_path", "") or "")
    child_summary = (
        _summarize_child_receipts_unverified(
            state=state,
            agent_id=agent_id,
            agent_transcript_path=agent_transcript_path,
        )
        if lifecycle == "stop"
        else None
    )
    ardur_child_id, metadata = _subagent_lifecycle_metadata(
        hook_input,
        claims=claims,
        trace_id=trace_id,
        lifecycle=lifecycle,
        observed_at=observed_at,
        child_receipt_summary=child_summary,
    )
    arguments = _lifecycle_arguments(hook_input, lifecycle=lifecycle)
    event = _build_policy_event(
        claims=claims,
        tool_name=event_name,
        arguments=arguments,
        trace_id=trace_id,
        phase=f"subagent-{lifecycle}",
    )
    _emit_chained_receipt(
        decision_enum=Decision.PERMIT,
        event=event,
        decisions=[],
        reason=f"subagent {lifecycle} observed",
        trace_id=trace_id,
        keys_dir=keys_dir,
        hook_input=hook_input,
        measurements=metadata,
        subagent_record=_subagent_registry_record(
            metadata,
            lifecycle=lifecycle,
            observed_at=observed_at,
        ),
    )
    if lifecycle == "start":
        return {
            "hookSpecificOutput": {
                "hookEventName": "SubagentStart",
                "additionalContext": (
                    "Ardur is observing this subagent as "
                    f"{ardur_child_id}. Inherited tool and resource policy still applies."
                ),
            }
        }
    return {"continue": True}


def handle_subagent_start(
    hook_input: dict[str, Any],
    *,
    keys_dir: Path | None = None,
) -> dict[str, Any]:
    return _handle_subagent_lifecycle(hook_input, keys_dir=keys_dir, lifecycle="start")


def handle_subagent_stop(
    hook_input: dict[str, Any],
    *,
    keys_dir: Path | None = None,
) -> dict[str, Any]:
    return _handle_subagent_lifecycle(hook_input, keys_dir=keys_dir, lifecycle="stop")


def _handle_pre_tool_use_daemon_first(
    hook_input: dict[str, Any],
    *,
    keys_dir: Path | None = None,
) -> dict[str, Any]:
    """Attempt daemon dispatch first, then fall back to local handling.

    The fallback preserves existing behavior when no daemon is running or when
    daemon I/O fails. We do not fail the hook call on daemon availability.
    """
    try:
        from .claude_code_daemon_client import dispatch_pre_tool_use, is_valid_pre_tool_use_output

        daemon_output = dispatch_pre_tool_use(hook_input, keys_dir=keys_dir)
    except Exception:  # pragma: no cover - defensive daemon boundary
        daemon_output = None

    if daemon_output is not None and is_valid_pre_tool_use_output(daemon_output):
        return daemon_output
    return handle_pre_tool_use(hook_input, keys_dir=keys_dir)


def _claude_code_hook_input_next_steps(condition: str, *, phase: str) -> list[dict[str, str]]:
    return [
        {
            "condition": condition,
            "action": "configure_claude_code_protection",
            "command": "ardur protect claude-code --scope <your-project> --home <ardur-home>",
            "detail": (
                "Configure local Claude Code protection and inspect the generated hook/plugin setup "
                "before feeding hook JSON."
            ),
        },
        {
            "condition": condition,
            "action": "rerun_with_hook_event_json_file",
            "command": (
                f"ardur claude-code-hook {phase} --keys-dir <keys-dir> "
                "< <claude-code-hook-event-json-file>"
            ),
            "detail": (
                "Feed a Claude Code hook JSON object from <claude-code-hook-event-json-file>. "
                "Keep sensitive values and local private paths out of shared logs and reports."
            ),
        },
    ]


def _claude_code_hook_input_failure_response(exc: Exception, *, phase: str) -> dict[str, Any]:
    if isinstance(exc, json.JSONDecodeError):
        condition = "claude_code_hook_input_malformed"
        message = "Claude Code hook input is not valid JSON."
        detail = (
            "Input must be a valid JSON object; "
            f"parsing failed at line {exc.lineno}, column {exc.colno}."
        )
    else:
        condition = "claude_code_hook_input_not_object"
        message = "Claude Code hook input must be a JSON object."
        detail = (
            "Input must be a JSON object from <claude-code-hook-event-json-file>; arrays, "
            "strings, numbers, booleans, and null are not accepted."
        )
    return {
        "ok": False,
        "error": condition,
        "condition": condition,
        "message": message,
        "detail": detail,
        "next_steps": _claude_code_hook_input_next_steps(condition, phase=phase),
    }


def _load_hook_input(stream: Any) -> dict[str, Any]:
    raw = _read_hook_input(stream)
    if not raw.strip():
        return {}
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise HookInputNotObjectError("Claude Code hook payload must be a JSON object")
    return parsed


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Reads hook input JSON from stdin, writes hook
    output JSON to stdout. Exit code is 0 on success (handler returned
    a dict), 1 on JSON-parse failure or unhandled exception."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="vibap.claude_code_hook")
    parser.add_argument(
        "phase",
        choices=["pre", "post", "subagent-start", "subagent-stop"],
        help="hook lifecycle phase being invoked",
    )
    parser.add_argument(
        "--keys-dir",
        type=Path,
        default=None,
        help="signing keys directory (default: $VIBAP_KEYS_DIR or DEFAULT_HOME/keys)",
    )
    args = parser.parse_args(argv)

    try:
        hook_input = _load_hook_input(sys.stdin)
    except json.JSONDecodeError as exc:
        print(json.dumps(_claude_code_hook_input_failure_response(exc, phase=args.phase), sort_keys=True))
        return 1
    except HookInputNotObjectError as exc:
        print(json.dumps(_claude_code_hook_input_failure_response(exc, phase=args.phase), sort_keys=True))
        return 1
    except ValueError as exc:
        sys.stderr.write(f"ardur: invalid hook input: {exc}\n")
        return 1

    handlers = {
        "pre": _handle_pre_tool_use_daemon_first,
        "post": handle_post_tool_use,
        "subagent-start": handle_subagent_start,
        "subagent-stop": handle_subagent_stop,
    }
    handler = handlers[args.phase]
    try:
        output = handler(hook_input, keys_dir=args.keys_dir)
    except Exception as exc:  # pylint: disable=broad-except
        sys.stderr.write(f"ardur: hook handler crashed: {exc}\n")
        return 1
    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
