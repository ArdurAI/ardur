"""Biscuit-based mission passports for the ADR-014 migration."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from biscuit_auth import (
    AuthorizationError,
    AuthorizerBuilder,
    Biscuit,
    BiscuitBuildError,
    BiscuitBuilder,
    BiscuitValidationError,
    BlockBuilder,
    Check,
    DataLogError,
    Fact,
    KeyPair,
    Policy,
    PrivateKey,
    PublicKey,
    Rule,
)

from .passport import (
    MissionPassport,
    _cwd_is_subpath,
    _normalize_cwd,
    derive_mission_id,
)

# Verified against the installed biscuit_auth 0.4.0 runtime in
# `vibap-prototype/.venv` before writing this module:
#   inspect.signature(BiscuitBuilder) == (source=None, parameters=None, scope_parameters=None)
#   inspect.signature(BiscuitBuilder.build) == (self, /, root)
#   inspect.signature(BlockBuilder) == (source=None, parameters=None, scope_parameters=None)
#   inspect.signature(Biscuit.from_bytes) == (data, root)
#   inspect.signature(Biscuit.append) == (self, /, block)
#   inspect.signature(AuthorizerBuilder.add_fact) == (self, /, fact)
#   inspect.signature(AuthorizerBuilder.add_policy) == (self, /, policy)
#   inspect.signature(AuthorizerBuilder.build) == (self, /, token)
#   inspect.signature(Policy) == (source, parameters=None, scope_parameters=None)
#
# Two runtime mismatches from the plan were also verified and recorded in
# `docs/STATUS-2026-04-17-overnight.md`:
#   1. UnverifiedBiscuit exposes `from_base64`, not `from_bytes`.
#   2. `Biscuit.append` does not accept the issuer private key directly.

_DEFAULT_ALLOW_POLICY = Policy("allow if agent_id($agent)")


class BiscuitIssueError(RuntimeError):
    """Raised when a Biscuit passport cannot be built or signed."""


class BiscuitVerifyError(RuntimeError):
    """Raised when a Biscuit passport fails signature or authorization checks."""


class BiscuitAttenuationError(RuntimeError):
    """Raised when a requested child attenuation widens parent authority."""


@dataclass(slots=True)
class PassportContext:
    """Normalized Biscuit passport context for the proxy."""

    agent_id: str
    spiffe_id: str
    mission: str
    # H1 (2026-04-19): stable mission identifier for PolicyStore lookup.
    # Distinct from ``agent_id`` (two missions for one agent get
    # distinct keys) and from ``jti`` (per-issuance, unstable).
    # Always present after Biscuit decode — the issuance path derives a
    # default via ``passport.derive_mission_id`` when MissionPassport.
    # mission_id is unset, so legacy credentials re-issued through
    # current code still get a meaningful non-random value. Credentials
    # issued BEFORE this field existed will not carry the fact at all;
    # ``_context_from_blocks`` derives the same fallback so decode stays
    # backward-compatible with unversioned tokens on disk.
    mission_id: str
    allowed_tools: list[str]
    forbidden_tools: list[str]
    resource_scope: list[str]
    allowed_side_effect_classes: list[str]
    max_tool_calls: int
    max_tool_calls_per_class: dict[str, int]
    max_duration_s: int
    delegation_allowed: bool
    max_delegation_depth: int
    cwd: str | None
    jti: str
    parent_jti: str | None
    issuer_spiffe_id: str
    expires_at: int
    issued_at: int
    delegation_depth: int
    delegation_chain: list[dict[str, str]]
    extra_facts: dict[str, Any]


def issue_biscuit_passport(
    mission: MissionPassport,
    issuer_private_key: PrivateKey,
    issuer_spiffe_id: str,
    ttl_s: int = 600,
    now: int | None = None,
) -> bytes:
    """Issue a signed Biscuit passport from a MissionPassport dataclass."""

    issued_at = int(time.time() if now is None else now)
    ttl = int(ttl_s)
    if not mission.agent_id.strip():
        raise BiscuitIssueError("agent_id must be non-empty")
    holder_spiffe_id = _require_nonempty_str(
        mission.holder_spiffe_id,
        field="holder_spiffe_id",
        error_cls=BiscuitIssueError,
    )
    issuer_spiffe = _require_nonempty_str(
        issuer_spiffe_id,
        field="issuer_spiffe_id",
        error_cls=BiscuitIssueError,
    )
    if ttl <= 0:
        raise BiscuitIssueError("ttl_s must be positive")

    expires_at = issued_at + ttl
    builder = BiscuitBuilder()
    jti = _new_jti()

    try:
        _add_fact(builder, "agent_id", mission.agent_id)
        _add_fact(builder, "spiffe_id", holder_spiffe_id)
        _add_fact(builder, "issuer_spiffe_id", issuer_spiffe)
        _add_fact(builder, "mission", mission.mission)
        # H1: stable mission identifier for PolicyStore lookup. Distinct
        # from jti (per-issuance) and agent_id (per-workload). Same
        # (agent_id, mission text) pair derives the same value across
        # re-issuances so server-side policy registrations stay valid.
        _add_fact(
            builder,
            "mission_id",
            mission.mission_id
            or derive_mission_id(mission.agent_id, mission.mission),
        )
        _add_fact(builder, "jti", jti)
        _add_fact(builder, "iat", issued_at)
        _add_fact(builder, "exp", expires_at)
        _add_fact(builder, "max_tool_calls", int(mission.max_tool_calls))
        _add_fact(builder, "max_duration_s", int(mission.max_duration_s))
        _add_fact(builder, "delegation_allowed", bool(mission.delegation_allowed))
        _add_fact(builder, "max_delegation_depth", int(mission.max_delegation_depth))
        if mission.parent_jti is not None:
            _add_fact(builder, "parent_jti", mission.parent_jti)
        if mission.cwd is not None:
            _add_fact(builder, "cwd", mission.cwd)
        for tool in mission.allowed_tools:
            _add_fact(builder, "allowed_tool", tool)
        for tool in mission.forbidden_tools:
            _add_fact(builder, "forbidden_tool", tool)
        for scope in mission.resource_scope:
            _add_fact(builder, "resource_scope", scope)
        for side_effect_class in mission.allowed_side_effect_classes:
            _add_fact(builder, "allowed_side_effect_class", side_effect_class)
        for side_effect_class, budget in sorted(
            mission.max_tool_calls_per_class.items()
        ):
            _add_fact(
                builder, "max_tool_calls_per_class", side_effect_class, int(budget)
            )
        builder.add_check(Check(f"check if time($t), $t <= {expires_at}"))
        token = builder.build(issuer_private_key)
    except (BiscuitBuildError, ValueError, TypeError) as exc:
        raise BiscuitIssueError(f"failed to issue biscuit passport: {exc}") from exc

    return bytes(token.to_bytes())


def verify_biscuit_passport(
    token: bytes,
    root_public_key: PublicKey,
    now: int | None = None,
    *,
    iat_future_skew_s: int | None = None,
    iat_past_skew_s: int | None = None,
) -> PassportContext:
    """Verify a Biscuit passport and return the effective context.

    Round-4 hardening (FIX-R4-1, 2026-04-28): the Biscuit format carries
    its own ``iat`` fact at the authority block, distinct from the JWT
    ``iat`` claim that :func:`vibap.passport.assert_iat_in_window` already
    bounds. Without an explicit bound here, a briefly-compromised issuer
    could mint passports with ``iat=year_3000, exp=year_3000+ttl`` that
    pass the built-in ``$t <= exp`` Biscuit check forever (because the
    verifier's wall-clock ``time($t)`` value is much smaller than the
    forged ``exp``). We mirror the JWT-side defaults: ±300s future,
    30 days past — set either to ``None`` to disable for archival replay.

    The bound is applied AFTER Biscuit's own signature/policy
    verification, so signature-forged tokens fail at the cryptographic
    layer first; the iat gate guards against an authentic-but-future
    token from a real signer.
    """

    if iat_future_skew_s is None:
        from .passport import DEFAULT_IAT_FUTURE_SKEW_S
        iat_future_skew_s = DEFAULT_IAT_FUTURE_SKEW_S
    if iat_past_skew_s is None:
        from .passport import DEFAULT_IAT_PAST_SKEW_S
        iat_past_skew_s = DEFAULT_IAT_PAST_SKEW_S

    try:
        parsed = Biscuit.from_bytes(token, root_public_key)
    except BiscuitValidationError as exc:
        raise BiscuitVerifyError(f"invalid signature/format: {exc}") from exc

    effective_now = int(time.time() if now is None else now)
    authorizer_builder = AuthorizerBuilder()
    authorizer_builder.add_fact(Fact(f"time({effective_now})"))
    authorizer_builder.add_policy(_DEFAULT_ALLOW_POLICY)
    authorizer = authorizer_builder.build(parsed)
    try:
        authorizer.authorize()
    except AuthorizationError as exc:
        raise BiscuitVerifyError(f"authorize failed: {exc}") from exc

    try:
        block_facts = [_extract_authority_block_facts(authorizer, parsed.block_source(0))]
        block_facts.extend(
            _parse_block_source(parsed.block_source(index))
            for index in range(1, parsed.block_count())
        )
    except ValueError as exc:
        raise BiscuitVerifyError(str(exc)) from exc

    # FIX-R5-H5 (round-5 hardening, 2026-04-28): walk EVERY block's iat
    # through the bounded-skew gate BEFORE we attempt to build the
    # PassportContext. The round-4 auditor's PoC: an attacker briefly
    # compromises an issuer to mint a root with iat=year_3000,
    # exp=year_3001, then appends a child block with iat=now via
    # Biscuit's open-attenuation property. ``context.issued_at`` would
    # end up as the leaf's iat (=now), so a leaf-only check passes.
    # Walking every block's iat catches the far-future authority block.
    # We run this BEFORE _context_from_blocks so the H5 gap is caught
    # even when an attacker crafts a leaf block missing other required
    # facts (jti / mission / etc.) — the iat-bound failure is the
    # primary security signal for the audit's threat model.
    # FIX-R6-8 (round-6, 2026-04-29): walk EVERY iat fact row in EVERY
    # block, not just iat_facts[0]. Round-5 audit (LOW-1) noted that
    # ``_extract_authority_block_facts`` queries the authorizer which
    # may return iat rows from any block that asserted ``iat(...)``;
    # if a future biscuit-auth library version reverses the iteration
    # order, an attacker's far-future authority iat could hide behind
    # a benign present-time iat at index 0. Iterating every row makes
    # the bound robust to row-ordering changes upstream.
    for block_index, block in enumerate(block_facts):
        iat_facts = block.get("iat", [])
        if not iat_facts:
            if block_index == 0:
                raise BiscuitVerifyError(
                    "biscuit passport authority block missing iat fact"
                )
            continue
        for fact_idx, fact_row in enumerate(iat_facts):
            block_iat = fact_row[0]
            if not isinstance(block_iat, int) or isinstance(block_iat, bool):
                raise BiscuitVerifyError(
                    f"biscuit passport block {block_index} iat row "
                    f"{fact_idx} must be int, "
                    f"got {type(block_iat).__name__}"
                )
            if iat_future_skew_s and block_iat > effective_now + iat_future_skew_s:
                raise BiscuitVerifyError(
                    f"biscuit passport block {block_index} iat lies "
                    f"more than {iat_future_skew_s}s in the future "
                    f"(iat={block_iat}, now={effective_now})"
                )
            if iat_past_skew_s and block_iat < effective_now - iat_past_skew_s:
                raise BiscuitVerifyError(
                    f"biscuit passport block {block_index} iat lies "
                    f"more than {iat_past_skew_s}s in the past "
                    f"(iat={block_iat}, now={effective_now})"
                )

    try:
        context = _context_from_blocks(block_facts)
    except ValueError as exc:
        raise BiscuitVerifyError(str(exc)) from exc

    return context


def derive_child_biscuit(
    parent_token: bytes,
    issuer_root_private_key: PrivateKey,
    child_spiffe_id: str,
    child_allowed_tools: list[str] | None = None,
    child_resource_scope: list[str] | None = None,
    child_max_tool_calls: int | None = None,
    child_max_duration_s: int | None = None,
    child_max_tool_calls_per_class: dict[str, int] | None = None,
    child_cwd: str | None = None,
    now: int | None = None,
) -> bytes:
    """Append a first-party attenuation block to a parent Biscuit."""

    keypair = KeyPair.from_private_key(issuer_root_private_key)
    root_public_key = keypair.public_key
    parent_context = verify_biscuit_passport(parent_token, root_public_key, now=now)
    if not parent_context.delegation_allowed:
        raise BiscuitAttenuationError("parent passport does not allow delegation")
    if parent_context.max_delegation_depth <= 0:
        raise BiscuitAttenuationError("delegation depth exhausted")

    effective_now = int(time.time() if now is None else now)
    child_spiffe = _require_nonempty_str(
        child_spiffe_id,
        field="child_spiffe_id",
        error_cls=BiscuitAttenuationError,
    )

    usable_parent_tools = set(parent_context.allowed_tools) - set(
        parent_context.forbidden_tools
    )
    if child_allowed_tools is None:
        final_allowed_tools = list(parent_context.allowed_tools)
    else:
        requested_tools = _dedupe_preserve_order(child_allowed_tools)
        if not set(requested_tools).issubset(usable_parent_tools):
            expanded = sorted(set(requested_tools) - usable_parent_tools)
            raise BiscuitAttenuationError(f"tool scope expansion: {expanded}")
        final_allowed_tools = requested_tools
    final_forbidden_tools = sorted(
        set(parent_context.forbidden_tools)
        | (set(parent_context.allowed_tools) - set(final_allowed_tools))
    )

    final_resource_scope = _derive_resource_scope(
        parent_context.resource_scope,
        child_resource_scope,
    )

    if child_max_tool_calls is None:
        final_max_tool_calls = parent_context.max_tool_calls
    else:
        if child_max_tool_calls > parent_context.max_tool_calls:
            raise BiscuitAttenuationError("tool budget expansion is not allowed")
        if child_max_tool_calls < 0:
            raise BiscuitAttenuationError("child_max_tool_calls must be non-negative")
        final_max_tool_calls = child_max_tool_calls

    if child_max_duration_s is None:
        final_max_duration_s = parent_context.max_duration_s
    else:
        if child_max_duration_s > parent_context.max_duration_s:
            raise BiscuitAttenuationError("duration expansion is not allowed")
        if child_max_duration_s <= 0:
            raise BiscuitAttenuationError("child_max_duration_s must be positive")
        final_max_duration_s = child_max_duration_s

    final_per_class_budget = dict(parent_context.max_tool_calls_per_class)
    if child_max_tool_calls_per_class is not None:
        for (
            side_effect_class,
            requested_budget,
        ) in child_max_tool_calls_per_class.items():
            if side_effect_class not in parent_context.allowed_side_effect_classes:
                raise BiscuitAttenuationError(
                    f"side-effect-class expansion is not allowed: {side_effect_class}"
                )
            if requested_budget < 0:
                raise BiscuitAttenuationError(
                    f"per-class budget must be non-negative: {side_effect_class}"
                )
            parent_budget = parent_context.max_tool_calls_per_class.get(
                side_effect_class
            )
            if parent_budget is not None and requested_budget > parent_budget:
                raise BiscuitAttenuationError(
                    f"per-class budget expansion is not allowed: {side_effect_class}"
                )
            final_per_class_budget[side_effect_class] = requested_budget

    final_cwd = _derive_child_cwd(parent_context.cwd, child_cwd)
    child_jti = _new_jti()
    child_exp = min(parent_context.expires_at, effective_now + final_max_duration_s)
    if child_exp <= effective_now:
        raise BiscuitAttenuationError("parent passport expired or insufficient TTL")
    remaining_depth = parent_context.max_delegation_depth - 1
    child_block = BlockBuilder()
    _add_fact(child_block, "jti", child_jti)
    _add_fact(child_block, "parent_jti", parent_context.jti)
    _add_fact(child_block, "spiffe_id", child_spiffe)
    _add_fact(child_block, "iat", effective_now)
    _add_fact(child_block, "exp", child_exp)
    _add_fact(child_block, "max_tool_calls", final_max_tool_calls)
    _add_fact(child_block, "max_duration_s", child_exp - effective_now)
    _add_fact(child_block, "delegation_allowed", remaining_depth > 0)
    _add_fact(child_block, "max_delegation_depth", remaining_depth)
    if final_cwd is not None:
        _add_fact(child_block, "cwd", final_cwd)
    for tool in final_allowed_tools:
        _add_fact(child_block, "allowed_tool", tool)
    for tool in final_forbidden_tools:
        _add_fact(child_block, "forbidden_tool", tool)
    for scope in final_resource_scope:
        _add_fact(child_block, "resource_scope", scope)
    for side_effect_class in parent_context.allowed_side_effect_classes:
        _add_fact(child_block, "allowed_side_effect_class", side_effect_class)
    for side_effect_class, budget in sorted(final_per_class_budget.items()):
        _add_fact(child_block, "max_tool_calls_per_class", side_effect_class, budget)
    child_block.add_check(Check(f"check if time($t), $t <= {child_exp}"))

    try:
        parsed_parent = Biscuit.from_bytes(parent_token, root_public_key)
        child_token = parsed_parent.append(child_block)
    except (
        AuthorizationError,
        BiscuitValidationError,
        BiscuitBuildError,
        ValueError,
    ) as exc:
        raise BiscuitAttenuationError(f"failed to append child biscuit: {exc}") from exc

    return bytes(child_token.to_bytes())


def encode_biscuit_b64(token: bytes) -> str:
    """Encode raw Biscuit bytes into unpadded URL-safe base64."""

    return base64.urlsafe_b64encode(token).rstrip(b"=").decode("ascii")


def decode_biscuit_b64(s: str) -> bytes:
    """Decode unpadded URL-safe base64 Biscuit bytes."""

    if not isinstance(s, str) or not s:
        raise ValueError("biscuit base64 must be a non-empty string")
    padding = "=" * (-len(s) % 4)
    try:
        return base64.b64decode(
            (s + padding).encode("ascii"), altchars=b"-_", validate=True
        )
    except (ValueError, OSError, UnicodeEncodeError) as exc:
        raise ValueError(f"invalid biscuit base64: {exc}") from exc


def _context_from_blocks(blocks: list[dict[str, list[list[Any]]]]) -> PassportContext:
    if not blocks:
        raise ValueError("missing authority block")

    root = blocks[0]
    effective_agent_id = _required_single(root, "agent_id", str)
    effective_spiffe_id = _required_single(root, "spiffe_id", str)
    effective_mission = _required_single(root, "mission", str)
    # H1: extract mission_id. ``_optional_single`` is used because
    # Biscuits issued BEFORE this field existed don't carry the fact;
    # we fall back to the deterministic derivation so decode stays
    # backward-compatible (legacy tokens in flight don't become
    # un-verifiable). Tokens issued by current code always include the
    # fact explicitly.
    effective_mission_id = _optional_single(root, "mission_id", str) or (
        derive_mission_id(effective_agent_id, effective_mission)
    )
    effective_issuer_spiffe_id = _required_single(root, "issuer_spiffe_id", str)
    effective_jti = _required_single(root, "jti", str)
    effective_issued_at = _required_single(root, "iat", int)
    effective_expires_at = _required_single(root, "exp", int)
    effective_max_tool_calls = _required_single(root, "max_tool_calls", int)
    effective_max_duration_s = _required_single(root, "max_duration_s", int)
    effective_delegation_allowed = _required_single(root, "delegation_allowed", bool)
    effective_max_delegation_depth = _required_single(root, "max_delegation_depth", int)
    effective_parent_jti = _optional_single(root, "parent_jti", str)
    effective_cwd = _optional_single(root, "cwd", str)
    effective_allowed_tools = _fact_values(root, "allowed_tool", str)
    effective_forbidden_tools = _fact_values(root, "forbidden_tool", str)
    effective_resource_scope = _fact_values(root, "resource_scope", str)
    effective_allowed_side_effect_classes = _fact_values(
        root, "allowed_side_effect_class", str
    )
    effective_max_tool_calls_per_class = _pair_values(root, "max_tool_calls_per_class")
    # KNOWN LIMITATION (ADR-016 "Known limitation: Biscuit-origin lineage"):
    # the chain link's ``token_hash`` here is sha256 of THIS block's Datalog
    # source, not sha256 of the whole token bytes. The JWT path's cold
    # lineage index (``trusted_parent_token_hashes``) stores whole-token
    # hashes; comparing these two across process boundaries will never
    # match. In-process flows avoid the mismatch only because the proxy
    # holds the live session at verify time. Do NOT rely on this field
    # for cross-process Biscuit cold verification until a follow-up ADR
    # unifies the hash domain.
    delegation_chain = [
        {
            "jti": effective_jti,
            "spiffe_id": effective_spiffe_id,
            "token_hash": hashlib.sha256(
                root["__source__"].encode("utf-8")
            ).hexdigest(),
        }
    ]
    extra_facts = _unknown_fact_map(root)

    for block in blocks[1:]:
        block_jti = _required_single(block, "jti", str)
        block_spiffe_id = _required_single(block, "spiffe_id", str)
        delegation_chain.append(
            {
                "jti": block_jti,
                "spiffe_id": block_spiffe_id,
                "token_hash": hashlib.sha256(
                    block["__source__"].encode("utf-8")
                ).hexdigest(),
            }
        )
        effective_jti = block_jti
        effective_spiffe_id = block_spiffe_id
        effective_issued_at = _required_single(block, "iat", int)
        effective_expires_at = _required_single(block, "exp", int)
        effective_parent_jti = _required_single(block, "parent_jti", str)
        effective_max_tool_calls = _required_single(block, "max_tool_calls", int)
        effective_max_duration_s = _required_single(block, "max_duration_s", int)
        effective_delegation_allowed = _required_single(
            block, "delegation_allowed", bool
        )
        effective_max_delegation_depth = _required_single(
            block, "max_delegation_depth", int
        )
        if "cwd" in block:
            effective_cwd = _required_single(block, "cwd", str)
        if "allowed_tool" in block:
            effective_allowed_tools = _fact_values(block, "allowed_tool", str)
        if "forbidden_tool" in block:
            effective_forbidden_tools = _fact_values(block, "forbidden_tool", str)
        if "resource_scope" in block:
            effective_resource_scope = _fact_values(block, "resource_scope", str)
        if "allowed_side_effect_class" in block:
            effective_allowed_side_effect_classes = _fact_values(
                block, "allowed_side_effect_class", str
            )
        if "max_tool_calls_per_class" in block:
            effective_max_tool_calls_per_class = _pair_values(
                block, "max_tool_calls_per_class"
            )
        extra_facts.update(_unknown_fact_map(block))

    # Canonicalize list-valued fields: sorted output guarantees a
    # deterministic PassportContext regardless of the Biscuit authorizer
    # query order, which the library does not promise to preserve.
    return PassportContext(
        agent_id=effective_agent_id,
        spiffe_id=effective_spiffe_id,
        mission=effective_mission,
        mission_id=effective_mission_id,
        allowed_tools=sorted(effective_allowed_tools),
        forbidden_tools=sorted(effective_forbidden_tools),
        resource_scope=sorted(effective_resource_scope),
        allowed_side_effect_classes=sorted(effective_allowed_side_effect_classes),
        max_tool_calls=effective_max_tool_calls,
        max_tool_calls_per_class=effective_max_tool_calls_per_class,
        max_duration_s=effective_max_duration_s,
        delegation_allowed=effective_delegation_allowed,
        max_delegation_depth=effective_max_delegation_depth,
        cwd=effective_cwd,
        jti=effective_jti,
        parent_jti=effective_parent_jti,
        issuer_spiffe_id=effective_issuer_spiffe_id,
        expires_at=effective_expires_at,
        issued_at=effective_issued_at,
        delegation_depth=max(0, len(blocks) - 1),
        delegation_chain=delegation_chain,
        extra_facts=extra_facts,
    )


def _parse_block_source(source: str) -> dict[str, Any]:
    facts: dict[str, Any] = {"__source__": source}
    # `Authorizer.query()` returns structured `Fact` rows, but it does not expose
    # which token block a row came from. We preserve block-local chain semantics by
    # splitting the block source into full Datalog statements, then letting
    # biscuit_auth parse each fact via `Fact(...).terms` instead of scraping with
    # regexes or `ast.literal_eval`.
    for statement in _split_block_statements(source):
        if statement.startswith("check if"):
            continue
        try:
            fact = Fact(statement.removesuffix(";"))
        except DataLogError as exc:
            raise ValueError(f"unparseable block source statement: {statement}") from exc
        facts.setdefault(fact.name, []).append(list(fact.terms))
    return facts


def _extract_authority_block_facts(authorizer: Any, source: str) -> dict[str, Any]:
    facts: dict[str, Any] = {"__source__": source}
    for name in (
        "agent_id",
        "spiffe_id",
        "issuer_spiffe_id",
        "mission",
        "mission_id",
        "jti",
        "parent_jti",
        "cwd",
        "allowed_tool",
        "forbidden_tool",
        "resource_scope",
        "allowed_side_effect_class",
    ):
        rows = _query_fact_terms(authorizer, name, 1)
        if rows:
            facts[name] = rows

    for name in (
        "iat",
        "exp",
        "max_tool_calls",
        "max_duration_s",
        "max_delegation_depth",
    ):
        rows = _query_fact_terms(authorizer, name, 1)
        if rows:
            facts[name] = rows

    delegation_rows = _query_fact_terms(authorizer, "delegation_allowed", 1)
    if delegation_rows:
        facts["delegation_allowed"] = delegation_rows

    budget_rows = _query_fact_terms(authorizer, "max_tool_calls_per_class", 2)
    if budget_rows:
        facts["max_tool_calls_per_class"] = budget_rows

    return facts


def _query_fact_terms(authorizer: Any, predicate: str, arity: int) -> list[list[Any]]:
    variables = ", ".join(f"$v{index}" for index in range(arity))
    rows = authorizer.query(Rule(f"data({variables}) <- {predicate}({variables})"))
    return [list(row.terms) for row in rows]


def _split_block_statements(source: str) -> list[str]:
    statements: list[str] = []
    buffer: list[str] = []
    in_string = False
    escaped = False

    for char in source:
        buffer.append(char)
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
            continue
        if char == ";":
            statement = "".join(buffer).strip()
            if statement:
                statements.append(statement)
            buffer = []

    if in_string:
        raise ValueError("unterminated quoted string in block source")

    tail = "".join(buffer).strip()
    if tail:
        raise ValueError(f"unterminated block statement: {tail}")
    return statements


def _required_single(block: dict[str, Any], name: str, expected_type: type[Any]) -> Any:
    values = block.get(name)
    if not values:
        raise ValueError(f"missing:{name}")
    if len(values[-1]) != 1 or not isinstance(values[-1][0], expected_type):
        raise ValueError(f"malformed:{name}")
    return values[-1][0]


def _optional_single(
    block: dict[str, Any], name: str, expected_type: type[Any]
) -> Any | None:
    values = block.get(name)
    if not values:
        return None
    if len(values[-1]) != 1 or not isinstance(values[-1][0], expected_type):
        raise ValueError(f"malformed:{name}")
    return values[-1][0]


def _fact_values(
    block: dict[str, Any], name: str, expected_type: type[Any]
) -> list[Any]:
    values = block.get(name, [])
    parsed: list[Any] = []
    for entry in values:
        if len(entry) != 1 or not isinstance(entry[0], expected_type):
            raise ValueError(f"malformed:{name}")
        parsed.append(entry[0])
    return parsed


def _pair_values(block: dict[str, Any], name: str) -> dict[str, int]:
    values = block.get(name, [])
    parsed: dict[str, int] = {}
    for entry in values:
        if (
            len(entry) != 2
            or not isinstance(entry[0], str)
            or not isinstance(entry[1], int)
        ):
            raise ValueError(f"malformed:{name}")
        parsed[entry[0]] = entry[1]
    return parsed


def _unknown_fact_map(block: dict[str, Any]) -> dict[str, Any]:
    known = {
        "__source__",
        "agent_id",
        "spiffe_id",
        "issuer_spiffe_id",
        "mission",
        "mission_id",
        "jti",
        "parent_jti",
        "iat",
        "exp",
        "allowed_tool",
        "forbidden_tool",
        "resource_scope",
        "allowed_side_effect_class",
        "max_tool_calls",
        "max_tool_calls_per_class",
        "max_duration_s",
        "delegation_allowed",
        "max_delegation_depth",
        "cwd",
    }
    extra: dict[str, Any] = {}
    for name, values in block.items():
        if name in known:
            continue
        extra[name] = values
    return extra


def _derive_resource_scope(
    parent_scope: list[str], child_scope: list[str] | None
) -> list[str]:
    if child_scope is None:
        return list(parent_scope)
    normalized_child_scope = _dedupe_preserve_order(child_scope)
    if not parent_scope:
        return normalized_child_scope
    for child_entry in normalized_child_scope:
        if not any(
            _resource_scope_is_narrower(child_entry, parent_entry)
            for parent_entry in parent_scope
        ):
            raise BiscuitAttenuationError(f"resource scope expansion: {child_entry}")
    return normalized_child_scope


def _resource_scope_is_narrower(child: str, parent: str) -> bool:
    if child == parent:
        return True
    if child.startswith("/") and parent.startswith("/"):
        try:
            return _cwd_is_subpath(
                _normalize_cwd(child) or "", _normalize_cwd(parent) or ""
            )
        except ValueError:
            return False
    return False


def _derive_child_cwd(parent_cwd: str | None, child_cwd: str | None) -> str | None:
    if child_cwd is None:
        return parent_cwd
    normalized_child = _normalize_cwd(child_cwd)
    if normalized_child is None:
        if parent_cwd is not None:
            raise BiscuitAttenuationError(
                f"cwd escape is not allowed: clearing parent's cwd {parent_cwd!r}"
            )
        return None
    if parent_cwd is None:
        return normalized_child
    if not _cwd_is_subpath(normalized_child, parent_cwd):
        raise BiscuitAttenuationError(
            f"cwd escape: child cwd '{normalized_child}' is not a subpath of parent cwd '{parent_cwd}'"
        )
    return normalized_child


def _add_fact(builder: BiscuitBuilder | BlockBuilder, name: str, *args: Any) -> None:
    """Append a ``name(arg1, arg2, ...)`` Datalog fact to the builder.

    Lane B (2026-04-19) — fix for the STAC-replay-uncovered escape defect.
    Previously this function serialized string args via JSON-style
    escaping and concatenated them into a Datalog source string. That
    failed for ~5% of STAC missions whose content contained characters
    (including unquoted apostrophes, some backslash sequences, and
    newline escape sequences) that the Biscuit Datalog parser rejects
    even when they round-trip as valid JSON. The parser and JSON have
    overlapping-but-unequal escape grammars, so string interpolation is
    the wrong primitive.

    Replaced with biscuit-python's parameter-binding API: strings are
    passed as parameters keyed by auto-generated placeholders (``{p0}``,
    ``{p1}``, ...). The Rust-backed ``biscuit-python`` library handles
    its own escaping, which matches Biscuit's Datalog parser by
    construction — eliminating the class of bugs where a mission
    string that happens to contain a quote character fails issuance.

    Integers and booleans keep the old literal-interpolation path
    because they have no parser-escape-grammar mismatch (parser accepts
    ``42``, ``true``, ``false`` unchanged).
    """
    template_parts: list[str] = []
    params: dict[str, Any] = {}
    for i, arg in enumerate(args):
        if isinstance(arg, bool):
            template_parts.append("true" if arg else "false")
        elif isinstance(arg, int):
            template_parts.append(str(arg))
        elif isinstance(arg, str):
            placeholder = f"p{i}"
            template_parts.append("{" + placeholder + "}")
            params[placeholder] = arg
        else:
            raise TypeError(f"unsupported biscuit fact arg: {arg!r}")
    template = f"{name}({', '.join(template_parts)})"
    if params:
        builder.add_fact(Fact(template, params))
    else:
        builder.add_fact(Fact(template))


def _format_fact_arg(value: Any) -> str:
    """Legacy serialization retained for any external caller that was
    using this function directly (search: there were none in the repo,
    but the public-sounding name keeps it stable for third parties).

    .. deprecated:: Lane B 2026-04-19
       Use :func:`_add_fact` which uses biscuit-python's parameter
       binding and handles the full character set Biscuit's Datalog
       parser accepts — this helper's ``json.dumps`` path rejects
       about 5% of real-world mission strings (apostrophes, certain
       backslash sequences, newlines).
    """
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    raise TypeError(f"unsupported biscuit fact arg: {value!r}")


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value not in seen:
            deduped.append(value)
            seen.add(value)
    return deduped


def _new_jti() -> str:
    return str(uuid.uuid4())


def _require_nonempty_str(
    value: str | None,
    *,
    field: str,
    error_cls: type[RuntimeError],
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise error_cls(f"{field} must be a non-empty string")
    return value.strip()
