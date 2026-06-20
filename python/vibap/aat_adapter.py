"""Minimal AAT-compatible JWT adapter for MCEP sessions.

This is intentionally a narrow interop shim, not a standards-complete AAT
implementation. It accepts the repo's minimal AAT-shaped JWT profile, resolves
``mission_ref`` to an authoritative Mission Declaration, and maps the grant to
the internal mission-passport claim shape used by the governance proxy.
"""

from __future__ import annotations

import copy
import hashlib
import time
from dataclasses import dataclass
from typing import Any, Callable

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from .mission import (
    MissionBindingError,
    MissionCache,
    MissionStatusUnavailableError,
    fetch_mission_declaration,
    mission_is_revoked,
    parse_mission_ref,
)
from .passport import ALGORITHM, MissionPassport, assert_iat_in_window, verify_pop

AAT_AUTHORIZATION_DETAIL_TYPE = "attenuating_agent_token"
AAT_CREDENTIAL_FORMAT = "aat-compatible-jwt"


@dataclass(frozen=True)
class AATSessionMaterial:
    grant_id: str
    claims: dict[str, Any]
    mission: MissionPassport
    ttl_s: int
    extra_claims: dict[str, Any]


def decode_aat_claims(
    token: str,
    public_key: ec.EllipticCurvePublicKey,
) -> dict[str, Any]:
    claims = jwt.decode(
        token,
        public_key,
        algorithms=[ALGORITHM],
        options={
            "require": ["jti", "iss", "sub", "iat", "exp", "aat_type"],
            "verify_aud": False,
            # Bounded-iat check below; PyJWT's default check uses zero
            # leeway and would clash with cross-node clock drift.
            "verify_iat": False,
        },
    )
    assert_iat_in_window(claims.get("iat"), field_name="AAT iat")
    if claims.get("aat_type") != "delegation":
        raise PermissionError("unsupported AAT token shape: aat_type must be delegation")
    if "mission_ref" not in claims:
        raise PermissionError("AAT grant missing mission_ref")
    if "authorization_details" not in claims:
        raise PermissionError("AAT grant missing authorization_details")
    return claims


def material_from_aat_grant(
    token: str,
    public_key: ec.EllipticCurvePublicKey,
    mission_cache: MissionCache,
    *,
    parent_claims: dict[str, Any] | None = None,
    mission_loader: Callable[[Any], Any] | None = None,
    holder_public_key: ec.EllipticCurvePublicKey | None = None,
    kb_jwt: str | None = None,
    require_pop: bool = True,
) -> AATSessionMaterial:
    """Build session material from a verified AAT grant.

    Proof-of-possession (H2 from the 2026-04-21 review; default flipped
    fail-closed in the 2026-04-28 hardening pass):

    - When ``require_pop=True`` (the default) AND the AAT carries a ``cnf``
      claim (confirmation key), the presenter MUST demonstrate possession of
      the matching private key by supplying ``holder_public_key`` and a fresh
      ``kb_jwt`` (RFC 7800 key-binding). This mirrors the enforcement the
      non-AAT passport path performs in :meth:`GovernanceProxy.start_session`.
    - When the AAT has no ``cnf`` (pure bearer mode), PoP is skipped
      regardless of ``require_pop`` — the flag only gates *cnf-bearing* AATs.
    - **The default changed to ``require_pop=True`` on 2026-04-28** so that
      callers do not accidentally accept replayable confirmation-bound AATs.
      Library callers that legitimately need bearer-style acceptance (e.g.
      tests, demos that don't have key-binding infrastructure) MUST opt out
      explicitly with ``require_pop=False``. This makes the security-relevant
      decision visible in every call site grep, instead of buried in a
      default-argument flag.
    - Prior to this change, ``cnf`` was structurally copied into
      ``extra_claims["aat_cnf"]`` but never verified by default — a captured
      AAT could be replayed by anyone who observed it, violating the paper's
      claim that confirmation-bound credentials are holder-restricted.
    """
    claims = decode_aat_claims(token, public_key)
    # Round-4 hardening (FIX-R4-5, 2026-04-28): mirror the GovernanceProxy
    # passport path's robust cnf check. Previously the gate at
    # ``isinstance(cnf, dict) and require_pop`` silently routed cnf=""/0/
    # False/[] AATs through the bearer path, restoring the pre-2026-04-21
    # truthy-skip bug for the AAT format. Now ANY non-None cnf forces
    # verify_pop to run; that helper rejects malformed shapes with
    # PermissionError ("cnf claim but missing jkt", etc.).
    if "cnf" in claims and claims["cnf"] is not None and require_pop:
        if holder_public_key is None or kb_jwt is None:
            raise PermissionError(
                "AAT grant presents a cnf claim but PoP inputs were not "
                "supplied (holder_public_key and kb_jwt are required for "
                "confirmation-bound AATs when require_pop=True). To accept "
                "this AAT in bearer mode (NOT recommended for production), "
                "pass require_pop=False explicitly."
            )
        # verify_pop treats the AAT claim dict + token the same as a passport:
        # validates cnf.jkt thumbprint match AND verifies the KB-JWT signature
        # + nonce freshness. Non-dict / missing-jkt cnf payloads also raise
        # PermissionError here, defending against type-confusion bypass.
        verify_pop(claims, token, holder_public_key, kb_jwt)
    if parent_claims is not None:
        _assert_child_grant_narrows_parent(claims, parent_claims)

    try:
        mission_ref = parse_mission_ref(claims["mission_ref"])
        loader = mission_loader or (
            lambda ref: fetch_mission_declaration(ref, public_key)
        )
        declaration = mission_cache.resolve(mission_ref, lambda: loader(mission_ref))
        if mission_is_revoked(declaration, public_key):
            raise PermissionError("AAT mission_ref points to a revoked mission")
    except (MissionBindingError, MissionStatusUnavailableError) as exc:
        raise PermissionError(str(exc)) from exc

    granted_tools = _extract_tools(claims)
    mission_tools = set(declaration.passport.allowed_tools)
    widened_tools = sorted(granted_tools - mission_tools)
    if widened_tools:
        raise PermissionError(f"AAT grant widens mission tools: {widened_tools}")

    max_tool_calls = _extract_max_tool_calls(claims, declaration.passport.max_tool_calls)
    if max_tool_calls > declaration.passport.max_tool_calls:
        raise PermissionError("AAT grant widens mission max_tool_calls")

    depth = _int_claim(claims, "del_depth", fallback="delegation_depth", default=0)
    max_depth = _int_claim(
        claims,
        "del_max_depth",
        fallback="max_delegation_depth",
        default=depth,
    )
    remaining_depth = max(0, max_depth - depth)
    now = int(time.time())
    ttl_s = max(1, min(int(claims["exp"]) - now, declaration.passport.max_duration_s))

    passport = MissionPassport(
        agent_id=str(claims["sub"]),
        mission=declaration.passport.mission,
        allowed_tools=sorted(granted_tools),
        forbidden_tools=sorted(mission_tools - granted_tools),
        resource_scope=_extract_resource_scope(claims, declaration.passport.resource_scope),
        max_tool_calls=max_tool_calls,
        max_duration_s=ttl_s,
        delegation_allowed=remaining_depth > 0,
        max_delegation_depth=remaining_depth,
        mission_id=declaration.mission_id,
    )
    extra_claims = {
        "jti": str(claims["jti"]),
        "credential_format": AAT_CREDENTIAL_FORMAT,
        "aat_grant_id": str(claims["jti"]),
        "aat_issuer": str(claims["iss"]),
        "aat_type": str(claims["aat_type"]),
        "mission_ref": copy.deepcopy(claims["mission_ref"]),
        "mission_digest": declaration.payload_digest,
        "external_grant_token_hash": hashlib.sha256(token.encode("utf-8")).hexdigest(),
    }
    if "cnf" in claims:
        extra_claims["aat_cnf"] = copy.deepcopy(claims["cnf"])
    return AATSessionMaterial(
        grant_id=str(claims["jti"]),
        claims=claims,
        mission=passport,
        ttl_s=ttl_s,
        extra_claims=extra_claims,
    )


def _extract_tools(claims: dict[str, Any]) -> set[str]:
    tools: set[str] = set()
    for detail in _authorization_details(claims):
        raw_tools = detail.get("tools")
        if isinstance(raw_tools, dict):
            tools.update(str(name) for name in raw_tools if str(name).strip())
        elif isinstance(raw_tools, list):
            for item in raw_tools:
                if isinstance(item, str) and item.strip():
                    tools.add(item)
                elif isinstance(item, dict) and isinstance(item.get("name"), str):
                    tools.add(item["name"])
    if not tools:
        raise PermissionError("AAT grant has no supported tool grants")
    return tools


def _extract_max_tool_calls(claims: dict[str, Any], default: int) -> int:
    candidates: list[int] = []
    if "max_tool_calls" in claims:
        candidates.append(int(claims["max_tool_calls"]))
    budget = claims.get("budget")
    if isinstance(budget, dict) and "tool_calls" in budget:
        candidates.append(int(budget["tool_calls"]))
    for detail in _authorization_details(claims):
        if "max_tool_calls" in detail:
            candidates.append(int(detail["max_tool_calls"]))
    value = min(candidates) if candidates else int(default)
    if value <= 0:
        raise PermissionError("AAT grant max_tool_calls must be positive")
    return value


def _extract_resource_scope(
    claims: dict[str, Any],
    mission_scope: list[str],
) -> list[str]:
    raw_scope = claims.get("resource_scope")
    if raw_scope is None:
        return list(mission_scope)
    if not isinstance(raw_scope, list) or not all(isinstance(item, str) for item in raw_scope):
        raise PermissionError("AAT grant resource_scope must be a string array")
    requested = set(raw_scope)
    if mission_scope:
        widened = sorted(requested - set(mission_scope))
        if widened:
            raise PermissionError(f"AAT grant widens mission resource_scope: {widened}")
    return sorted(requested)


def _assert_child_grant_narrows_parent(
    child: dict[str, Any],
    parent: dict[str, Any],
) -> None:
    child_tools = _extract_tools(child)
    parent_tools = _extract_tools(parent)
    widened_tools = sorted(child_tools - parent_tools)
    if widened_tools:
        raise PermissionError(f"AAT child grant widens parent tools: {widened_tools}")
    child_budget = _extract_max_tool_calls(child, default=10**9)
    parent_budget = _extract_max_tool_calls(parent, default=10**9)
    if child_budget > parent_budget:
        raise PermissionError("AAT child grant widens parent budget")
    child_depth = _int_claim(child, "del_depth", fallback="delegation_depth", default=0)
    parent_depth = _int_claim(parent, "del_depth", fallback="delegation_depth", default=0)
    if child_depth <= parent_depth:
        raise PermissionError("AAT child grant must increase delegation depth")


def _authorization_details(claims: dict[str, Any]) -> list[dict[str, Any]]:
    raw = claims.get("authorization_details")
    if not isinstance(raw, list):
        raise PermissionError("authorization_details must be an array")
    details = [
        item
        for item in raw
        if isinstance(item, dict)
        and item.get("type") == AAT_AUTHORIZATION_DETAIL_TYPE
    ]
    if not details:
        raise PermissionError("no supported AAT authorization detail found")
    return details


def _int_claim(
    claims: dict[str, Any],
    name: str,
    *,
    fallback: str,
    default: int,
) -> int:
    raw = claims.get(name, claims.get(fallback, default))
    return int(raw)
