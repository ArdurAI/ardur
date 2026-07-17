"""Mission Declaration loading, caching, and revocation checks."""

from __future__ import annotations

import base64
import copy
import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import threading
import urllib.parse
import urllib.request
import zlib
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

# jsonschema is a runtime dependency (moved from [dev] on 2026-04-28) so that
# every install can validate Mission Declarations against the v0.1 spec at
# the network boundary. The schema itself ships as package data under
# vibap/_specs/ — see _specs/__init__.py.
import jsonschema

from ._specs import mission_declaration_v01_schema
from .passport import (
    ALGORITHM,
    DEFAULT_AUDIENCE,
    MissionPassport,
    assert_iat_in_window,
)

# NOTE: urlopen is accessed as the module-level binding so that
# monkeypatching `vibap.mission.urlopen` in tests works regardless of
# test ordering. We assign the production binding (``_pinned_urlopen``,
# defined below) at the bottom of this module — the variable is
# re-bound, not just initialized.
urlopen = urllib.request.urlopen  # placeholder; real binding set at end of module.

_FETCH_TIMEOUT_S = 5.0
MAX_STATUS_LIST_BYTES = 1 << 20
MAX_DECOMPRESSED_BYTES = 16 << 20


class MissionBindingError(RuntimeError):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


class MissionStatusUnavailableError(RuntimeError):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True, slots=True)
class MissionReference:
    uri: str
    mission_id: str | None = None
    mission_digest: str | None = None

    def cache_key(self) -> str:
        return "|".join([self.uri, self.mission_id or "", self.mission_digest or ""])


@dataclass(frozen=True, slots=True)
class MissionDeclaration:
    mission_id: str
    issuer: str
    subject: str
    audience: str | list[str]
    issued_at: int
    expires_at: int
    jwt_id: str
    passport: MissionPassport
    resource_policies: tuple[dict[str, Any], ...] = ()
    effect_policies: tuple[dict[str, Any], ...] = ()
    lineage_budgets: dict[str, Any] = field(default_factory=dict)
    delegation_policy: dict[str, Any] = field(default_factory=dict)
    flow_policies: tuple[dict[str, Any], ...] = ()
    required_telemetry: tuple[str, ...] = ()
    receipt_policy: dict[str, Any] = field(default_factory=dict)
    conformance_profile: str | None = None
    tool_manifest_digest: str | None = None
    revocation_ref: str | None = None
    approval_policy: dict[str, Any] = field(default_factory=dict)
    governed_memory_stores: tuple[dict[str, Any], ...] = ()
    probing_rate_limit: int | None = None
    payload_digest: str = ""
    raw_claims: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)
    token: str = field(default="", repr=False, compare=False)

    def policy_claims(self) -> dict[str, Any]:
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": self.subject,
            "aud": copy.deepcopy(self.audience),
            "iat": self.issued_at,
            "exp": self.expires_at,
            "jti": self.jwt_id,
            "mission_id": self.mission_id,
            "mission": self.passport.mission,
            "allowed_tools": list(self.passport.allowed_tools),
            "forbidden_tools": list(self.passport.forbidden_tools),
            "resource_scope": list(self.passport.resource_scope),
            "max_tool_calls": self.passport.max_tool_calls,
            "max_duration_s": self.passport.max_duration_s,
            "delegation_allowed": self.passport.delegation_allowed,
            "max_delegation_depth": self.passport.max_delegation_depth,
        }
        if self.passport.parent_jti is not None:
            claims["parent_jti"] = self.passport.parent_jti
        if self.passport.cwd is not None:
            claims["cwd"] = self.passport.cwd
        if self.passport.risk_budget is not None:
            claims["risk_budget"] = copy.deepcopy(self.passport.risk_budget)
        if self.approval_policy:
            claims["approval_policy"] = copy.deepcopy(self.approval_policy)
        for name in (
            "resource_policies",
            "effect_policies",
            "lineage_budgets",
            "delegation_policy",
            "flow_policies",
            "required_telemetry",
            "receipt_policy",
            "conformance_profile",
            "tool_manifest_digest",
            "revocation_ref",
            "governed_memory_stores",
            "probing_rate_limit",
        ):
            value = getattr(self, name)
            if value not in (None, (), {}, []):
                claims[name] = copy.deepcopy(value)
        return claims


class MissionCache:
    def __init__(self, max_entries: int = 256) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self.max_entries = max_entries
        self._lock = threading.Lock()
        self._by_id: OrderedDict[str, MissionDeclaration] = OrderedDict()
        self._ref_to_id: OrderedDict[str, str] = OrderedDict()

    def get(self, mission_id: str) -> MissionDeclaration | None:
        with self._lock:
            mission = self._by_id.get(mission_id)
            if mission is None:
                return None
            self._by_id.move_to_end(mission_id)
            return mission

    def get_by_ref(self, ref: MissionReference) -> MissionDeclaration | None:
        ref_key = ref.cache_key()
        with self._lock:
            mission_id = self._ref_to_id.get(ref_key) or ref.mission_id
            if mission_id is None:
                return None
            mission = self._by_id.get(mission_id)
            if mission is None:
                self._ref_to_id.pop(ref_key, None)
                return None
            if ref.mission_digest and mission.payload_digest != ref.mission_digest:
                return None
            self._by_id.move_to_end(mission_id)
            self._ref_to_id[ref_key] = mission_id
            self._ref_to_id.move_to_end(ref_key)
            return mission

    def put(
        self, mission: MissionDeclaration, *, ref: MissionReference | None = None
    ) -> MissionDeclaration:
        with self._lock:
            self._by_id[mission.mission_id] = mission
            self._by_id.move_to_end(mission.mission_id)
            if ref is not None:
                self._ref_to_id[ref.cache_key()] = mission.mission_id
                self._ref_to_id.move_to_end(ref.cache_key())
            while len(self._by_id) > self.max_entries:
                evicted_id, _ = self._by_id.popitem(last=False)
                stale = [
                    key for key, value in self._ref_to_id.items() if value == evicted_id
                ]
                for key in stale:
                    self._ref_to_id.pop(key, None)
            while len(self._ref_to_id) > self.max_entries * 2:
                self._ref_to_id.popitem(last=False)
            return mission

    def resolve(
        self, ref: MissionReference, loader: Callable[[], MissionDeclaration]
    ) -> MissionDeclaration:
        cached = self.get_by_ref(ref)
        if cached is not None:
            return cached
        return self.put(loader(), ref=ref)


# --- Mission Declaration validation (FIX-3 from S2 hostile audit, 2026-04-28).
#
# The v0.1 schema lives at /docs/specs/mission-declaration-v0.1.schema.json
# and is mirrored at vibap/_specs/mission_declaration_v01.schema.json so the
# runtime can validate without depending on the source docs tree.
#
# Two validators are exposed here, used at different rigor tiers:
#
# - ``_validate_required_v01_members(claims)`` — runs UNCONDITIONALLY inside
#   :func:`load_mission_declaration`. Checks the seven audit-flagged members
#   (``receipt_policy``, ``conformance_profile``, ``tool_manifest_digest``,
#   ``revocation_ref``, ``approval_policy``, ``governed_memory_stores``,
#   ``probing_rate_limit``) are present and basically well-shaped. These
#   are the spec members whose absence makes the policy silent-permissive
#   (the exact failure mode the audit flagged). Fails closed on missing
#   or wrong-typed entries. Cheap and back-compat: existing legacy fields
#   like ``allowed_tools`` continue to be accepted alongside.
#
# - ``validate_v01_md_schema(claims)`` — full jsonschema-against-spec
#   validation, opt-in via ``strict_schema=True``. Used by producers that
#   know they're emitting clean v0.1-conformant MDs. Rejects MDs that mix
#   legacy and v0.1 forms (``additionalProperties: false`` at the root).
#
# Defense-in-depth: required-members is a small hand-rolled assertion that
# survives even if the embedded jsonschema is broken or the package data
# is missing. Strict-schema is the rigorous version for clean producers.

# Of the seven v0.1 spec members the audit listed, FIVE are flagged here
# as always-required after the round-3 (2026-04-28) re-audit. The two
# omitted members are intentional, not oversights:
#
# - ``approval_policy``: the proxy treats its absence as an explicit
#   "no approval gate" — i.e. omission is a visible choice, not a silent
#   default. Including it in the always-required list would force every
#   tool call in deployments that don't use approvals to carry an
#   operator_id.
# - ``probing_rate_limit``: round-2 audit flagged this as
#   validate-but-don't-enforce. The runtime currently has no rate-limiter
#   that consumes the value, so requiring producers to ship it without
#   any downstream effect is honesty-debt theater. It remains required
#   under strict-schema (opt-in) for clean v0.1 producers, and will
#   return to the always-required list when a per-mission rate-limiter
#   actually consumes it.
#
# Both members ARE still mandatory under ``strict_schema=True`` because
# the v0.1 schema lists them as required at the spec level — the lite
# always-on check is a strict subset focused on members whose absence
# creates a *silent permissive default* in the runtime today.
_REQUIRED_V01_MEMBERS: tuple[tuple[str, type | tuple[type, ...]], ...] = (
    ("receipt_policy", dict),
    ("conformance_profile", str),
    ("tool_manifest_digest", str),
    ("revocation_ref", str),
    ("governed_memory_stores", list),
)
_VALID_CONFORMANCE_PROFILES = frozenset(
    {"Delegation-Core", "MIC-State", "MIC-Evidence"}
)
_VALID_RECEIPT_LEVELS = frozenset({"minimal", "counter_signed", "transparency_logged"})


def _validate_required_v01_members(claims: dict[str, Any]) -> None:
    """Fail-closed check that the seven audit-flagged spec members are
    present and basically well-shaped.

    This is the always-on guard against the silent-default pattern the S2
    audit flagged (FIX-3): the previous loader silently treated missing
    ``receipt_policy`` / ``conformance_profile`` / ``tool_manifest_digest``
    / ``revocation_ref`` / ``approval_policy`` / ``governed_memory_stores``
    / ``probing_rate_limit`` as if they were optional, then proceeded with
    permissive defaults. After this change, a producer that ships an MD
    without any of these fields is rejected at load time.

    Raises :class:`MissionBindingError` with reason ``"schema_invalid"``.
    """
    for name, expected_type in _REQUIRED_V01_MEMBERS:
        if name not in claims:
            raise MissionBindingError(
                "schema_invalid",
                f"mission declaration missing required v0.1 member: {name}",
            )
        value = claims[name]
        # bool is a subclass of int — guard the int check explicitly.
        if expected_type is int and isinstance(value, bool):
            raise MissionBindingError(
                "schema_invalid",
                f"mission declaration member {name!r} must be int, got bool",
            )
        if not isinstance(value, expected_type):
            raise MissionBindingError(
                "schema_invalid",
                f"mission declaration member {name!r} must be of type "
                f"{expected_type.__name__ if isinstance(expected_type, type) else expected_type!r}",
            )

    # Stronger checks on enum-bound members so a typo doesn't sneak through.
    profile = claims["conformance_profile"]
    if profile not in _VALID_CONFORMANCE_PROFILES:
        raise MissionBindingError(
            "schema_invalid",
            f"conformance_profile {profile!r} not one of "
            f"{sorted(_VALID_CONFORMANCE_PROFILES)}",
        )
    receipt_level = claims["receipt_policy"].get("level")
    if receipt_level not in _VALID_RECEIPT_LEVELS:
        raise MissionBindingError(
            "schema_invalid",
            f"receipt_policy.level {receipt_level!r} not one of "
            f"{sorted(_VALID_RECEIPT_LEVELS)}",
        )
    # tool_manifest_digest must be a sha-256 hex digest string.
    tmd = claims["tool_manifest_digest"]
    if not (
        tmd.startswith("sha-256:")
        and len(tmd) == len("sha-256:") + 64
        and all(c in "0123456789abcdef" for c in tmd[len("sha-256:") :])
    ):
        raise MissionBindingError(
            "schema_invalid",
            "tool_manifest_digest must match sha-256:<64 hex chars>",
        )
    # probing_rate_limit shape check — only runs when the producer ships
    # it (it is no longer always-required after the round-3 audit; see
    # _REQUIRED_V01_MEMBERS comment). When present it must still be a
    # positive integer because strict_schema validation may consume it.
    if "probing_rate_limit" in claims:
        prl = claims["probing_rate_limit"]
        if isinstance(prl, bool) or not isinstance(prl, int) or prl < 1:
            raise MissionBindingError(
                "schema_invalid",
                "probing_rate_limit, when present, must be a positive integer",
            )
    # MIC-Evidence requires a non-minimal receipt level.
    if profile == "MIC-Evidence" and receipt_level == "minimal":
        raise MissionBindingError(
            "schema_invalid",
            "MIC-Evidence profile requires receipt_policy.level "
            "to be counter_signed or transparency_logged",
        )


def validate_v01_md_schema(claims: dict[str, Any]) -> None:
    """Validate Mission Declaration claims against the full v0.1 spec.

    Opt-in via ``strict_schema=True`` on :func:`load_mission_declaration`.
    Use this from producers that emit clean v0.1-conformant MDs without
    legacy fields (e.g. the ``ardur`` HTTP /issue endpoint after the spec
    migration completes). Existing producers that emit legacy fields like
    ``allowed_tools`` will fail this check because the v0.1 schema sets
    ``additionalProperties: false`` at the root.

    Raises :class:`MissionBindingError` with reason ``"schema_invalid"``.
    """
    try:
        jsonschema.validate(claims, mission_declaration_v01_schema())
    except jsonschema.ValidationError as exc:
        path_segments = [str(p) for p in exc.absolute_path]
        path = "/" + "/".join(path_segments) if path_segments else "(root)"
        raise MissionBindingError(
            "schema_invalid",
            f"mission declaration violates v0.1 schema at {path}: {exc.message}",
        ) from exc
    except jsonschema.SchemaError as exc:  # pragma: no cover — schema bug
        raise MissionBindingError(
            "schema_invalid",
            f"embedded v0.1 schema is malformed: {exc.message}",
        ) from exc


def parse_mission_ref(value: Any) -> MissionReference:
    if isinstance(value, str):
        if not value.strip():
            raise MissionBindingError("chain_invalid", "mission_ref is empty")
        return MissionReference(uri=value.strip())
    if not isinstance(value, dict):
        raise MissionBindingError(
            "chain_invalid", "mission_ref must be a string or object"
        )
    uri = value.get("uri", value.get("url"))
    if not isinstance(uri, str) or not uri.strip():
        raise MissionBindingError("chain_invalid", "mission_ref.uri is required")
    mission_id = value.get("mission_id")
    if mission_id is not None and (
        not isinstance(mission_id, str) or not mission_id.strip()
    ):
        raise MissionBindingError(
            "chain_invalid", "mission_ref.mission_id must be a non-empty string"
        )
    mission_digest = value.get("mission_digest")
    if mission_digest is not None and (
        not isinstance(mission_digest, str) or not mission_digest.startswith("sha-256:")
    ):
        raise MissionBindingError(
            "chain_invalid", "mission_ref.mission_digest must use sha-256:<hex>"
        )
    return MissionReference(
        uri=uri.strip(),
        mission_id=mission_id.strip() if isinstance(mission_id, str) else None,
        mission_digest=mission_digest,
    )


def load_mission_declaration(
    md_jwt: str,
    public_key: ec.EllipticCurvePublicKey,
    *,
    strict_schema: bool = False,
) -> MissionDeclaration:
    """Decode, verify, and parse a Mission Declaration JWT.

    Validation runs in two tiers (FIX-3 from the 2026-04-28 hostile audit):

    - **Always:** :func:`_validate_required_v01_members` enforces that the
      seven audit-flagged required spec members (``receipt_policy``,
      ``conformance_profile``, ``tool_manifest_digest``, ``revocation_ref``,
      ``approval_policy``, ``governed_memory_stores``, ``probing_rate_limit``)
      are present and well-typed. Missing or malformed → fails closed with
      ``MissionBindingError("schema_invalid", ...)``. This guards against
      the silent-default pattern where the loader treated absence as
      "use safe defaults" — a permissive read-as-zero on security-relevant
      claims. Cheap, back-compat: legacy fields like ``allowed_tools`` keep
      flowing through alongside.

    - **Opt-in:** ``strict_schema=True`` additionally runs
      :func:`validate_v01_md_schema`, the full jsonschema-against-spec
      validator. Reject MDs that mix v0.1 with legacy fields. Use this in
      producers that emit clean v0.1 MDs (HTTP /issue once the spec
      migration completes; AAT issuers downstream of this codebase).
    """
    try:
        claims = jwt.decode(
            md_jwt,
            public_key,
            algorithms=[ALGORITHM],
            audience=DEFAULT_AUDIENCE,
            options={
                "require": ["iss", "sub", "aud", "iat", "exp", "jti", "mission_id"],
                # Bounded-iat skew enforced below via the shared helper;
                # PyJWT's default check is too brittle for cross-node use.
                "verify_iat": False,
            },
        )
    except jwt.PyJWTError as exc:
        raise MissionBindingError(
            "chain_invalid", f"mission declaration verification failed: {exc}"
        ) from exc
    # Bounded-iat gate (round 3, 2026-04-28). Mirrors the receipt-side
    # FIX-6 generalization to mission declarations so a forged MD with
    # iat=year_3000, exp=year_3001 cannot survive verification just
    # because both timestamps are in the future together.
    try:
        assert_iat_in_window(claims.get("iat"), field_name="MD iat")
    except jwt.InvalidTokenError as exc:
        raise MissionBindingError(
            "chain_invalid", f"mission declaration {exc}"
        ) from exc
    # Always run the required-members guard. The strict full-schema check
    # is opt-in for clean producers (see docstring).
    _validate_required_v01_members(claims)
    if strict_schema:
        validate_v01_md_schema(claims)
    try:
        passport = MissionPassport.from_dict(
            {
                "agent_id": str(claims["sub"]),
                "mission": str(
                    claims.get("mission", claims.get("mission_id", claims["jti"]))
                ),
                "allowed_tools": list(
                    claims.get("allowed_tools", claims.get("allowed_tool_classes", []))
                ),
                "forbidden_tools": list(claims.get("forbidden_tools", [])),
                "resource_scope": _legacy_resource_scope(
                    claims.get("resource_scope"),
                    claims.get("resource_policies"),
                ),
                "max_tool_calls": int(claims.get("max_tool_calls", 50)),
                "max_duration_s": int(
                    claims.get(
                        "max_duration_s",
                        max(1, int(claims["exp"]) - int(claims["iat"])),
                    )
                ),
                "delegation_allowed": bool(
                    claims.get(
                        "delegation_allowed",
                        bool(
                            (
                                (claims.get("delegation_policy") or {}).get(
                                    "max_depth", 0
                                )
                            )
                        ),
                    )
                ),
                "max_delegation_depth": int(
                    claims.get(
                        "max_delegation_depth",
                        ((claims.get("delegation_policy") or {}).get("max_depth", 0)),
                    )
                ),
                "parent_jti": claims.get("parent_jti"),
                "cwd": claims.get("cwd"),
                **(
                    {"risk_budget": copy.deepcopy(claims["risk_budget"])}
                    if "risk_budget" in claims
                    else {}
                ),
            }
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise MissionBindingError(
            "chain_invalid", f"mission declaration schema invalid: {exc}"
        ) from exc

    return MissionDeclaration(
        mission_id=str(claims["mission_id"]),
        issuer=str(claims["iss"]),
        subject=str(claims["sub"]),
        audience=copy.deepcopy(claims["aud"]),
        issued_at=int(claims["iat"]),
        expires_at=int(claims["exp"]),
        jwt_id=str(claims["jti"]),
        passport=passport,
        resource_policies=_tuple_of_dicts(claims.get("resource_policies")),
        effect_policies=_tuple_of_dicts(claims.get("effect_policies")),
        lineage_budgets=_dict_or_empty(claims.get("lineage_budgets")),
        delegation_policy=_dict_or_empty(claims.get("delegation_policy")),
        flow_policies=_tuple_of_dicts(claims.get("flow_policies")),
        required_telemetry=_tuple_of_strs(claims.get("required_telemetry")),
        receipt_policy=_dict_or_empty(claims.get("receipt_policy")),
        conformance_profile=_optional_str(claims.get("conformance_profile")),
        tool_manifest_digest=_optional_str(claims.get("tool_manifest_digest")),
        revocation_ref=_optional_str(claims.get("revocation_ref")),
        approval_policy=_dict_or_empty(claims.get("approval_policy")),
        governed_memory_stores=_tuple_of_dicts(claims.get("governed_memory_stores")),
        probing_rate_limit=_optional_int(claims.get("probing_rate_limit")),
        payload_digest=_payload_digest(claims),
        raw_claims=copy.deepcopy(claims),
        token=md_jwt,
    )


def fetch_mission_declaration(
    ref: MissionReference,
    public_key: ec.EllipticCurvePublicKey,
    *,
    strict_schema: bool = False,
) -> MissionDeclaration:
    """Fetch and verify an MD from a network reference.

    The required-members guard inside :func:`load_mission_declaration`
    runs unconditionally — fetched bytes that omit any of the seven
    audit-flagged spec members fail closed regardless of this flag.
    ``strict_schema=True`` additionally enforces full v0.1 schema
    conformance (rejecting MDs with legacy fields). Production producers
    that emit clean v0.1 MDs SHOULD opt in. (FIX-3, 2026-04-28.)
    """
    if urllib.parse.urlparse(ref.uri).scheme.lower() != "https":
        raise MissionBindingError("chain_invalid", "mission_ref must use https")
    mission = load_mission_declaration(
        _fetch_text(ref.uri),
        public_key,
        strict_schema=strict_schema,
    )
    if ref.mission_id and ref.mission_id != mission.mission_id:
        raise MissionBindingError(
            "chain_invalid", "mission_ref mission_id does not match loaded mission"
        )
    if ref.mission_digest and ref.mission_digest != mission.payload_digest:
        raise MissionBindingError(
            "chain_invalid", "mission_ref mission_digest does not match loaded mission"
        )
    return mission


def mission_is_revoked(
    mission: MissionDeclaration, public_key: ec.EllipticCurvePublicKey
) -> bool:
    if mission.revocation_ref is None:
        return False
    uri, idx = _parse_revocation_ref(mission.revocation_ref)
    try:
        claims = jwt.decode(
            _fetch_text(uri),
            public_key,
            algorithms=[ALGORITHM],
            options={
                "require": ["iat", "exp"],
                "verify_aud": False,
                # Status lists also fail closed on absurd iat — same
                # generalization as MD/AAT/passport (round 3, 2026-04-28).
                "verify_iat": False,
            },
        )
    except jwt.PyJWTError as exc:
        raise MissionBindingError(
            "chain_invalid", f"status list verification failed: {exc}"
        ) from exc
    try:
        assert_iat_in_window(claims.get("iat"), field_name="status list iat")
    except jwt.InvalidTokenError as exc:
        raise MissionBindingError("chain_invalid", f"status list {exc}") from exc
    container = claims.get("status_list", claims.get("status"))
    if not isinstance(container, dict):
        raise MissionBindingError(
            "chain_invalid", "status list token missing status_list claim"
        )
    try:
        bits = int(container.get("bits", 1))
    except (TypeError, ValueError) as exc:
        raise MissionBindingError(
            "chain_invalid", "status list bits must be an integer"
        ) from exc
    if bits not in (1, 2, 4, 8):
        raise MissionBindingError(
            "chain_invalid", f"unsupported status list bits={bits}"
        )
    lst = container.get("lst")
    if not isinstance(lst, str) or not lst:
        raise MissionBindingError("chain_invalid", "status list token missing lst")
    try:
        decompressor = zlib.decompressobj()
        raw = decompressor.decompress(_b64url_decode(lst), MAX_DECOMPRESSED_BYTES)
    except (ValueError, zlib.error) as exc:
        raise MissionBindingError(
            "chain_invalid", "status list decompression failed"
        ) from exc
    if decompressor.unconsumed_tail or decompressor.unused_data:
        raise MissionStatusUnavailableError(
            "status_list_too_large", "status list exceeded decompression limit"
        )
    return _status_value(raw, idx=idx, bits=bits) != 0


def _assert_public_target(url: str) -> None:
    """M1 SSRF defense: reject fetches whose hostname resolves to a private
    or otherwise unsafe IP class. Blocks AWS IMDS (169.254/16), loopback,
    RFC1918, link-local, multicast, reserved, and unspecified ranges.

    Residual TOCTOU: DNS can re-resolve to a different IP at actual fetch
    time. Acceptable for M1 — the common-case attack (Mission URL
    controlled by adversary pointing at 169.254.169.254) is closed here.
    A stronger fix would pin the resolved IP into urlopen via a custom
    HTTPSConnection factory; tracked as a future hardening.
    """
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    if not host:
        raise MissionBindingError("chain_invalid", "url missing hostname")
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        # Fail-open on DNS failure: the attacker can't bypass the IP-class
        # block because urlopen's own getaddrinfo will also fail (or hit
        # the same /etc/hosts entry we'd see here). Letting urlopen handle
        # the unresolvable case keeps test mocks working and preserves
        # fail-closed semantics at the fetch layer (URLError → caller).
        return
    seen: set[str] = set()
    for info in infos:
        ip_str = info[4][0]
        if ip_str in seen:
            continue
        seen.add(ip_str)
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise MissionBindingError(
                "chain_invalid",
                f"url resolves to non-public IP {ip_str} (class blocked to defeat SSRF)",
            )


class _PinnedIPHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that connects to a pre-resolved, pre-validated IP
    rather than re-resolving the hostname at connect time.

    Closes the residual TOCTOU between :func:`_assert_public_target` and
    the subsequent socket connection (FIX-7 from S2 hostile audit). The
    original hostname is preserved for TLS SNI and certificate
    validation, so the security properties of HTTPS are maintained.
    """

    def __init__(
        self,
        host: str,
        *,
        pinned_ip: str,
        port: int | None = None,
        timeout: float | None = None,
        context: ssl.SSLContext | None = None,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:  # noqa: D401 — interface override
        # socket.create_connection bypasses DNS by accepting an IP literal,
        # so the hostname → IP resolution we already did stays binding.
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port),
            self.timeout,
        )
        if self._tunnel_host is not None:  # pragma: no cover — proxy path
            self._tunnel()
        # TLS handshake still uses ``self.host`` for SNI + cert validation.
        if isinstance(self._context, ssl.SSLContext):
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def _resolve_to_pinned_public_ip(host: str, port: int) -> str:
    """Resolve ``host`` and return the first IP that passes
    :func:`_assert_public_target`'s class checks.

    The returned IP is the one we'll connect to — guaranteeing that the
    IP we validated is the IP we use, regardless of any DNS rebind that
    might happen between validation and connect.
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise MissionStatusUnavailableError(
            "revocation_unavailable",
            f"DNS resolution failed for {host}: {exc}",
        ) from exc
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return ip_str
    raise MissionBindingError(
        "chain_invalid",
        f"all resolved IPs for {host} are non-public; refusing to fetch",
    )


class _PinnedIPResponse:
    """Adapter that exposes :class:`http.client.HTTPResponse` through the
    minimal urllib-style context-manager interface :func:`_fetch_text`
    expects (``read(size)`` returning bytes, plus ``__enter__``/``__exit__``)."""

    def __init__(
        self, conn: http.client.HTTPSConnection, resp: http.client.HTTPResponse
    ) -> None:
        self._conn = conn
        self._resp = resp

    def read(self, size: int = -1) -> bytes:
        return self._resp.read(size) if size != -1 else self._resp.read()

    def __enter__(self) -> "_PinnedIPResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # noqa: ANN001
        try:
            self._resp.close()
        finally:
            self._conn.close()
        return False


def _pinned_urlopen(
    request_or_url,
    timeout: float | None = None,
    context: ssl.SSLContext | None = None,
):
    """Production replacement for :func:`urllib.request.urlopen` that
    pins the resolved IP to defeat DNS-rebinding TOCTOU.

    This function is bound to :data:`urlopen` at the bottom of this
    module, so test monkeypatches that replace ``mission.urlopen``
    transparently substitute their own implementation. Real fetches go
    through the pinned-IP path; tests stay mockable.
    """
    if isinstance(request_or_url, Request):
        url = request_or_url.full_url
        headers = dict(request_or_url.header_items())
    else:
        url = str(request_or_url)
        headers = {}
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() != "https":
        raise URLError(
            f"_pinned_urlopen supports https only; got scheme {parsed.scheme!r}"
        )
    host = parsed.hostname
    if not host:
        raise URLError("_pinned_urlopen: url missing hostname")
    port = parsed.port or 443
    pinned_ip = _resolve_to_pinned_public_ip(host, port)

    conn = _PinnedIPHTTPSConnection(
        host,
        pinned_ip=pinned_ip,
        port=port,
        timeout=timeout,
        context=context or ssl.create_default_context(),
    )
    try:
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        # urlopen sets Host automatically from self.host, but we set it
        # explicitly to remove any chance of header injection through the
        # caller's URL parsing. Other caller-supplied headers (Accept etc)
        # are forwarded.
        send_headers = {**headers, "Host": host}
        conn.request("GET", path, headers=send_headers)
        resp = conn.getresponse()
    except OSError as exc:
        conn.close()
        raise URLError(f"pinned-IP fetch failed: {exc}") from exc
    # Round-3 audit closures (2026-04-28):
    #
    # 1. Reject HTTP redirects explicitly. ``urllib.request.urlopen``
    #    follows up to 10 redirects via HTTPRedirectHandler — re-resolving
    #    DNS at each hop and bypassing this function's pinned-IP guard.
    #    For the security-sensitive callers we serve (status lists,
    #    Mission Declarations), a redirect is an operational anomaly that
    #    should fail visibly, not silently land at a different host. If a
    #    real-world deployment legitimately needs redirects, the caller
    #    can resolve the target URL and reconfigure the producer rather
    #    than have us follow blindly.
    # 2. Surface HTTP error status. ``http.client`` returns the response
    #    object regardless of status; ``urllib.request.urlopen`` raises
    #    ``HTTPError`` on >=400. Without that, a 500 body would be passed
    #    to the JWT decoder downstream — fail-closed-ish, but the error
    #    path is murkier than necessary and an attacker who controls the
    #    pinned-IP cert could deliver crafted non-200 bodies. Match
    #    urlopen's behavior.
    if 300 <= resp.status < 400:
        location = resp.getheader("Location") or "(no Location header)"
        try:
            resp.close()
        finally:
            conn.close()
        raise URLError(
            f"pinned-IP fetch refused redirect (status {resp.status} -> "
            f"{location}); reconfigure the producer to serve final URLs"
        )
    if resp.status >= 400:
        body_preview = resp.read(256)
        try:
            resp.close()
        finally:
            conn.close()
        raise HTTPError(
            url,
            resp.status,
            f"pinned-IP fetch saw HTTP {resp.status}; body preview: {body_preview!r}",
            dict(resp.getheaders()) if hasattr(resp, "getheaders") else {},
            None,
        )
    return _PinnedIPResponse(conn, resp)


def _fetch_text(url: str) -> str:
    _assert_public_target(url)
    request = Request(
        url,
        headers={
            "Accept": "application/jwt, application/statuslist+jwt, application/json"
        },
    )
    try:
        with urlopen(
            request, timeout=_FETCH_TIMEOUT_S, context=ssl.create_default_context()
        ) as response:
            body = response.read(MAX_STATUS_LIST_BYTES + 1)
            if len(body) > MAX_STATUS_LIST_BYTES:
                raise MissionStatusUnavailableError(
                    "status_list_too_large", "status list response exceeded size limit"
                )
            return body.decode("utf-8").strip()
    except (HTTPError, URLError, OSError, TimeoutError) as exc:
        raise MissionStatusUnavailableError(
            "revocation_unavailable", f"fetch failed for {url}"
        ) from exc


def _parse_revocation_ref(revocation_ref: str) -> tuple[str, int]:
    parsed = urllib.parse.urlparse(revocation_ref)
    if parsed.scheme.lower() != "https":
        raise MissionBindingError("chain_invalid", "revocation_ref must use https")
    if not parsed.fragment:
        raise MissionBindingError(
            "chain_invalid", "revocation_ref must include #idx=<n>"
        )
    try:
        fragment = urllib.parse.parse_qs(parsed.fragment, strict_parsing=True)
    except ValueError as exc:
        raise MissionBindingError(
            "chain_invalid", "revocation_ref fragment is malformed"
        ) from exc
    idx_values = fragment.get("idx")
    if idx_values is None or len(idx_values) != 1:
        raise MissionBindingError(
            "chain_invalid", "revocation_ref must include exactly one idx"
        )
    try:
        idx = int(idx_values[0])
    except ValueError as exc:
        raise MissionBindingError(
            "chain_invalid", "revocation_ref idx must be an integer"
        ) from exc
    if idx < 0:
        raise MissionBindingError(
            "chain_invalid", "revocation_ref idx must be non-negative"
        )
    return urllib.parse.urlunparse(parsed._replace(fragment="")), idx


def _legacy_resource_scope(resource_scope: Any, resource_policies: Any) -> list[str]:
    if resource_scope is not None:
        return list(resource_scope)
    if not isinstance(resource_policies, list):
        return []
    patterns: list[str] = []
    for entry in resource_policies:
        if not isinstance(entry, dict):
            raise ValueError("resource_policies entries must be objects")
        pattern = entry.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise ValueError("resource_policies[].pattern must be a non-empty string")
        if pattern.startswith("glob:"):
            patterns.append(pattern[len("glob:") :])
        elif pattern.startswith("exact:"):
            patterns.append(pattern[len("exact:") :])
        else:
            patterns.append(pattern)
    return patterns


def _payload_digest(claims: dict[str, Any]) -> str:
    canonical = json.dumps(
        claims,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "sha-256:" + hashlib.sha256(canonical).hexdigest()


def _tuple_of_dicts(value: Any) -> tuple[dict[str, Any], ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise MissionBindingError("chain_invalid", "mission array field must be a list")
    items: list[dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, dict):
            raise MissionBindingError(
                "chain_invalid", "mission array field must contain objects"
            )
        items.append(copy.deepcopy(entry))
    return tuple(items)


def _tuple_of_strs(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise MissionBindingError("chain_invalid", "required_telemetry must be a list")
    items: list[str] = []
    for entry in value:
        if not isinstance(entry, str) or not entry:
            raise MissionBindingError(
                "chain_invalid", "required_telemetry must contain strings"
            )
        items.append(entry)
    return tuple(items)


def _dict_or_empty(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise MissionBindingError(
            "chain_invalid", "mission object field must be an object"
        )
    return copy.deepcopy(value)


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise MissionBindingError(
            "chain_invalid", "mission string field must be a non-empty string"
        )
    return value


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise MissionBindingError(
            "chain_invalid", "mission integer field must be an integer"
        ) from exc


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _status_value(raw: bytes, *, idx: int, bits: int) -> int:
    start_bit = idx * bits
    end_bit = start_bit + bits
    if end_bit > len(raw) * 8:
        raise MissionBindingError("chain_invalid", "status list idx is out of range")
    value = 0
    for bit_index in range(start_bit, end_bit):
        byte = raw[bit_index // 8]
        shift = 7 - (bit_index % 8)
        value = (value << 1) | ((byte >> shift) & 0x01)
    return value


# Late binding: rebind ``urlopen`` from the placeholder
# (``urllib.request.urlopen``) at the top of this module to the
# TOCTOU-resistant production implementation. Tests that monkeypatch
# ``vibap.mission.urlopen`` continue to work because monkeypatch replaces
# the variable at import time, after this rebind has run. (FIX-7,
# 2026-04-28.)
urlopen = _pinned_urlopen
