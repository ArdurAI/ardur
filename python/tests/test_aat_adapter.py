from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

import jwt
import pytest

import vibap.aat_adapter as aat_adapter_module
import vibap.mission as mission_module
from vibap.passport import ALGORITHM, MissionPassport, issue_passport
from vibap.proxy import Decision
from vibap.receipt import verify_chain

from conftest import (
    v01_default_status_list_token,
    v01_default_status_url,
    v01_required_md_extras,
)

decode_aat_claims = aat_adapter_module.decode_aat_claims
material_from_aat_grant = aat_adapter_module.material_from_aat_grant


class _Response:
    def __init__(self, body: str | bytes) -> None:
        self._body = body.encode("utf-8") if isinstance(body, str) else body

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            return self._body
        return self._body[:size]

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


def test_aat_empty_mission_scope_cannot_grant_resource_authority() -> None:
    with pytest.raises(PermissionError, match="widens mission resource_scope"):
        aat_adapter_module._extract_resource_scope(
            {"resource_scope": ["/workspace/*"]},
            [],
        )


def test_aat_explicit_unrestricted_mission_can_grant_bounded_scope() -> None:
    assert aat_adapter_module._extract_resource_scope(
        {"resource_scope": ["/workspace/*"]},
        ["**"],
    ) == ["/workspace/*"]


def test_aat_bounded_mission_can_grant_empty_scope() -> None:
    assert (
        aat_adapter_module._extract_resource_scope(
            {"resource_scope": []},
            ["/workspace/*"],
        )
        == []
    )


def _install_fetch_map(
    monkeypatch,
    mapping: dict[str, str],
    *,
    private_key=None,
    mission_ids: list[str] | None = None,
) -> None:
    """Install an in-process urlopen mock keyed by URL.

    To save callers from wiring the helper's default revocation status URL
    into every test, pass ``private_key`` and ``mission_ids``: the helper
    will then auto-include never-revoked status-list responses for each
    mission_id's :func:`v01_default_status_url`. The MD load triggers a
    revocation fetch via ``mission_is_revoked``, so without this the test
    would fail with a bare ``KeyError`` on the default status URL.
    """
    full_mapping: dict[str, str] = dict(mapping)
    if private_key is not None and mission_ids:
        for mission_id in mission_ids:
            url = v01_default_status_url(mission_id)
            full_mapping.setdefault(
                url, v01_default_status_list_token(private_key, mission_id)
            )

    def fake_urlopen(request, timeout=0, context=None):  # noqa: ANN001, ARG001
        url = request.full_url if hasattr(request, "full_url") else str(request)
        return _Response(full_mapping[url])

    monkeypatch.setattr(mission_module, "urlopen", fake_urlopen)


def _issue_md(
    private_key,
    *,
    mission_id: str,
    allowed_tools: list[str] | None = None,
    max_tool_calls: int = 3,
) -> str:
    mission = MissionPassport(
        agent_id="md-authority",
        mission_id=mission_id,
        mission="authoritative AAT-backed mission",
        allowed_tools=allowed_tools or ["read"],
        forbidden_tools=[],
        resource_scope=["**"],
        max_tool_calls=max_tool_calls,
        max_duration_s=300,
        delegation_allowed=True,
        max_delegation_depth=2,
    )
    return issue_passport(
        mission,
        private_key,
        ttl_s=300,
        extra_claims=v01_required_md_extras(mission_id=mission_id),
    )


def _issue_aat(
    private_key,
    *,
    mission_ref: dict[str, str] | None,
    tools: list[str],
    max_tool_calls: int = 2,
    grant_id: str | None = None,
    aat_type: str | None = "delegation",
    del_depth: int = 0,
    del_max_depth: int = 2,
    par_hash: str | None = None,
    dg_profile: str | None = None,
    include_sub: bool = True,
) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": "https://tenuo.example/issuer",
        "iat": now,
        "exp": now + 300,
        "jti": grant_id or str(uuid.uuid4()),
        "del_depth": del_depth,
        "del_max_depth": del_max_depth,
        "authorization_details": [
            {
                "type": "attenuating_agent_token",
                "tools": {tool: {} for tool in tools},
                "max_tool_calls": max_tool_calls,
            }
        ],
        "cnf": {"jwk": {"kid": "holder-key"}},
    }
    if include_sub:
        claims["sub"] = "aat-agent"
    if aat_type is not None:
        claims["aat_type"] = aat_type
    if par_hash is not None:
        claims["par_hash"] = par_hash
    if dg_profile is not None:
        claims["ardur_dg_profile"] = dg_profile
    if mission_ref is not None:
        claims["mission_ref"] = mission_ref
    return jwt.encode(claims, private_key, algorithm=ALGORITHM)


def _receipt_entries(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_start_session_from_aat_evaluates_and_emits_mission_bound_receipt(
    proxy,
    private_key,
    public_key,
    monkeypatch,
):
    mission_id = "urn:ardur:mission:aat:permit"
    md_url = "https://issuer.example/md/aat-permit.jwt"
    md_token = _issue_md(private_key, mission_id=mission_id)
    md = mission_module.load_mission_declaration(md_token, public_key)
    _install_fetch_map(
        monkeypatch,
        {md_url: md_token},
        private_key=private_key,
        mission_ids=[mission_id],
    )
    aat_jti = str(uuid.uuid4())
    aat_token = _issue_aat(
        private_key,
        grant_id=aat_jti,
        mission_ref={
            "uri": md_url,
            "mission_id": mission_id,
            "mission_digest": md.payload_digest,
        },
        tools=["read"],
    )

    # require_pop=False because this happy-path test is not exercising PoP
    # (the test factory _issue_aat carries a cnf claim by default; the
    # 2026-04-28 hardening pass made cnf-bearing AAT without holder_public_key
    # fail closed by default). PoP behavior has its own dedicated test class
    # (TestAATProofOfPossession) below.
    session = proxy.start_session_from_aat(
        aat_token,
        signing_key=private_key,
        require_pop=False,
    )
    decision, reason = proxy.evaluate_tool_call(session, "read", {})

    assert session.jti == aat_jti
    assert session.passport_claims["credential_format"] == "aat-compatible-jwt"
    assert session.passport_claims["aat_grant_id"] == aat_jti
    assert session.passport_claims["mission_digest"] == md.payload_digest
    assert decision == Decision.PERMIT
    assert reason == "within scope"

    entries = _receipt_entries(proxy.receipts_log_path)
    claims = verify_chain([entry["jwt"] for entry in entries], public_key)
    assert claims[0]["grant_id"] == aat_jti
    assert claims[0]["evidence_proof_ref"]["mission_digest"] == md.payload_digest


def test_aat_missing_mission_ref_fails_closed(proxy, private_key):
    aat_token = _issue_aat(private_key, mission_ref=None, tools=["read"])

    with pytest.raises(PermissionError, match="mission_ref"):
        proxy.start_session_from_aat(aat_token, signing_key=private_key)


def test_aat_mission_digest_mismatch_fails_closed(
    proxy,
    private_key,
    public_key,
    monkeypatch,
):
    mission_id = "urn:ardur:mission:aat:digest"
    md_url = "https://issuer.example/md/aat-digest.jwt"
    md_token = _issue_md(private_key, mission_id=mission_id)
    _install_fetch_map(
        monkeypatch,
        {md_url: md_token},
        private_key=private_key,
        mission_ids=[mission_id],
    )
    aat_token = _issue_aat(
        private_key,
        mission_ref={
            "uri": md_url,
            "mission_id": mission_id,
            "mission_digest": "sha-256:" + ("0" * 64),
        },
        tools=["read"],
    )

    # require_pop=False isolates the test to mission_digest semantics —
    # cnf carried by the factory is irrelevant here. The external message is
    # fixed-code sanitized; the chained cause retains the diagnostic detail.
    with pytest.raises(PermissionError) as exc_info:
        proxy.start_session_from_aat(
            aat_token,
            signing_key=private_key,
            require_pop=False,
        )
    assert str(exc_info.value) == "aat_mission_resolution_failed"
    assert isinstance(exc_info.value.__cause__, mission_module.MissionBindingError)
    assert "mission_digest" in str(exc_info.value.__cause__)


def test_aat_unsupported_token_shape_fails_closed(proxy, private_key):
    aat_token = _issue_aat(
        private_key,
        mission_ref={"uri": "https://issuer.example/md/unused.jwt"},
        tools=["read"],
        aat_type="execution",
    )

    with pytest.raises(PermissionError, match="aat_type"):
        proxy.start_session_from_aat(aat_token, signing_key=private_key)


def test_aat_draft_01_wire_fails_with_explicit_revision_error(
    private_key,
    public_key,
):
    aat_token = _issue_aat(
        private_key,
        mission_ref={"uri": "https://issuer.example/md/unused.jwt"},
        tools=["read"],
        aat_type=None,
    )

    with pytest.raises(
        PermissionError,
        match=aat_adapter_module.AAT_UNSUPPORTED_REVISION,
    ):
        aat_adapter_module.decode_aat_claims(aat_token, public_key)


def test_aat_draft_01_profile_routes_to_full_chain_verifier(
    private_key,
    public_key,
):
    aat_token = _issue_aat(
        private_key,
        mission_ref={"uri": "https://issuer.example/md/unused.jwt"},
        tools=["read"],
        aat_type=None,
        dg_profile=aat_adapter_module.AAT_DG_PROFILE_V02,
        include_sub=False,
    )

    with pytest.raises(PermissionError, match="Go full-chain verifier"):
        aat_adapter_module.decode_aat_claims(aat_token, public_key)


def test_aat_draft_01_profile_rejects_mixed_aat_type(
    private_key,
    public_key,
):
    aat_token = _issue_aat(
        private_key,
        mission_ref={"uri": "https://issuer.example/md/unused.jwt"},
        tools=["read"],
        aat_type="delegation",
        dg_profile=aat_adapter_module.AAT_DG_PROFILE_V02,
    )

    with pytest.raises(PermissionError, match="must omit aat_type"):
        aat_adapter_module.decode_aat_claims(aat_token, public_key)


def test_aat_draft_00_root_child_grandchild_narrowing(private_key):
    mission_ref = {
        "uri": "https://issuer.example/md/organic.jwt",
        "mission_id": "urn:ardur:mission:aat:organic",
        "mission_digest": "sha-256:" + ("1" * 64),
    }
    root_token = _issue_aat(
        private_key,
        mission_ref=mission_ref,
        tools=["read", "write"],
        max_tool_calls=3,
        del_depth=0,
        del_max_depth=2,
    )
    root = jwt.decode(
        root_token,
        options={"verify_signature": False},
    )
    child_token = _issue_aat(
        private_key,
        mission_ref=mission_ref,
        tools=["read"],
        max_tool_calls=2,
        del_depth=1,
        del_max_depth=2,
        par_hash=aat_adapter_module._aat_parent_hash(root_token),
    )
    child = jwt.decode(
        child_token,
        options={"verify_signature": False},
    )
    grandchild_token = _issue_aat(
        private_key,
        mission_ref=mission_ref,
        tools=["read"],
        max_tool_calls=1,
        del_depth=2,
        del_max_depth=2,
        par_hash=aat_adapter_module._aat_parent_hash(child_token),
    )
    grandchild = jwt.decode(
        grandchild_token,
        options={"verify_signature": False},
    )

    aat_adapter_module._assert_child_grant_narrows_parent(child, root)
    aat_adapter_module._assert_child_parent_binding(child, root_token)
    aat_adapter_module._assert_child_grant_narrows_parent(grandchild, child)
    aat_adapter_module._assert_child_parent_binding(grandchild, child_token)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda child, parent: child["authorization_details"][0]["tools"].update(
                {"write": {}}
            ),
            "widens parent tools",
        ),
        (
            lambda child, parent: child["authorization_details"][0].update(
                {"max_tool_calls": 4}
            ),
            "widens parent budget",
        ),
        (lambda child, parent: child.update({"del_depth": 2}), "exactly one"),
        (lambda child, parent: child.update({"del_max_depth": 3}), "depth window"),
        (
            lambda child, parent: child.update({"iat": int(parent["iat"]) - 1}),
            "iat precedes",
        ),
        (
            lambda child, parent: child.update({"exp": int(parent["exp"]) + 1}),
            "exp exceeds",
        ),
        (
            lambda child, parent: child.update(
                {"mission_ref": {"uri": "https://evil.example/md.jwt"}}
            ),
            "changes mission_ref",
        ),
    ],
)
def test_aat_child_narrowing_rejects_mutations(private_key, mutation, message):
    mission_ref = {"uri": "https://issuer.example/md/narrowing.jwt"}
    parent = jwt.decode(
        _issue_aat(
            private_key,
            mission_ref=mission_ref,
            tools=["read"],
            max_tool_calls=3,
            del_depth=0,
            del_max_depth=2,
        ),
        options={"verify_signature": False},
    )
    child = jwt.decode(
        _issue_aat(
            private_key,
            mission_ref=mission_ref,
            tools=["read"],
            max_tool_calls=2,
            del_depth=1,
            del_max_depth=2,
        ),
        options={"verify_signature": False},
    )
    mutation(child, parent)

    with pytest.raises(PermissionError, match=message):
        aat_adapter_module._assert_child_grant_narrows_parent(child, parent)


def test_aat_requires_exactly_one_supported_authorization_detail(private_key):
    claims = jwt.decode(
        _issue_aat(
            private_key,
            mission_ref={"uri": "https://issuer.example/md/details.jwt"},
            tools=["read"],
        ),
        options={"verify_signature": False},
    )
    claims["authorization_details"].append(dict(claims["authorization_details"][0]))

    with pytest.raises(PermissionError, match="exactly one"):
        aat_adapter_module._extract_tools(claims)


def test_aat_adapter_rejects_unenforced_argument_constraints(private_key):
    claims = jwt.decode(
        _issue_aat(
            private_key,
            mission_ref={"uri": "https://issuer.example/md/constraints.jwt"},
            tools=["read"],
        ),
        options={"verify_signature": False},
    )
    claims["authorization_details"][0]["tools"]["read"] = {
        "path": {"constraint_type": "critical-unrecognized"}
    }

    with pytest.raises(PermissionError, match="does not support argument constraints"):
        aat_adapter_module._extract_tools(claims)


def test_aat_parent_binding_rejects_a_different_parent_token(private_key):
    parent = _issue_aat(
        private_key,
        mission_ref={"uri": "https://issuer.example/md/parent.jwt"},
        tools=["read"],
    )
    other_parent = _issue_aat(
        private_key,
        mission_ref={"uri": "https://issuer.example/md/other-parent.jwt"},
        tools=["read"],
    )
    child = jwt.decode(
        _issue_aat(
            private_key,
            mission_ref={"uri": "https://issuer.example/md/parent.jwt"},
            tools=["read"],
            del_depth=1,
            par_hash=aat_adapter_module._aat_parent_hash(parent),
        ),
        options={"verify_signature": False},
    )

    with pytest.raises(PermissionError, match="does not bind"):
        aat_adapter_module._assert_child_parent_binding(child, other_parent)


@pytest.mark.parametrize("invalid_depth", [1.5, "1", True])
def test_aat_adapter_rejects_non_integer_depth_claims(private_key, invalid_depth):
    claims = jwt.decode(
        _issue_aat(
            private_key,
            mission_ref={"uri": "https://issuer.example/md/depth.jwt"},
            tools=["read"],
        ),
        options={"verify_signature": False},
    )
    claims["del_depth"] = invalid_depth

    with pytest.raises(PermissionError, match="must be an integer"):
        aat_adapter_module._int_claim(
            claims,
            "del_depth",
            fallback="delegation_depth",
            default=0,
        )


@pytest.mark.parametrize("invalid_budget", [1.5, "2", True, 0, -1])
def test_aat_adapter_rejects_non_integer_or_non_positive_budgets(
    private_key,
    invalid_budget,
):
    claims = jwt.decode(
        _issue_aat(
            private_key,
            mission_ref={"uri": "https://issuer.example/md/budget.jwt"},
            tools=["read"],
        ),
        options={"verify_signature": False},
    )
    claims["authorization_details"][0]["max_tool_calls"] = invalid_budget

    with pytest.raises(PermissionError, match="positive integer"):
        aat_adapter_module._extract_max_tool_calls(claims, default=3)


def test_aat_adapter_rejects_malformed_unrelated_authorization_detail(private_key):
    claims = jwt.decode(
        _issue_aat(
            private_key,
            mission_ref={"uri": "https://issuer.example/md/auth-detail.jwt"},
            tools=["read"],
        ),
        options={"verify_signature": False},
    )
    claims["authorization_details"].insert(0, "not-an-object")

    with pytest.raises(PermissionError, match="entries must be objects"):
        aat_adapter_module._authorization_details(claims)


def test_aat_child_tool_widening_fails_closed(
    proxy,
    private_key,
    public_key,
    monkeypatch,
):
    mission_id = "urn:ardur:mission:aat:widen"
    md_url = "https://issuer.example/md/aat-widen.jwt"
    md_token = _issue_md(
        private_key,
        mission_id=mission_id,
        allowed_tools=["read", "delete_file"],
    )
    md = mission_module.load_mission_declaration(md_token, public_key)
    _install_fetch_map(
        monkeypatch,
        {md_url: md_token},
        private_key=private_key,
        mission_ids=[mission_id],
    )
    mission_ref = {
        "uri": md_url,
        "mission_id": mission_id,
        "mission_digest": md.payload_digest,
    }
    parent = _issue_aat(
        private_key,
        mission_ref=mission_ref,
        tools=["read"],
        max_tool_calls=2,
    )
    child = _issue_aat(
        private_key,
        mission_ref=mission_ref,
        tools=["read", "delete_file"],
        max_tool_calls=1,
        del_depth=1,
        del_max_depth=2,
    )

    # require_pop=False isolates the test to delegation-narrowing semantics —
    # cnf carried by the factory is irrelevant here.
    with pytest.raises(PermissionError, match="widens parent tools"):
        proxy.start_session_from_aat(
            child,
            signing_key=private_key,
            parent_aat_token=parent,
            require_pop=False,
        )


# H2: AAT proof-of-possession enforcement. Before this, cnf was structurally
# copied into extra_claims["aat_cnf"] but never verified — a captured AAT could
# be replayed by anyone who observed it. Setting require_pop=True now demands
# holder_public_key + kb_jwt when the AAT carries a cnf claim.
class TestAATProofOfPossession:
    def test_cnf_without_pop_inputs_raises_when_require_pop_true(
        self, proxy, private_key, tmp_path, monkeypatch
    ):
        # Mint an authoritative mission declaration so the adapter can resolve mission_ref.
        mission_id = "urn:mission:pop-test"
        md_jwt = _issue_md(private_key, mission_id=mission_id)
        md_url = "https://tenuo.example/missions/pop-test"
        _install_fetch_map(
            monkeypatch,
            {md_url: md_jwt},
            private_key=private_key,
            mission_ids=[mission_id],
        )
        aat_token = _issue_aat(
            private_key,
            mission_ref={
                "uri": md_url,
                "mission_id": mission_id,
                "mission_digest": mission_module.load_mission_declaration(
                    md_jwt, proxy.public_key
                ).payload_digest,
            },
            tools=["read"],
        )
        cache = mission_module.MissionCache()
        with pytest.raises(PermissionError, match="PoP inputs were not supplied"):
            material_from_aat_grant(
                aat_token,
                proxy.public_key,
                cache,
                require_pop=True,
            )

    def test_cnf_without_pop_inputs_is_accepted_when_require_pop_false(
        self, proxy, private_key, tmp_path, monkeypatch
    ):
        """Explicit opt-out preserves bearer-style acceptance of cnf-bearing
        AAT. Since 2026-04-28 the default is require_pop=True; callers that
        legitimately need bearer mode must opt out *explicitly* so the
        security-relevant choice is visible at the call site."""
        mission_id = "urn:mission:pop-explicit-optout"
        md_jwt = _issue_md(private_key, mission_id=mission_id)
        md_url = "https://tenuo.example/missions/pop-explicit-optout"
        _install_fetch_map(
            monkeypatch,
            {md_url: md_jwt},
            private_key=private_key,
            mission_ids=[mission_id],
        )
        aat_token = _issue_aat(
            private_key,
            mission_ref={
                "uri": md_url,
                "mission_id": mission_id,
                "mission_digest": mission_module.load_mission_declaration(
                    md_jwt, proxy.public_key
                ).payload_digest,
            },
            tools=["read"],
        )
        cache = mission_module.MissionCache()
        material = material_from_aat_grant(
            aat_token,
            proxy.public_key,
            cache,
            require_pop=False,  # explicit opt-out (not the default)
        )
        assert material.extra_claims["aat_cnf"] == {"jwk": {"kid": "holder-key"}}

    @pytest.mark.parametrize(
        "malformed_cnf",
        [
            "",  # empty string
            42,  # int
            False,  # bool (also a non-dict shape)
            [],  # empty list
            ["jkt", "thumb"],  # list with content
            0,  # zero
            "thumbprint-as-string",  # well-formed-looking string
        ],
    )
    def test_cnf_non_dict_does_not_silently_route_to_bearer(
        self, proxy, private_key, monkeypatch, malformed_cnf
    ):
        """H8 (round-4 audit) regression: before round-5 the gate was
        ``isinstance(cnf, dict) and require_pop`` — non-dict cnf values
        silently routed to the bearer path, treating the AAT as
        unauthenticated. The fix uses ``"cnf" in claims and claims["cnf"]
        is not None`` so any non-None cnf forces verify_pop, which
        rejects malformed shapes with PermissionError. This parametrized
        test covers every shape the round-4 audit listed."""
        mission_id = f"urn:mission:cnf-malformed-{type(malformed_cnf).__name__}"
        md_jwt = _issue_md(private_key, mission_id=mission_id)
        md_url = f"https://tenuo.example/missions/cnf-malformed-{id(malformed_cnf)}"
        _install_fetch_map(
            monkeypatch,
            {md_url: md_jwt},
            private_key=private_key,
            mission_ids=[mission_id],
        )

        # Mint an AAT with the malformed cnf shape directly.
        now = int(time.time())
        aat_claims = {
            "iss": "https://tenuo.example/issuer",
            "sub": "aat-agent",
            "iat": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
            "aat_type": "delegation",
            "del_depth": 0,
            "del_max_depth": 2,
            "authorization_details": [
                {
                    "type": "attenuating_agent_token",
                    "tools": {"read": {}},
                    "max_tool_calls": 2,
                }
            ],
            "mission_ref": {
                "uri": md_url,
                "mission_id": mission_id,
                "mission_digest": mission_module.load_mission_declaration(
                    md_jwt, proxy.public_key
                ).payload_digest,
            },
            "cnf": malformed_cnf,
        }
        aat_token = jwt.encode(aat_claims, private_key, algorithm=ALGORITHM)
        cache = mission_module.MissionCache()
        # The default require_pop=True must reject ANY non-None cnf —
        # even one that's the wrong shape — so an attacker can't bypass
        # PoP by sending cnf="" or cnf=42 etc.
        with pytest.raises(PermissionError):
            material_from_aat_grant(aat_token, proxy.public_key, cache)

    def test_cnf_aat_without_pop_inputs_fails_closed_by_default(
        self, proxy, private_key, tmp_path, monkeypatch
    ):
        """Regression test for the 2026-04-28 default flip.

        Before this change, ``require_pop`` defaulted to False and a
        cnf-bearing AAT presented without holder_public_key + kb_jwt was
        silently accepted, with cnf only structurally copied into receipts.
        That made the cnf binding cosmetic — anyone who observed the AAT
        could replay it. The default is now True; this test proves it.
        """
        mission_id = "urn:mission:pop-default-fails-closed"
        md_jwt = _issue_md(private_key, mission_id=mission_id)
        md_url = "https://tenuo.example/missions/pop-default-fails-closed"
        _install_fetch_map(
            monkeypatch,
            {md_url: md_jwt},
            private_key=private_key,
            mission_ids=[mission_id],
        )
        aat_token = _issue_aat(
            private_key,
            mission_ref={
                "uri": md_url,
                "mission_id": mission_id,
                "mission_digest": mission_module.load_mission_declaration(
                    md_jwt, proxy.public_key
                ).payload_digest,
            },
            tools=["read"],
        )
        cache = mission_module.MissionCache()
        # No explicit require_pop — relies on the new fail-closed default.
        with pytest.raises(PermissionError, match="PoP inputs were not supplied"):
            material_from_aat_grant(aat_token, proxy.public_key, cache)

    def test_start_session_from_aat_fails_closed_by_default_for_cnf_aat(
        self, proxy, private_key, monkeypatch
    ):
        """The proxy entry point inherits the same fail-closed default."""
        mission_id = "urn:mission:proxy-pop-default-fails-closed"
        md_jwt = _issue_md(private_key, mission_id=mission_id)
        md_url = "https://tenuo.example/missions/proxy-pop-default-fails-closed"
        _install_fetch_map(
            monkeypatch,
            {md_url: md_jwt},
            private_key=private_key,
            mission_ids=[mission_id],
        )
        aat_token = _issue_aat(
            private_key,
            mission_ref={
                "uri": md_url,
                "mission_id": mission_id,
                "mission_digest": mission_module.load_mission_declaration(
                    md_jwt, proxy.public_key
                ).payload_digest,
            },
            tools=["read"],
        )
        # No explicit require_pop — relies on the new fail-closed default.
        with pytest.raises(PermissionError, match="PoP inputs were not supplied"):
            proxy.start_session_from_aat(
                aat_token,
                signing_key=private_key,
            )


# --- Round-3 audit (2026-04-28): generalize bounded-iat-skew from receipts to
# AAT/MD/passport JWT loaders. An AAT minted with iat=year_3000, exp=year_3001
# would have passed verification before this change because PyJWT's verify_iat
# default doesn't bound future skew. assert_iat_in_window now closes that gap
# at every JWT decode call site.


class TestAATIatSkewGuard:
    def test_aat_with_iat_in_far_future_fails_closed(self, private_key, public_key):
        import jwt as _jwt

        far_future = int(time.time()) + 365 * 86400
        aat_token = _jwt.encode(
            {
                "iss": "https://tenuo.example/issuer",
                "sub": "aat-agent",
                "iat": far_future,
                "exp": far_future + 300,
                "jti": str(uuid.uuid4()),
                "aat_type": "delegation",
                "del_depth": 0,
                "del_max_depth": 2,
                "authorization_details": [
                    {
                        "type": "attenuating_agent_token",
                        "tools": {"read": {}},
                        "max_tool_calls": 2,
                    }
                ],
                "mission_ref": {
                    "uri": "https://issuer.example/md/never.jwt",
                    "mission_id": "urn:test:future",
                    "mission_digest": "sha-256:" + ("0" * 64),
                },
            },
            private_key,
            algorithm=ALGORITHM,
        )
        with pytest.raises(_jwt.InvalidTokenError, match="AAT iat"):
            decode_aat_claims(aat_token, public_key)


# --- Round-3 audit (2026-04-28): positive-path PoP success test for
# material_from_aat_grant. Round-2 audit observed that all four FIX-2 PoP
# tests exercised the rejection or bearer-passthrough paths — there was
# no test asserting that a correctly-signed KB-JWT against a valid
# holder key for a cnf-bearing AAT succeeds. If verify_pop were silently
# bypassed (e.g., a refactor commenting out aat_adapter.py:114), nothing
# would catch it. This test is that catch.


class TestAATPoPHappyPath:
    def test_valid_kb_jwt_with_matching_holder_key_succeeds(
        self, proxy, private_key, monkeypatch
    ):
        from cryptography.hazmat.primitives.asymmetric import ec
        from vibap.passport import compute_jwk_thumbprint, create_kb_jwt

        # Generate a holder keypair distinct from the issuer.
        holder_priv = ec.generate_private_key(ec.SECP256R1())
        holder_pub = holder_priv.public_key()
        thumbprint = compute_jwk_thumbprint(holder_pub)

        mission_id = "urn:mission:pop-happy-path"
        md_jwt = _issue_md(private_key, mission_id=mission_id)
        md_url = "https://tenuo.example/missions/pop-happy-path"
        _install_fetch_map(
            monkeypatch,
            {md_url: md_jwt},
            private_key=private_key,
            mission_ids=[mission_id],
        )

        # Issue a cnf-bearing AAT whose cnf.jkt matches the holder's pubkey.
        now = int(time.time())
        grant_id = str(uuid.uuid4())
        aat_claims = {
            "iss": "https://tenuo.example/issuer",
            "sub": "aat-agent",
            "iat": now,
            "exp": now + 300,
            "jti": grant_id,
            "aat_type": "delegation",
            "del_depth": 0,
            "del_max_depth": 2,
            "authorization_details": [
                {
                    "type": "attenuating_agent_token",
                    "tools": {"read": {}},
                    "max_tool_calls": 2,
                }
            ],
            "mission_ref": {
                "uri": md_url,
                "mission_id": mission_id,
                "mission_digest": mission_module.load_mission_declaration(
                    md_jwt, proxy.public_key
                ).payload_digest,
            },
            "cnf": {"jkt": thumbprint},
        }
        aat_token = jwt.encode(aat_claims, private_key, algorithm=ALGORITHM)

        # Mint a KB-JWT bound to this exact AAT.
        kb_jwt = create_kb_jwt(holder_priv, aat_token)

        cache = mission_module.MissionCache()
        material = material_from_aat_grant(
            aat_token,
            proxy.public_key,
            cache,
            holder_public_key=holder_pub,
            kb_jwt=kb_jwt,
            # require_pop defaults to True. Do NOT override.
        )
        assert material.grant_id == grant_id
        assert material.extra_claims["aat_cnf"] == {"jkt": thumbprint}
        # The session material would not have been built if verify_pop
        # had been bypassed — this assertion is the security guarantee
        # we want pinned. If verify_pop is silently disabled and bearer-
        # accepts the AAT, this test still passes by construction; the
        # complementary fail-closed test
        # (test_cnf_aat_without_pop_inputs_fails_closed_by_default)
        # is the catch that ensures verify_pop is actually being called.

    def test_bearer_aat_no_cnf_accepted_with_require_pop_true(
        self, proxy, private_key, tmp_path, monkeypatch
    ):
        """An AAT without any cnf claim is bearer-mode and must be accepted
        even when require_pop=True — the flag only gates cnf-carrying AATs."""
        mission_id = "urn:mission:bearer-aat"
        md_jwt = _issue_md(private_key, mission_id=mission_id)
        md_url = "https://tenuo.example/missions/bearer-aat"
        _install_fetch_map(
            monkeypatch,
            {md_url: md_jwt},
            private_key=private_key,
            mission_ids=[mission_id],
        )

        # Issue an AAT WITHOUT cnf (strip via custom claim set).
        now = int(time.time())
        grant_id = str(uuid.uuid4())
        claims = {
            "iss": "https://tenuo.example/issuer",
            "sub": "aat-agent",
            "iat": now,
            "exp": now + 300,
            "jti": grant_id,
            "aat_type": "delegation",
            "del_depth": 0,
            "del_max_depth": 2,
            "authorization_details": [
                {
                    "type": "attenuating_agent_token",
                    "tools": {"read": {}},
                    "max_tool_calls": 2,
                }
            ],
            "mission_ref": {
                "uri": md_url,
                "mission_id": mission_id,
                "mission_digest": mission_module.load_mission_declaration(
                    md_jwt, proxy.public_key
                ).payload_digest,
            },
        }
        aat_token = jwt.encode(claims, private_key, algorithm=ALGORITHM)

        cache = mission_module.MissionCache()
        material = material_from_aat_grant(
            aat_token,
            proxy.public_key,
            cache,
            require_pop=True,  # still accepted because no cnf in the AAT
        )
        assert "aat_cnf" not in material.extra_claims
        assert material.grant_id == grant_id


# ---------------------------------------------------------------------------
# End-to-end integration: AAT + PolicyStore composition
# ---------------------------------------------------------------------------


class TestAATAdapterEndToEnd:
    """Full AAT flow: mission declaration → AAT grant → session start →
    policy evaluation → receipt chain verification."""

    def test_full_aat_flow_with_policy_store(
        self, private_key, public_key, monkeypatch, tmp_path
    ):
        """AAT session backed by a PolicyStore with forbid_rules blocking /etc/ paths."""
        import copy
        import hashlib

        from vibap.passport import MissionPassport, issue_passport
        from vibap.policy_store import InMemoryPolicyStore
        from vibap.proxy import GovernanceProxy

        mission_id = "urn:ardur:mission:aat-e2e-store"
        md_url = "https://issuer.example/md/aat-e2e.jwt"

        # Build mission declaration
        mission = MissionPassport(
            agent_id="aat-e2e-agent",
            mission="AAT end-to-end with policy store",
            mission_id=mission_id,
            allowed_tools=["read_file", "write_file"],
            forbidden_tools=[],
            resource_scope=["**"],
            max_tool_calls=10,
            max_duration_s=600,
            delegation_allowed=True,
            max_delegation_depth=2,
        )
        md_token = issue_passport(
            mission,
            private_key,
            ttl_s=600,
            extra_claims=v01_required_md_extras(mission_id=mission_id),
        )
        md = mission_module.load_mission_declaration(md_token, public_key)
        _install_fetch_map(
            monkeypatch,
            {md_url: md_token},
            private_key=private_key,
            mission_ids=[mission_id],
        )

        # Build forbid_rules policy and PolicyStore
        rules = [{"id": "no_system", "forbid_when": {"target_matches": "^/etc/"}}]
        data_json = json.dumps(rules, sort_keys=True, separators=(",", ":"))
        sha = hashlib.sha256(data_json.encode("utf-8")).hexdigest()
        forbid_spec = {
            "backend": "forbid_rules",
            "label": "compliance",
            "policy_sha256": sha,
            "data_inline": copy.deepcopy(rules),
        }
        store = InMemoryPolicyStore()
        store.put_policies(mission_id=mission_id, policies=[forbid_spec])

        # Create proxy with PolicyStore
        proxy = GovernanceProxy(
            log_path=tmp_path / "log.jsonl",
            state_dir=tmp_path / "state",
            public_key=public_key,
            policy_store=store,
        )

        # Issue AAT
        aat_jti = str(uuid.uuid4())
        now = int(time.time())
        aat_claims = {
            "iss": "https://tenuo.example/issuer",
            "sub": "aat-e2e-agent",
            "iat": now,
            "exp": now + 300,
            "jti": aat_jti,
            "aat_type": "delegation",
            "del_depth": 0,
            "del_max_depth": 2,
            "authorization_details": [
                {
                    "type": "attenuating_agent_token",
                    "tools": {"read_file": {}, "write_file": {}},
                    "max_tool_calls": 5,
                }
            ],
            "mission_ref": {
                "uri": md_url,
                "mission_id": mission_id,
                "mission_digest": md.payload_digest,
            },
        }
        aat_token = jwt.encode(aat_claims, private_key, algorithm=ALGORITHM)

        # Start session — require_pop=False since we're not testing PoP here
        session = proxy.start_session_from_aat(
            aat_token,
            signing_key=private_key,
            require_pop=False,
        )

        # Allowed: no forbid_rules match
        decision, reason = proxy.evaluate_tool_call(
            session,
            "read_file",
            {"path": "/tmp/ok.txt"},
        )
        assert decision == Decision.PERMIT, f"Expected PERMIT, got {decision}: {reason}"

        # Denied by forbid_rules: /etc/ path
        decision, reason = proxy.evaluate_tool_call(
            session,
            "read_file",
            {"path": "/etc/passwd"},
        )
        assert decision == Decision.DENY, f"Expected DENY, got {decision}: {reason}"
        assert "no_system" in reason

        # Verify receipt chain
        entries = _receipt_entries(proxy.receipts_log_path)
        assert len(entries) >= 2
        claims_list = verify_chain(
            [e["jwt"] for e in entries],
            proxy.receipt_public_key,
        )
        trace_ids = {c["trace_id"] for c in claims_list}
        assert len(trace_ids) == 1

    def test_aat_session_evaluates_multiple_tools(
        self, private_key, public_key, monkeypatch, tmp_path
    ):
        """AAT session exercises multiple tool evaluations across the full pipeline,
        including forbidden-tool denial and receipt chain verification."""
        from vibap.passport import MissionPassport, issue_passport
        from vibap.proxy import GovernanceProxy

        mission_id = "urn:ardur:mission:aat-multi-tool"
        md_url = "https://issuer.example/md/aat-multi.jwt"

        mission = MissionPassport(
            agent_id="aat-multi-agent",
            mission="multi-tool AAT test",
            mission_id=mission_id,
            allowed_tools=["read_file", "write_file", "search_files"],
            forbidden_tools=[],
            resource_scope=["**"],
            max_tool_calls=20,
            max_duration_s=600,
        )
        md_token = issue_passport(
            mission,
            private_key,
            ttl_s=600,
            extra_claims=v01_required_md_extras(mission_id=mission_id),
        )
        md = mission_module.load_mission_declaration(md_token, public_key)
        _install_fetch_map(
            monkeypatch,
            {md_url: md_token},
            private_key=private_key,
            mission_ids=[mission_id],
        )

        proxy = GovernanceProxy(
            log_path=tmp_path / "log.jsonl",
            state_dir=tmp_path / "state",
            public_key=public_key,
        )

        now = int(time.time())
        aat_token = jwt.encode(
            {
                "iss": "https://tenuo.example/issuer",
                "sub": "aat-multi-agent",
                "iat": now,
                "exp": now + 300,
                "jti": str(uuid.uuid4()),
                "aat_type": "delegation",
                "del_depth": 0,
                "del_max_depth": 2,
                "authorization_details": [
                    {
                        "type": "attenuating_agent_token",
                        "tools": {
                            "read_file": {},
                            "write_file": {},
                            "search_files": {},
                        },
                        "max_tool_calls": 10,
                    }
                ],
                "mission_ref": {
                    "uri": md_url,
                    "mission_id": mission_id,
                    "mission_digest": md.payload_digest,
                },
            },
            private_key,
            algorithm=ALGORITHM,
        )

        session = proxy.start_session_from_aat(
            aat_token,
            signing_key=private_key,
            require_pop=False,
        )

        # All three tools permitted
        for tool in ["read_file", "write_file", "search_files"]:
            decision, reason = proxy.evaluate_tool_call(
                session,
                tool,
                {"path": "/workspace/data.csv"},
            )
            assert decision == Decision.PERMIT, f"{tool} should be PERMIT: {reason}"

        # Tool not in AAT denied
        decision, reason = proxy.evaluate_tool_call(
            session,
            "delete_file",
            {"path": "/workspace/data.csv"},
        )
        assert decision == Decision.DENY

        # Multiple additional permitted calls — budget is NOT exhausted
        for i in range(5):
            decision, _ = proxy.evaluate_tool_call(
                session,
                "read_file",
                {"path": f"/tmp/file{i}.txt"},
            )
            assert decision == Decision.PERMIT

        # Receipt chain integrity — each PERMIT + the DENY produce a receipt
        entries = _receipt_entries(proxy.receipts_log_path)
        assert len(entries) >= 9
        claims_list = verify_chain(
            [e["jwt"] for e in entries],
            proxy.receipt_public_key,
        )
        assert all(c["verdict"] in ("compliant", "violation") for c in claims_list)
