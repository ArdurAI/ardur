from __future__ import annotations

import hashlib
from dataclasses import fields

import pytest
from biscuit_auth import (
    Biscuit,
    BiscuitValidationError,
    BlockBuilder,
    Fact,
    KeyPair,
    UnverifiedBiscuit,
)

from vibap.biscuit_passport import (
    BiscuitAttenuationError,
    BiscuitIssueError,
    BiscuitVerifyError,
    PassportContext,
    _parse_block_source,
    decode_biscuit_b64,
    derive_child_biscuit,
    encode_biscuit_b64,
    issue_biscuit_passport,
    verify_biscuit_passport,
)
from vibap.passport import MissionPassport


def _mission(**overrides: object) -> MissionPassport:
    payload: dict[str, object] = {
        "agent_id": "agent-001",
        "mission": "analyze quarterly data",
        "allowed_tools": ["read_file", "search", "write_file"],
        "forbidden_tools": ["delete_file"],
        "resource_scope": ["/workspace/project"],
        "max_tool_calls": 5,
        "max_duration_s": 300,
        "delegation_allowed": True,
        "max_delegation_depth": 3,
        "cwd": "/workspace/project",
        "allowed_side_effect_classes": ["none", "external_send"],
        "max_tool_calls_per_class": {"external_send": 1},
        "holder_spiffe_id": "spiffe://example.org/agent/root",
    }
    payload.update(overrides)
    return MissionPassport(**payload)


def _keypair() -> KeyPair:
    return KeyPair()


def _block_facts(token: bytes, public_key) -> dict[str, list[list[object]]]:
    biscuit = Biscuit.from_bytes(token, public_key)
    return _parse_block_source(biscuit.block_source(0))


def _tamper_token_at_marker(token: bytes, marker: bytes) -> bytes:
    raw = bytearray(token)
    index = bytes(raw).find(marker)
    if index < 0:
        raise AssertionError(f"marker not found in token bytes: {marker!r}")
    raw[index] ^= 0x01
    return bytes(raw)


def _append_handcrafted_child(
    parent: bytes,
    public_key: object,
    *,
    expected_parent_jti: str,
    **overrides: list[str],
) -> bytes:
    """Append a structured child without using the trusted issuance helper."""

    facts_by_name = {
        "jti": ['jti("handcrafted-child")'],
        "parent_jti": [f'parent_jti("{expected_parent_jti}")'],
        "spiffe_id": ['spiffe_id("spiffe://example.org/agent/attacker")'],
        "iat": ["iat(101)"],
        "exp": ["exp(301)"],
        "max_tool_calls": ["max_tool_calls(4)"],
        "max_duration_s": ["max_duration_s(200)"],
        "delegation_allowed": ["delegation_allowed(true)"],
        "max_delegation_depth": ["max_delegation_depth(2)"],
        "cwd": ['cwd("/workspace/project/reports")'],
        "allowed_tool": [
            'allowed_tool("read_file")',
            'allowed_tool("search")',
        ],
        "forbidden_tool": [
            'forbidden_tool("delete_file")',
            'forbidden_tool("write_file")',
        ],
        "resource_scope": ['resource_scope("/workspace/project/reports")'],
        "allowed_side_effect_class": [
            'allowed_side_effect_class("none")',
            'allowed_side_effect_class("external_send")',
        ],
        "max_tool_calls_per_class": [
            'max_tool_calls_per_class("external_send", 1)'
        ],
    }
    facts_by_name.update(overrides)
    block = BlockBuilder()
    for fact_sources in facts_by_name.values():
        for source in fact_sources:
            block.add_fact(Fact(source))
    return bytes(Biscuit.from_bytes(parent, public_key).append(block).to_bytes())


def test_issue_emits_valid_biscuit_parseable_by_unverified_biscuit() -> None:
    keypair = _keypair()
    token = issue_biscuit_passport(
        _mission(),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    unverified = UnverifiedBiscuit.from_base64(encode_biscuit_b64(token))

    assert unverified.block_count() == 1


def test_issue_sets_expected_facts_from_mission_dataclass() -> None:
    keypair = _keypair()
    mission = _mission()
    token = issue_biscuit_passport(
        mission,
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    facts = _block_facts(token, keypair.public_key)

    assert facts["agent_id"] == [["agent-001"]]
    assert facts["spiffe_id"] == [["spiffe://example.org/agent/root"]]
    assert facts["issuer_spiffe_id"] == [["spiffe://example.org/issuer/root"]]
    assert facts["mission"] == [["analyze quarterly data"]]
    assert facts["allowed_tool"] == [["read_file"], ["search"], ["write_file"]]
    assert facts["forbidden_tool"] == [["delete_file"]]
    assert facts["resource_scope"] == [["/workspace/project"]]
    assert facts["allowed_side_effect_class"] == [["none"], ["external_send"]]
    assert facts["max_tool_calls_per_class"] == [["external_send", 1]]


def test_issue_writes_cwd_only_when_set() -> None:
    keypair = _keypair()
    token_without_cwd = issue_biscuit_passport(
        _mission(cwd=None),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    token_with_cwd = issue_biscuit_passport(
        _mission(cwd="/workspace/project/subdir"),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    without_facts = _block_facts(token_without_cwd, keypair.public_key)
    with_facts = _block_facts(token_with_cwd, keypair.public_key)

    assert "cwd" not in without_facts
    assert with_facts["cwd"] == [["/workspace/project/subdir"]]


def test_issue_serializes_per_class_budget_correctly() -> None:
    keypair = _keypair()
    token = issue_biscuit_passport(
        _mission(max_tool_calls_per_class={"external_send": 1, "state_change": 2}),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    facts = _block_facts(token, keypair.public_key)

    assert facts["max_tool_calls_per_class"] == [
        ["external_send", 1],
        ["state_change", 2],
    ]


def test_issue_raises_on_empty_agent_id() -> None:
    keypair = _keypair()

    with pytest.raises(BiscuitIssueError, match="agent_id must be non-empty"):
        issue_biscuit_passport(
            _mission(agent_id=""),
            keypair.private_key,
            "spiffe://example.org/issuer/root",
            now=100,
        )


def test_verify_accepts_valid_biscuit() -> None:
    keypair = _keypair()
    token = issue_biscuit_passport(
        _mission(),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    context = verify_biscuit_passport(token, keypair.public_key, now=101)

    assert context.agent_id == "agent-001"
    assert context.spiffe_id == "spiffe://example.org/agent/root"
    assert context.issuer_spiffe_id == "spiffe://example.org/issuer/root"


def test_verify_rejects_wrong_root_public_key() -> None:
    issuer = _keypair()
    other = _keypair()
    token = issue_biscuit_passport(
        _mission(),
        issuer.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    with pytest.raises(BiscuitVerifyError, match="invalid signature/format"):
        verify_biscuit_passport(token, other.public_key, now=101)


def test_verify_rejects_expired_biscuit() -> None:
    keypair = _keypair()
    token = issue_biscuit_passport(
        _mission(max_duration_s=1),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        ttl_s=1,
        now=100,
    )

    with pytest.raises(BiscuitVerifyError, match="authorize failed"):
        verify_biscuit_passport(token, keypair.public_key, now=102)


def test_verify_populates_passport_context_fully() -> None:
    keypair = _keypair()
    token = issue_biscuit_passport(
        _mission(),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    context = verify_biscuit_passport(token, keypair.public_key, now=101)

    # H1 (2026-04-19): mission_id is now a first-class field on
    # PassportContext. Assertion references context.mission_id directly
    # rather than hard-coding the derivation so the test is agnostic to
    # the derive_mission_id implementation. The separate assertions
    # below pin the exact derived value for this fixture, which IS
    # the behavioral contract tests should lock in.
    expected_mission_id = (
        "mission:agent-001:"
        + hashlib.sha256(b"analyze quarterly data").hexdigest()[:12]
    )
    assert context.mission_id == expected_mission_id
    assert context == PassportContext(
        agent_id="agent-001",
        spiffe_id="spiffe://example.org/agent/root",
        mission="analyze quarterly data",
        mission_id=expected_mission_id,
        allowed_tools=["read_file", "search", "write_file"],
        forbidden_tools=["delete_file"],
        resource_scope=["/workspace/project"],
        allowed_side_effect_classes=["external_send", "none"],  # sorted output is deterministic
        max_tool_calls=5,
        max_tool_calls_per_class={"external_send": 1},
        max_duration_s=300,
        delegation_allowed=True,
        max_delegation_depth=3,
        cwd="/workspace/project",
        jti=context.jti,
        parent_jti=None,
        issuer_spiffe_id="spiffe://example.org/issuer/root",
        expires_at=700,
        issued_at=100,
        delegation_depth=0,
        delegation_chain=[
            {
                "jti": context.jti,
                "spiffe_id": "spiffe://example.org/agent/root",
                "token_hash": context.delegation_chain[0]["token_hash"],
            }
        ],
        extra_facts={},
    )
    assert len(context.delegation_chain[0]["token_hash"]) == 64


def test_verify_succeeds_on_mission_description_with_newlines_and_special_chars() -> None:
    keypair = _keypair()
    mission_text = 'line 1\nline 2 (nested(example)) and "quoted text"'
    token = issue_biscuit_passport(
        _mission(mission=mission_text),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    context = verify_biscuit_passport(token, keypair.public_key, now=101)

    assert context.mission == mission_text


def test_verify_rejects_malformed_bytes() -> None:
    keypair = _keypair()

    with pytest.raises(BiscuitVerifyError, match="invalid signature/format"):
        verify_biscuit_passport(b"not-a-biscuit", keypair.public_key, now=100)


def test_derive_narrows_allowed_tools() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    child = derive_child_biscuit(
        parent,
        keypair.private_key,
        "spiffe://example.org/agent/child",
        child_allowed_tools=["read_file"],
        now=101,
    )

    context = verify_biscuit_passport(child, keypair.public_key, now=102)

    assert context.allowed_tools == ["read_file"]
    assert sorted(context.forbidden_tools) == ["delete_file", "search", "write_file"]


def test_derive_rejects_scope_expansion() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(resource_scope=["/workspace/project/reports"]),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    with pytest.raises(BiscuitAttenuationError, match="resource scope expansion"):
        derive_child_biscuit(
            parent,
            keypair.private_key,
            "spiffe://example.org/agent/child",
            child_resource_scope=["/workspace/project"],
            now=101,
        )


def test_explicit_unrestricted_parent_can_derive_bounded_scope() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(resource_scope=["**"]),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    child = derive_child_biscuit(
        parent,
        keypair.private_key,
        "spiffe://example.org/agent/child",
        child_resource_scope=["/workspace/project"],
        now=101,
    )

    context = verify_biscuit_passport(child, keypair.public_key, now=102)
    assert context.resource_scope == ["/workspace/project"]


def test_empty_parent_scope_cannot_derive_resource_authority() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(resource_scope=[]),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    with pytest.raises(BiscuitAttenuationError, match="resource scope expansion"):
        derive_child_biscuit(
            parent,
            keypair.private_key,
            "spiffe://example.org/agent/child",
            child_resource_scope=["/workspace/project"],
            now=101,
        )


def test_bounded_parent_can_derive_empty_resource_scope() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(resource_scope=["/workspace/project"]),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    child = derive_child_biscuit(
        parent,
        keypair.private_key,
        "spiffe://example.org/agent/child",
        child_resource_scope=[],
        now=101,
    )

    context = verify_biscuit_passport(child, keypair.public_key, now=102)
    assert context.resource_scope == []


def test_verifier_rejects_handcrafted_scope_expansion_from_empty_parent() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(resource_scope=[]),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    parent_context = verify_biscuit_passport(parent, keypair.public_key, now=101)
    block = BlockBuilder()
    for fact in (
        'jti("handcrafted-expansion")',
        f'parent_jti("{parent_context.jti}")',
        'spiffe_id("spiffe://example.org/agent/attacker")',
        "iat(101)",
        "exp(200)",
        "max_tool_calls(1)",
        "max_duration_s(99)",
        "delegation_allowed(false)",
        "max_delegation_depth(0)",
        'allowed_tool("read_file")',
        'resource_scope("/workspace/project")',
    ):
        block.add_fact(Fact(fact))
    token = Biscuit.from_bytes(parent, keypair.public_key).append(block).to_bytes()

    with pytest.raises(BiscuitVerifyError, match="resource scope expansion"):
        verify_biscuit_passport(token, keypair.public_key, now=102)


@pytest.mark.parametrize(
    ("dimension", "overrides"),
    [
        (
            "allowed_tool",
            {
                "allowed_tool": [
                    'allowed_tool("read_file")',
                    'allowed_tool("shell")',
                ]
            },
        ),
        (
            "forbidden_tool",
            {"forbidden_tool": ['forbidden_tool("harmless")']},
        ),
        (
            "resource_scope",
            {"resource_scope": ['resource_scope("/")']},
        ),
        (
            "allowed_side_effect_class",
            {
                "allowed_side_effect_class": [
                    'allowed_side_effect_class("none")',
                    'allowed_side_effect_class("state_change")',
                ]
            },
        ),
        (
            "max_tool_calls",
            {"max_tool_calls": ["max_tool_calls(6)"]},
        ),
        (
            "max_tool_calls_per_class",
            {
                "max_tool_calls_per_class": [
                    'max_tool_calls_per_class("external_send", 2)'
                ]
            },
        ),
        (
            "max_tool_calls_per_class",
            {
                "max_tool_calls_per_class": [
                    'max_tool_calls_per_class("none", 1)'
                ]
            },
        ),
        (
            "max_duration_s",
            {"max_duration_s": ["max_duration_s(301)"]},
        ),
        ("iat", {"iat": ["iat(99)"]}),
        ("exp", {"exp": ["exp(701)"]}),
        (
            "max_delegation_depth",
            {"max_delegation_depth": ["max_delegation_depth(3)"]},
        ),
        ("cwd", {"cwd": ['cwd("/")']}),
        (
            "parent_jti",
            {"parent_jti": ['parent_jti("unrelated-parent")']},
        ),
    ],
)
def test_verifier_rejects_each_handcrafted_authority_widening(
    dimension: str,
    overrides: dict[str, list[str]],
) -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    parent_context = verify_biscuit_passport(parent, keypair.public_key, now=101)
    token = _append_handcrafted_child(
        parent,
        keypair.public_key,
        expected_parent_jti=parent_context.jti,
        **overrides,
    )

    with pytest.raises(
        BiscuitVerifyError,
        match=rf"attenuation:{dimension}:",
    ):
        verify_biscuit_passport(token, keypair.public_key, now=102)


def test_verifier_accepts_handcrafted_monotonic_narrowing() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    parent_context = verify_biscuit_passport(parent, keypair.public_key, now=101)
    token = _append_handcrafted_child(
        parent,
        keypair.public_key,
        expected_parent_jti=parent_context.jti,
    )

    context = verify_biscuit_passport(token, keypair.public_key, now=102)

    assert context.allowed_tools == ["read_file", "search"]
    assert context.forbidden_tools == ["delete_file", "write_file"]
    assert context.resource_scope == ["/workspace/project/reports"]
    assert context.max_tool_calls == 4
    assert context.max_duration_s == 200
    assert context.max_delegation_depth == 2
    assert context.cwd == "/workspace/project/reports"


def test_verifier_accepts_tool_narrowing_from_unrestricted_parent() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(allowed_tools=["*"]),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    parent_context = verify_biscuit_passport(parent, keypair.public_key, now=101)
    token = _append_handcrafted_child(
        parent,
        keypair.public_key,
        expected_parent_jti=parent_context.jti,
        allowed_tool=['allowed_tool("read_file")'],
    )

    context = verify_biscuit_passport(token, keypair.public_key, now=102)

    assert context.allowed_tools == ["read_file"]


def test_verifier_accepts_side_effect_narrowing_from_unrestricted_parent() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(
            allowed_side_effect_classes=[],
            max_tool_calls_per_class={},
        ),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    parent_context = verify_biscuit_passport(parent, keypair.public_key, now=101)
    token = _append_handcrafted_child(
        parent,
        keypair.public_key,
        expected_parent_jti=parent_context.jti,
        allowed_side_effect_class=['allowed_side_effect_class("none")'],
        max_tool_calls_per_class=['max_tool_calls_per_class("none", 1)'],
    )

    context = verify_biscuit_passport(token, keypair.public_key, now=102)

    assert context.allowed_side_effect_classes == ["none"]
    assert context.max_tool_calls_per_class == {"none": 1}


def test_verifier_enforces_handcrafted_child_expiry_without_a_datalog_check() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    parent_context = verify_biscuit_passport(parent, keypair.public_key, now=100)
    token = _append_handcrafted_child(
        parent,
        keypair.public_key,
        expected_parent_jti=parent_context.jti,
        iat=["iat(100)"],
        exp=["exp(101)"],
    )

    with pytest.raises(BiscuitVerifyError, match=r"attenuation:exp:"):
        verify_biscuit_passport(token, keypair.public_key, now=102)


def test_verifier_rejects_structured_child_when_parent_disallows_delegation() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(delegation_allowed=False, max_delegation_depth=0),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    parent_context = verify_biscuit_passport(parent, keypair.public_key, now=101)
    token = _append_handcrafted_child(
        parent,
        keypair.public_key,
        expected_parent_jti=parent_context.jti,
    )

    with pytest.raises(
        BiscuitVerifyError,
        match=r"attenuation:delegation_allowed:",
    ):
        verify_biscuit_passport(token, keypair.public_key, now=102)


def test_verifier_rejects_reproduced_holder_authority_widening() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(
            allowed_tools=["read_file"],
            max_tool_calls=1,
            delegation_allowed=False,
            max_delegation_depth=0,
            cwd="/safe",
        ),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    parent_context = verify_biscuit_passport(parent, keypair.public_key, now=101)
    token = _append_handcrafted_child(
        parent,
        keypair.public_key,
        expected_parent_jti=parent_context.jti,
        allowed_tool=['allowed_tool("delete_file")'],
        forbidden_tool=['forbidden_tool("harmless")'],
        max_tool_calls=["max_tool_calls(999)"],
        delegation_allowed=["delegation_allowed(true)"],
        max_delegation_depth=["max_delegation_depth(99)"],
        cwd=['cwd("/")'],
    )

    with pytest.raises(BiscuitVerifyError, match=r"attenuation:"):
        verify_biscuit_passport(token, keypair.public_key, now=102)


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        (
            {"max_tool_calls": ["max_tool_calls(true)"]},
            "malformed:max_tool_calls",
        ),
        (
            {
                "max_tool_calls_per_class": [
                    'max_tool_calls_per_class("external_send", true)'
                ]
            },
            "malformed:max_tool_calls_per_class",
        ),
    ],
)
def test_verifier_rejects_boolean_values_for_integer_budgets(
    overrides: dict[str, list[str]],
    error: str,
) -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    parent_context = verify_biscuit_passport(parent, keypair.public_key, now=101)
    token = _append_handcrafted_child(
        parent,
        keypair.public_key,
        expected_parent_jti=parent_context.jti,
        **overrides,
    )

    with pytest.raises(BiscuitVerifyError, match=error):
        verify_biscuit_passport(token, keypair.public_key, now=102)


def test_derive_rejects_budget_expansion() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(max_tool_calls=2),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    with pytest.raises(BiscuitAttenuationError, match="tool budget expansion"):
        derive_child_biscuit(
            parent,
            keypair.private_key,
            "spiffe://example.org/agent/child",
            child_max_tool_calls=3,
            now=101,
        )


def test_derive_rejects_new_side_effect_class() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(max_tool_calls_per_class={"external_send": 1}),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    with pytest.raises(BiscuitAttenuationError, match="side-effect-class expansion"):
        derive_child_biscuit(
            parent,
            keypair.private_key,
            "spiffe://example.org/agent/child",
            child_max_tool_calls_per_class={"state_change": 1},
            now=101,
        )


def test_derive_accepts_new_budget_for_class_unbounded_in_parent() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(max_tool_calls_per_class={}),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    child = derive_child_biscuit(
        parent,
        keypair.private_key,
        "spiffe://example.org/agent/child",
        child_max_tool_calls_per_class={"external_send": 2},
        now=101,
    )

    context = verify_biscuit_passport(child, keypair.public_key, now=102)

    assert context.max_tool_calls_per_class == {"external_send": 2}


def test_derive_accepts_child_cwd_when_parent_cwd_is_none() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(cwd=None),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    child = derive_child_biscuit(
        parent,
        keypair.private_key,
        "spiffe://example.org/agent/child",
        child_cwd="/workspace/sales",
        now=101,
    )

    context = verify_biscuit_passport(child, keypair.public_key, now=102)

    assert context.cwd == "/workspace/sales"


def test_derive_rejects_child_cwd_expanding_beyond_parent() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(cwd="/workspace/project"),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    with pytest.raises(
        BiscuitAttenuationError,
        match="is not a subpath of parent cwd",
    ):
        derive_child_biscuit(
            parent,
            keypair.private_key,
            "spiffe://example.org/agent/child",
            child_cwd="/workspace/other",
            now=101,
        )


def test_derive_tracks_spiffe_id_per_block() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    child = derive_child_biscuit(
        parent,
        keypair.private_key,
        "spiffe://example.org/agent/child",
        child_allowed_tools=["read_file", "search"],
        now=101,
    )

    context = verify_biscuit_passport(child, keypair.public_key, now=102)

    assert [entry["spiffe_id"] for entry in context.delegation_chain] == [
        "spiffe://example.org/agent/root",
        "spiffe://example.org/agent/child",
    ]


def test_derive_enforces_max_delegation_depth() -> None:
    keypair = _keypair()
    root = issue_biscuit_passport(
        _mission(max_delegation_depth=1),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    child = derive_child_biscuit(
        root,
        keypair.private_key,
        "spiffe://example.org/agent/child",
        now=101,
    )

    with pytest.raises(
        BiscuitAttenuationError, match="does not allow delegation|depth exhausted"
    ):
        derive_child_biscuit(
            child,
            keypair.private_key,
            "spiffe://example.org/agent/grandchild",
            now=102,
        )


def test_derive_deeply_nested_chain_verifies() -> None:
    keypair = _keypair()
    token = issue_biscuit_passport(
        _mission(max_delegation_depth=3),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    token = derive_child_biscuit(
        token,
        keypair.private_key,
        "spiffe://example.org/agent/child-1",
        child_allowed_tools=["read_file", "search"],
        now=101,
    )
    token = derive_child_biscuit(
        token,
        keypair.private_key,
        "spiffe://example.org/agent/child-2",
        child_allowed_tools=["read_file"],
        now=102,
    )
    token = derive_child_biscuit(
        token,
        keypair.private_key,
        "spiffe://example.org/agent/child-3",
        child_allowed_tools=["read_file"],
        child_cwd="/workspace/project",
        now=103,
    )

    context = verify_biscuit_passport(token, keypair.public_key, now=104)

    assert context.delegation_depth == 3
    assert len(context.delegation_chain) == 4
    assert context.spiffe_id == "spiffe://example.org/agent/child-3"
    assert context.allowed_tools == ["read_file"]


def test_valid_a_to_b_to_c_chain_narrows_every_supported_authority() -> None:
    keypair = _keypair()
    root = issue_biscuit_passport(
        _mission(max_delegation_depth=2),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    child = derive_child_biscuit(
        root,
        keypair.private_key,
        "spiffe://example.org/agent/child",
        child_allowed_tools=["read_file", "search"],
        child_resource_scope=["/workspace/project/reports"],
        child_max_tool_calls=4,
        child_max_duration_s=200,
        child_max_tool_calls_per_class={"external_send": 1},
        child_cwd="/workspace/project/reports",
        now=101,
    )
    grandchild = derive_child_biscuit(
        child,
        keypair.private_key,
        "spiffe://example.org/agent/grandchild",
        child_allowed_tools=["read_file"],
        child_resource_scope=["/workspace/project/reports/q1"],
        child_max_tool_calls=2,
        child_max_duration_s=100,
        child_max_tool_calls_per_class={"external_send": 0},
        child_cwd="/workspace/project/reports/q1",
        now=102,
    )

    context = verify_biscuit_passport(grandchild, keypair.public_key, now=103)

    assert context.delegation_depth == 2
    assert context.allowed_tools == ["read_file"]
    assert context.resource_scope == ["/workspace/project/reports/q1"]
    assert context.max_tool_calls == 2
    assert context.max_duration_s == 100
    assert context.max_tool_calls_per_class == {"external_send": 0}
    assert context.delegation_allowed is False
    assert context.max_delegation_depth == 0
    assert context.cwd == "/workspace/project/reports/q1"


def test_verify_detects_chain_splice() -> None:
    """Tampering authority-block bytes in a 2-block biscuit must be rejected."""
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(
            mission="ROOTBLOCKMARKER-AAAA",
            max_delegation_depth=2,
        ),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    child = derive_child_biscuit(
        parent,
        keypair.private_key,
        "spiffe://example.org/agent/child",
        now=101,
    )
    tampered = _tamper_token_at_marker(child, b"ROOTBLOCKMARKER-AAAA")

    with pytest.raises(
        BiscuitValidationError,
        match="error deserializing or verifying the token",
    ):
        Biscuit.from_bytes(tampered, keypair.public_key)


def test_derive_chain_hash_prevents_block_reorder() -> None:
    """Substitution for block-swap: corrupt a middle child block byte and expect rejection."""
    keypair = _keypair()
    root = issue_biscuit_passport(
        _mission(
            mission="ROOTBLOCKMARKER-AAAA",
            max_delegation_depth=3,
        ),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    mid = derive_child_biscuit(
        root,
        keypair.private_key,
        "spiffe://example.org/agent/child-1",
        now=101,
    )
    leaf = derive_child_biscuit(
        mid,
        keypair.private_key,
        "spiffe://example.org/agent/child-2",
        now=102,
    )
    tampered = _tamper_token_at_marker(leaf, b"spiffe://example.org/agent/child-1")

    with pytest.raises(
        BiscuitValidationError,
        match="error deserializing or verifying the token",
    ):
        Biscuit.from_bytes(tampered, keypair.public_key)


def test_encode_decode_roundtrip() -> None:
    token = b"\x00\x01signed-biscuit\xff"

    encoded = encode_biscuit_b64(token)

    assert decode_biscuit_b64(encoded) == token


def test_decode_raises_on_invalid_b64() -> None:
    with pytest.raises(ValueError, match="invalid biscuit base64"):
        decode_biscuit_b64("###")


def test_passport_context_fields_match_legacy_mission_passport_fields() -> None:
    mission_fields = set(MissionPassport.__dataclass_fields__.keys())
    context_fields = {field.name for field in fields(PassportContext)}
    expected_shared = {
        "agent_id",
        "mission",
        "allowed_tools",
        "forbidden_tools",
        "resource_scope",
        "allowed_side_effect_classes",
        "max_tool_calls",
        "max_tool_calls_per_class",
        "max_duration_s",
        "delegation_allowed",
        "max_delegation_depth",
        "parent_jti",
        "cwd",
    }

    assert expected_shared.issubset(mission_fields)
    assert expected_shared.issubset(context_fields)
    assert "spiffe_id" in context_fields


def test_mission_passport_round_trips_holder_spiffe_id() -> None:
    mission = MissionPassport.from_dict(
        {
            "agent_id": "agent-001",
            "mission": "analyze quarterly data",
            "allowed_tools": ["read_file"],
            "holder_spiffe_id": "spiffe://example.org/agent/root",
        }
    )

    assert mission.holder_spiffe_id == "spiffe://example.org/agent/root"
    assert mission.to_dict()["holder_spiffe_id"] == "spiffe://example.org/agent/root"


def test_mission_passport_lineage_budgets_error_keeps_other_unknown_fields_visible() -> None:
    payload = {
        "agent_id": "agent-001",
        "mission": "coordinate child work",
        "allowed_tools": ["read_file"],
        "lineage_budgets": [{"type": "max_child_tool_calls", "limit": 3}],
        "resourc_scope": ["/data"],
    }

    with pytest.raises(ValueError) as excinfo:
        MissionPassport.from_dict(payload)

    message = str(excinfo.value)
    assert "lineage_budgets" in message
    assert "Phase 1" in message
    assert "deferred" in message
    assert "resourc_scope" in message


# --- Round-4 audit (FIX-R4-1, 2026-04-28): the round-3 hostile audit
# verified by PoC that ``verify_biscuit_passport`` accepted iat in the
# far future — the same threat model FIX-R3-A closed for JWT but
# unaddressed for the parallel Biscuit credential format. These tests
# pin the bounded-iat-skew gate added to the Biscuit verifier.

class TestBiscuitPassportIatSkewGuard:
    @staticmethod
    def _make_mission():
        return MissionPassport(
            agent_id="biscuit-agent",
            mission="iat-skew test",
            allowed_tools=["read"],
            forbidden_tools=[],
            resource_scope=[],
            max_tool_calls=5,
            max_duration_s=60,
            holder_spiffe_id="spiffe://example.org/agent/iat-skew",
        )

    def test_verify_rejects_far_future_iat(self):
        import time as _time

        kp = KeyPair()
        far_future = int(_time.time()) + 365 * 86400
        token = issue_biscuit_passport(
            self._make_mission(),
            kp.private_key,
            issuer_spiffe_id="spiffe://example.org/issuer",
            ttl_s=600,
            now=far_future,
        )
        with pytest.raises(
            BiscuitVerifyError,
            # Match either the legacy leaf-only message or the round-5
            # per-block message — both are valid fail-closed outcomes.
            match=r"biscuit passport (?:block \d+ )?iat lies more than",
        ):
            verify_biscuit_passport(token, kp.public_key)

    def test_verify_accepts_iat_within_clock_drift(self):
        import time as _time

        kp = KeyPair()
        slight_future = int(_time.time()) + 60  # within ±300s default
        token = issue_biscuit_passport(
            self._make_mission(),
            kp.private_key,
            issuer_spiffe_id="spiffe://example.org/issuer",
            ttl_s=600,
            now=slight_future,
        )
        # Should not raise.
        ctx = verify_biscuit_passport(token, kp.public_key)
        assert ctx.issued_at == slight_future

    def test_verify_rejects_multi_row_iat_with_far_future_in_one_row(self):
        """FIX-R6-8 + FIX-R7-2 (round-7, 2026-04-29) regression. R6-8
        changed the per-block walk from ``iat_facts[0][0]`` (only the
        first row) to iterating every row. Without iterating, an
        attacker could append a benign present-time iat to a block
        that already carries a far-future iat; the future iat hides
        behind the first-row-only check. This test constructs that
        exact attack — a child block with TWO iat facts, one
        legitimate, one far-future — and confirms rejection."""
        import time as _time

        from biscuit_auth import Biscuit, BlockBuilder, Fact

        kp = KeyPair()
        present_now = int(_time.time())
        # Mint a normal root (present-time iat).
        root_token_bytes = issue_biscuit_passport(
            self._make_mission(),
            kp.private_key,
            issuer_spiffe_id="spiffe://example.org/issuer",
            ttl_s=600,
            now=present_now,
        )
        # Append a child block with TWO iat facts: a benign present-
        # time iat (which the round-5 single-row check would have
        # accepted) AND a far-future iat (which round-6 must catch).
        far_future = present_now + 365 * 86400
        root_biscuit = Biscuit.from_bytes(root_token_bytes, kp.public_key)
        child_block = BlockBuilder()
        child_block.add_fact(Fact(f"iat({present_now})"))
        child_block.add_fact(Fact(f"iat({far_future})"))
        attacker_token = root_biscuit.append(child_block).to_bytes()

        with pytest.raises(
            BiscuitVerifyError,
            match=r"biscuit passport block 1 iat lies more than",
        ):
            verify_biscuit_passport(attacker_token, kp.public_key)

    def test_verify_rejects_far_future_root_with_present_child(self):
        """H5 (round-4 audit) regression: the attack is an attacker who
        briefly compromised an issuer to mint a ROOT block with
        iat=year_3000, exp=year_3001, then uses Biscuit's open-
        attenuation property (any holder can append) to add a CHILD
        block with iat=now via the low-level ``Biscuit.append`` API.
        A leaf-only iat check accepts because ``context.issued_at``
        resolves to the present-time leaf. Round-5 walks every block;
        the far-future authority block must be rejected."""
        import time as _time

        from biscuit_auth import Biscuit, BlockBuilder, Fact

        kp = KeyPair()
        far_future = int(_time.time()) + 365 * 86400
        root_token_bytes = issue_biscuit_passport(
            self._make_mission(),
            kp.private_key,
            issuer_spiffe_id="spiffe://example.org/issuer",
            ttl_s=10 * 365 * 86400,
            now=far_future,
        )
        # Parse the root and append a child block directly via Biscuit's
        # open-attenuation API — bypassing derive_child_biscuit, which
        # itself runs verify_biscuit_passport (and would correctly reject
        # the far-future root before any child gets appended).
        root_biscuit = Biscuit.from_bytes(root_token_bytes, kp.public_key)
        present_now = int(_time.time())
        child_block = BlockBuilder()
        # Add a present-time iat fact so the leaf "looks fresh".
        child_block.add_fact(Fact(f"iat({present_now})"))
        attacker_token = root_biscuit.append(child_block).to_bytes()

        with pytest.raises(
            BiscuitVerifyError,
            match=r"biscuit passport block 0 iat lies more than",
        ):
            verify_biscuit_passport(attacker_token, kp.public_key)
