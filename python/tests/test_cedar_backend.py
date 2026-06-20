"""Tests for vibap/backends/cedar.py.

Covers: Cedar evaluation, tri-state decision mapping (Allow / explicit
forbid Deny / default-deny Abstain), integrity-hash enforcement, context
coercion (floats → ints to avoid Cedar's lack of float type), error
paths, and end-to-end composition through the proxy.
"""

from __future__ import annotations

import hashlib

import pytest

from vibap.backends.cedar import (
    BACKEND_NAME,
    CedarBackend,
    CedarIntegrityError,
    _build_cedar_context,
    _verify_sha256,
)
from vibap.passport import MissionPassport, issue_passport
from vibap.policy_backend import get_backend
from vibap.proxy import Decision


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _spec(policy: str, **overrides) -> dict:
    base = {
        "backend": BACKEND_NAME,
        "label": "test",
        "policy_inline": policy,
        "policy_sha256": _sha(policy),
        "data_inline": [],
    }
    base.update(overrides)
    return base


# ─── Decision mapping ──────────────────────────────────────────────


class TestDecisionMapping:
    """Cedar Allow / explicit forbid Deny / default-deny Abstain must
    map correctly. The distinction between "explicit forbid" and
    "default-deny" is what makes composition semantics meaningful."""

    def test_allow_when_permit_policy_matches(self) -> None:
        b = CedarBackend()
        policy = 'permit(principal == User::"alice", action, resource);'
        pd = b.evaluate(
            tool_name="read_file", arguments={}, principal="alice",
            target="x", context={}, policy_spec=_spec(policy),
        )
        assert pd.decision == "Allow"
        assert any("policy" in r for r in pd.reasons)

    def test_explicit_forbid_maps_to_deny(self) -> None:
        b = CedarBackend()
        policy = '''permit(principal, action, resource);
forbid(principal == User::"evil", action, resource);'''
        pd = b.evaluate(
            tool_name="read_file", arguments={}, principal="evil",
            target="x", context={}, policy_spec=_spec(policy),
        )
        assert pd.decision == "Deny"
        assert any("policy" in r for r in pd.reasons)

    def test_default_deny_maps_to_abstain(self) -> None:
        """No policy matches → Cedar returns Deny (default-deny), but
        for composition we treat this as Abstain so the Cedar backend
        does not veto actions it has no opinion on."""
        b = CedarBackend()
        policy = 'permit(principal == User::"alice", action, resource);'
        pd = b.evaluate(
            tool_name="read_file", arguments={}, principal="bob",
            target="x", context={}, policy_spec=_spec(policy),
        )
        assert pd.decision == "Abstain"
        assert pd.reasons == ()

    def test_permit_with_context_condition(self) -> None:
        """Cedar `when` clauses on context values."""
        b = CedarBackend()
        policy = '''permit(principal, action, resource)
when { context.side_effect_class == "none" };'''
        pd = b.evaluate(
            tool_name="read_file", arguments={}, principal="alice",
            target="x", context={"side_effect_class": "none"},
            policy_spec=_spec(policy),
        )
        assert pd.decision == "Allow"

        pd2 = b.evaluate(
            tool_name="send_email", arguments={}, principal="alice",
            target="y", context={"side_effect_class": "external_send"},
            policy_spec=_spec(policy),
        )
        # when-clause evaluates to false → Cedar Deny + no matched policies → Abstain
        assert pd2.decision == "Abstain"


# ─── Integrity (SHA-256) enforcement ──────────────────────────────


class TestIntegrityEnforcement:
    def test_matching_sha256_permits_evaluation(self) -> None:
        b = CedarBackend()
        policy = "permit(principal, action, resource);"
        pd = b.evaluate(
            tool_name="x", arguments={}, principal="p",
            target="t", context={}, policy_spec=_spec(policy),
        )
        assert pd.decision == "Allow"

    def test_mismatched_sha256_denies_with_integrity_reason(self) -> None:
        b = CedarBackend()
        policy = "permit(principal, action, resource);"
        bad_spec = _spec(policy)
        bad_spec["policy_sha256"] = "0" * 64
        pd = b.evaluate(
            tool_name="x", arguments={}, principal="p",
            target="t", context={}, policy_spec=bad_spec,
        )
        assert pd.decision == "Deny"
        assert any("integrity" in r for r in pd.reasons)

    def test_missing_sha256_denies(self) -> None:
        b = CedarBackend()
        policy = "permit(principal, action, resource);"
        spec = _spec(policy)
        spec["policy_sha256"] = ""
        pd = b.evaluate(
            tool_name="x", arguments={}, principal="p",
            target="t", context={}, policy_spec=spec,
        )
        assert pd.decision == "Deny"
        assert any("integrity" in r for r in pd.reasons)

    def test_verify_sha256_raises_on_mismatch(self) -> None:
        with pytest.raises(CedarIntegrityError):
            _verify_sha256("hello", "0" * 64)

    def test_verify_sha256_accepts_match(self) -> None:
        _verify_sha256("hello", _sha("hello"))  # does not raise


# ─── Context coercion ─────────────────────────────────────────────


class TestContextCoercion:
    """Cedar's type system has no float. Python floats must be coerced
    to ints or Cedar returns NoDecision (context parse error)."""

    def test_bool_int_str_pass_through(self) -> None:
        ctx = _build_cedar_context(
            {"is_admin": True, "count": 3, "label": "x"}, arguments={},
        )
        assert ctx == {"is_admin": True, "count": 3, "label": "x"}

    def test_float_elapsed_s_becomes_elapsed_ms_int(self) -> None:
        ctx = _build_cedar_context({"elapsed_s": 0.250}, arguments={})
        assert "elapsed_s" not in ctx
        assert ctx["elapsed_ms"] == 250

    def test_other_float_rounds_to_int(self) -> None:
        ctx = _build_cedar_context({"score": 0.7}, arguments={})
        assert ctx["score"] == 1

    def test_unknown_type_becomes_string(self) -> None:
        class X:
            def __str__(self):
                return "xobj"
        ctx = _build_cedar_context({"x": X()}, arguments={})
        assert ctx["x"] == "xobj"

    def test_arguments_produce_preview_fields(self) -> None:
        ctx = _build_cedar_context({}, arguments={"a": 1, "b": [1, 2]})
        assert ctx["argument_count"] == 2
        assert "argument_preview" in ctx
        assert len(ctx["argument_preview"]) <= 256

    def test_empty_arguments_emit_no_preview(self) -> None:
        ctx = _build_cedar_context({}, arguments={})
        assert "argument_count" not in ctx


# ─── Registry integration ────────────────────────────────────────


class TestRegistry:
    def test_cedar_backend_registered_on_import(self) -> None:
        b = get_backend(BACKEND_NAME)
        assert b.name == BACKEND_NAME

    def test_registered_backend_evaluates_end_to_end(self) -> None:
        b = get_backend(BACKEND_NAME)
        policy = 'permit(principal == User::"alice", action, resource);'
        pd = b.evaluate(
            tool_name="read_file", arguments={}, principal="alice",
            target="x", context={}, policy_spec=_spec(policy),
        )
        assert pd.decision == "Allow"


# ─── Data (entities) ─────────────────────────────────────────────


class TestDataInline:
    def test_data_inline_list_of_entities_accepted(self) -> None:
        b = CedarBackend()
        policy = 'permit(principal == User::"alice", action, resource);'
        entities = [
            {"uid": {"type": "User", "id": "alice"}, "attrs": {}, "parents": []},
        ]
        spec = _spec(policy, data_inline=entities)
        pd = b.evaluate(
            tool_name="x", arguments={}, principal="alice",
            target="t", context={}, policy_spec=spec,
        )
        assert pd.decision == "Allow"

    def test_data_inline_wrong_type_denies(self) -> None:
        b = CedarBackend()
        policy = "permit(principal, action, resource);"
        spec = _spec(policy, data_inline={"not": "a list"})  # dict, not list/str
        pd = b.evaluate(
            tool_name="x", arguments={}, principal="p",
            target="t", context={}, policy_spec=spec,
        )
        assert pd.decision == "Deny"
        assert any("data_inline" in r for r in pd.reasons)


# ─── Malformed policy — catastrophic error path ──────────────────


class TestMalformedPolicy:
    def test_invalid_cedar_policy_denies_with_error_reason(self) -> None:
        b = CedarBackend()
        bad_policy = "this is not valid cedar syntax ::: {{{"
        pd = b.evaluate(
            tool_name="x", arguments={}, principal="p",
            target="t", context={}, policy_spec=_spec(bad_policy),
        )
        assert pd.decision == "Deny"
        assert any("cedar evaluation error" in r for r in pd.reasons)


# ─── End-to-end through proxy ────────────────────────────────────


class TestProxyEndToEnd:
    def test_cedar_compose_with_permit_allows_tool_call(
        self, proxy, private_key,
    ):
        policy = 'permit(principal, action, resource);'
        mission = MissionPassport(
            agent_id="cedar-e2e-1", mission="do work",
            allowed_tools=["read_file"], resource_scope=[],
            max_tool_calls=10,
            additional_policies=[_spec(policy, label="security_team")],
        )
        token = issue_passport(mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        decision, _, event = session.check_and_record(
            "read_file", {"path": "x"},
        )
        assert decision == Decision.PERMIT
        # Receipt has native + cedar
        backends = [pd["backend"] for pd in event.policy_decisions]
        assert "native_claims" in backends
        assert BACKEND_NAME in backends

    def test_cedar_explicit_forbid_denies_tool_call(
        self, proxy, private_key,
    ):
        policy = '''permit(principal, action, resource);
forbid(principal, action == Action::"send_email", resource);'''
        mission = MissionPassport(
            agent_id="cedar-e2e-2", mission="send report",
            allowed_tools=["send_email"], resource_scope=[],
            max_tool_calls=10,
            additional_policies=[_spec(policy, label="security_team")],
        )
        token = issue_passport(mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        decision, reason, event = session.check_and_record(
            "send_email", {"to": "x", "subject": "y", "body": "z"},
        )
        assert decision == Decision.DENY
        assert "security_team" in reason

    def test_cedar_integrity_mismatch_denies_at_proxy(
        self, proxy, private_key,
    ):
        policy = "permit(principal, action, resource);"
        spec = _spec(policy)
        spec["policy_sha256"] = "0" * 64  # wrong hash
        mission = MissionPassport(
            agent_id="cedar-e2e-3", mission="x",
            allowed_tools=["read_file"], resource_scope=[],
            max_tool_calls=10, additional_policies=[spec],
        )
        token = issue_passport(mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        decision, reason, _ = session.check_and_record(
            "read_file", {"path": "x"},
        )
        assert decision == Decision.DENY
        assert "integrity" in reason or "cedar" in reason
