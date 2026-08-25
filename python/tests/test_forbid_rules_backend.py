"""Tests for vibap/backends/forbid_rules.py.

The compliance-layer backend: pattern-based forbid rules with
integrity checking, short-circuit on first match, and Abstain when
no rule matches (default — compliance team has no opinion).
"""

from __future__ import annotations

import hashlib

import pytest

from vibap.backends.forbid_rules import (
    BACKEND_NAME,
    ForbidRulesBackend,
    ForbidRulesIntegrityError,
    _canonical_source,
    _rule_matches,
    _verify_sha256,
)
from vibap.passport import MissionPassport, issue_passport
from vibap.policy_backend import get_backend
from vibap.proxy import Decision


def _spec_for_rules(rules: list[dict], **overrides) -> dict:
    base = {
        "backend": BACKEND_NAME,
        "label": "compliance",
        "policy_inline": "",
        "policy_sha256": hashlib.sha256(
            _canonical_source(rules).encode("utf-8"),
        ).hexdigest(),
        "data_inline": rules,
    }
    base.update(overrides)
    return base


# ─── Canonical source + integrity ──────────────────────────────────


class TestCanonicalSource:
    def test_key_order_invariant(self) -> None:
        a = [{"id": "r", "forbid_when": {"tool_name": "x"}}]
        b = [{"forbid_when": {"tool_name": "x"}, "id": "r"}]
        assert _canonical_source(a) == _canonical_source(b)

    def test_compact_separators(self) -> None:
        rules = [{"id": "r", "forbid_when": {"tool_name": "x"}}]
        s = _canonical_source(rules)
        assert " " not in s
        assert s.startswith("[{")


class TestIntegrityEnforcement:
    def test_matching_sha256_passes(self) -> None:
        rules = [{"id": "r", "forbid_when": {"tool_name": "x"}}]
        _verify_sha256(
            rules,
            hashlib.sha256(_canonical_source(rules).encode()).hexdigest(),
        )

    def test_mismatched_sha256_raises(self) -> None:
        rules = [{"id": "r", "forbid_when": {"tool_name": "x"}}]
        with pytest.raises(ForbidRulesIntegrityError):
            _verify_sha256(rules, "0" * 64)

    def test_missing_sha256_raises(self) -> None:
        with pytest.raises(ForbidRulesIntegrityError):
            _verify_sha256([], "")


# ─── Predicate evaluation ─────────────────────────────────────────


class TestPredicates:
    def test_tool_name_exact_match(self) -> None:
        rule = {"id": "r", "forbid_when": {"tool_name": "delete_file"}}
        ok, _ = _rule_matches(
            rule, tool_name="delete_file", arguments={}, principal="p",
            target="t", context={},
        )
        assert ok

    def test_tool_name_exact_mismatch(self) -> None:
        rule = {"id": "r", "forbid_when": {"tool_name": "delete_file"}}
        ok, _ = _rule_matches(
            rule, tool_name="read_file", arguments={}, principal="p",
            target="t", context={},
        )
        assert not ok

    def test_tool_name_in_list(self) -> None:
        rule = {"id": "r", "forbid_when": {"tool_name_in": ["a", "b"]}}
        ok, _ = _rule_matches(
            rule, tool_name="b", arguments={}, principal="p",
            target="t", context={},
        )
        assert ok
        ok, _ = _rule_matches(
            rule, tool_name="c", arguments={}, principal="p",
            target="t", context={},
        )
        assert not ok

    def test_arg_contains_substring(self) -> None:
        rule = {"id": "r", "forbid_when": {"arg_contains": ["password", "ssn"]}}
        ok, reason = _rule_matches(
            rule, tool_name="x", arguments={"query": "user PASSWORD"},
            principal="p", target="t", context={},
        )
        assert ok
        assert "password" in reason

    def test_arg_contains_miss(self) -> None:
        rule = {"id": "r", "forbid_when": {"arg_contains": ["password"]}}
        ok, _ = _rule_matches(
            rule, tool_name="x", arguments={"query": "benign"},
            principal="p", target="t", context={},
        )
        assert not ok

    def test_target_matches_regex(self) -> None:
        rule = {"id": "r", "forbid_when": {"target_matches": r"^/hr/.*"}}
        ok, _ = _rule_matches(
            rule, tool_name="read", arguments={},
            principal="p", target="/hr/salary.csv", context={},
        )
        assert ok

    def test_target_matches_miss(self) -> None:
        rule = {"id": "r", "forbid_when": {"target_matches": r"^/hr/.*"}}
        ok, _ = _rule_matches(
            rule, tool_name="read", arguments={},
            principal="p", target="/sales/q1.csv", context={},
        )
        assert not ok

    def test_invalid_regex_fails_closed_matches(self) -> None:
        """Malformed regex is a broken compliance rule. Safer to match
        (over-deny) than to skip silently."""
        rule = {"id": "r", "forbid_when": {"target_matches": "[invalid("}}
        ok, reason = _rule_matches(
            rule, tool_name="r", arguments={},
            principal="p", target="any", context={},
        )
        assert ok
        assert "invalid regex" in reason

    def test_principal_exact(self) -> None:
        rule = {"id": "r", "forbid_when": {"principal": "evil"}}
        ok, _ = _rule_matches(
            rule, tool_name="r", arguments={},
            principal="evil", target="t", context={},
        )
        assert ok

    def test_action_class_from_context(self) -> None:
        rule = {"id": "r", "forbid_when": {"action_class": "send"}}
        ok, _ = _rule_matches(
            rule, tool_name="send_email", arguments={},
            principal="p", target="t", context={"action_class": "send"},
        )
        assert ok

    def test_multiple_predicates_all_must_pass_for_match(self) -> None:
        rule = {
            "id": "both",
            "forbid_when": {
                "tool_name": "send_email",
                "arg_contains": ["confidential"],
            },
        }
        ok, _ = _rule_matches(
            rule, tool_name="send_email", arguments={"body": "confidential data"},
            principal="p", target="t", context={},
        )
        assert ok
        # Tool matches but arg doesn't
        ok2, _ = _rule_matches(
            rule, tool_name="send_email", arguments={"body": "benign"},
            principal="p", target="t", context={},
        )
        assert not ok2

    def test_empty_forbid_when_never_matches(self) -> None:
        rule = {"id": "r", "forbid_when": {}}
        ok, _ = _rule_matches(
            rule, tool_name="x", arguments={},
            principal="p", target="t", context={},
        )
        assert not ok


# ─── Backend end-to-end ────────────────────────────────────────────


class TestBackendEvaluation:
    def test_no_rule_match_abstains(self) -> None:
        b = ForbidRulesBackend()
        rules = [{"id": "no_creds", "forbid_when": {"arg_contains": ["password"]}}]
        pd = b.evaluate(
            tool_name="read_file", arguments={"path": "q1.csv"},
            principal="alice", target="q1.csv", context={},
            policy_spec=_spec_for_rules(rules),
        )
        assert pd.decision == "Abstain"

    def test_rule_match_denies(self) -> None:
        b = ForbidRulesBackend()
        rules = [{"id": "no_creds", "forbid_when": {"arg_contains": ["password"]}}]
        pd = b.evaluate(
            tool_name="read_file", arguments={"q": "user password"},
            principal="alice", target="x", context={},
            policy_spec=_spec_for_rules(rules),
        )
        assert pd.decision == "Deny"
        assert "no_creds" in pd.reasons[0]

    def test_short_circuit_on_first_match(self) -> None:
        b = ForbidRulesBackend()
        rules = [
            {"id": "first", "forbid_when": {"tool_name": "delete_file"}},
            {"id": "second", "forbid_when": {"tool_name": "delete_file"}},
        ]
        pd = b.evaluate(
            tool_name="delete_file", arguments={}, principal="a",
            target="t", context={}, policy_spec=_spec_for_rules(rules),
        )
        assert pd.decision == "Deny"
        assert len(pd.reasons) == 1
        assert "first" in pd.reasons[0]

    def test_data_inline_wrong_type_denies(self) -> None:
        b = ForbidRulesBackend()
        spec = {
            "backend": BACKEND_NAME, "label": "x",
            "policy_inline": "", "policy_sha256": "x" * 64,
            "data_inline": "not a list",
        }
        pd = b.evaluate(
            tool_name="x", arguments={}, principal="p",
            target="t", context={}, policy_spec=spec,
        )
        assert pd.decision == "Deny"
        assert "data_inline" in pd.reasons[0]

    def test_integrity_mismatch_denies(self) -> None:
        b = ForbidRulesBackend()
        rules = [{"id": "r", "forbid_when": {"tool_name": "x"}}]
        spec = _spec_for_rules(rules)
        spec["policy_sha256"] = "0" * 64
        pd = b.evaluate(
            tool_name="x", arguments={}, principal="p",
            target="t", context={}, policy_spec=spec,
        )
        assert pd.decision == "Deny"
        assert "integrity" in pd.reasons[0]


# ─── Registry ─────────────────────────────────────────────────────


class TestRegistry:
    def test_registered_on_import(self) -> None:
        b = get_backend(BACKEND_NAME)
        assert b.name == BACKEND_NAME


# ─── Proxy end-to-end ─────────────────────────────────────────────


class TestProxyEndToEnd:
    def test_compose_with_forbid_rules_denies_on_match(
        self, proxy, private_key,
    ):
        rules = [
            {"id": "no_send_confidential",
             "forbid_when": {
                 "tool_name": "send_email",
                 "arg_contains": ["confidential"],
             }},
        ]
        mission = MissionPassport(
            agent_id="fr-e2e-1", mission="send report",
            allowed_tools=["send_email"], resource_scope=["**"],
            max_tool_calls=10,
            additional_policies=[_spec_for_rules(rules)],
        )
        token = issue_passport(mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        decision, reason, event = session.check_and_record(
            "send_email",
            {"to": "x", "subject": "y", "body": "confidential data"},
        )
        assert decision == Decision.DENY
        assert "compliance" in reason
        assert any(
            pd["backend"] == BACKEND_NAME and pd["decision"] == "Deny"
            for pd in event.policy_decisions
        )

    def test_compose_with_forbid_rules_permits_when_no_match(
        self, proxy, private_key,
    ):
        rules = [
            {"id": "no_deletion", "forbid_when": {"tool_name": "delete_file"}},
        ]
        mission = MissionPassport(
            agent_id="fr-e2e-2", mission="read",
            allowed_tools=["read_file"], resource_scope=["**"],
            max_tool_calls=10,
            additional_policies=[_spec_for_rules(rules)],
        )
        token = issue_passport(mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        decision, _, event = session.check_and_record(
            "read_file", {"path": "x"},
        )
        assert decision == Decision.PERMIT
        # Receipt shows compliance abstained
        frb = next(
            (pd for pd in event.policy_decisions if pd["backend"] == BACKEND_NAME),
            None,
        )
        assert frb is not None
        assert frb["decision"] == "Abstain"


# ─── Triple-backend composition (native + Cedar + forbid_rules) ────


class TestTripleCompositionIntegration:
    """Triple-backend composition tests. These exercise the end-to-end
    path where a MissionPassport's ``additional_policies`` references
    both Cedar and forbid_rules specs, and the proxy must look up both
    backends by name from the global registry at session-start time.

    The Cedar backend is not auto-registered on module import (unlike
    native + forbid_rules), so this suite registers it via autouse
    fixture. Without the fixture, every cedar-labelled policy spec
    resolves to 'unknown policy backend' and yields a spurious Deny."""

    @pytest.fixture(autouse=True)
    def _register_cedar_backend(self):
        """Register CedarBackend for the duration of these tests. The
        global registry is mutable process state, so we clean up after
        ourselves to avoid leaking registration into later tests that
        might expect a non-Cedar-aware proxy.

        cedarpy is an optional dep (the AWS Cedar Python binding is a
        ~11 MB compiled wheel). When it's not installed the triple-
        composition path is genuinely unavailable, so the right answer
        is to skip — not silently 'pass' by degrading to a 2-backend
        composition that no longer exercises the claim under test."""
        try:
            from vibap.backends.cedar import CedarBackend
        except ImportError as exc:
            pytest.skip(
                f"cedarpy not installed; triple-composition path "
                f"cannot be exercised ({exc})"
            )

        from vibap.policy_backend import (
            get_backend,
            register_backend,
            _REGISTRY,
        )
        try:
            get_backend("cedar")
            already_registered = True
        except Exception:
            already_registered = False

        if not already_registered:
            register_backend(CedarBackend())

        try:
            yield
        finally:
            if not already_registered:
                _REGISTRY.pop("cedar", None)

    def test_native_permits_cedar_permits_forbid_rules_abstains_yields_permit(
        self, proxy, private_key,
    ):
        # Cedar policy: permit all
        cedar_pol = "permit(principal, action, resource);"
        cedar_spec = {
            "backend": "cedar", "label": "security",
            "policy_inline": cedar_pol,
            "policy_sha256": hashlib.sha256(cedar_pol.encode()).hexdigest(),
        }
        # Forbid rules: deny credentials
        rules = [{"id": "no_creds", "forbid_when": {"arg_contains": ["password"]}}]
        forbid_spec = _spec_for_rules(rules)

        mission = MissionPassport(
            agent_id="triple-1", mission="do work",
            allowed_tools=["read_file"], resource_scope=["**"],
            max_tool_calls=10,
            additional_policies=[cedar_spec, forbid_spec],
        )
        token = issue_passport(mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        decision, _, event = session.check_and_record(
            "read_file", {"path": "q1.csv"},
        )
        assert decision == Decision.PERMIT
        # Receipt includes all 3 layers
        backends = [pd["backend"] for pd in event.policy_decisions]
        assert "native_claims" in backends
        assert "cedar" in backends
        assert BACKEND_NAME in backends

    def test_native_permits_cedar_permits_forbid_rules_denies_yields_deny(
        self, proxy, private_key,
    ):
        cedar_pol = "permit(principal, action, resource);"
        cedar_spec = {
            "backend": "cedar", "label": "security",
            "policy_inline": cedar_pol,
            "policy_sha256": hashlib.sha256(cedar_pol.encode()).hexdigest(),
        }
        rules = [{"id": "no_creds", "forbid_when": {"arg_contains": ["password"]}}]
        forbid_spec = _spec_for_rules(rules)

        mission = MissionPassport(
            agent_id="triple-2", mission="do work",
            allowed_tools=["read_file"], resource_scope=["**"],
            max_tool_calls=10,
            additional_policies=[cedar_spec, forbid_spec],
        )
        token = issue_passport(mission, private_key, ttl_s=60)
        session = proxy.start_session(token)
        decision, reason, event = session.check_and_record(
            "read_file", {"query": "find my password"},
        )
        assert decision == Decision.DENY
        assert "compliance" in reason or "no_creds" in reason
