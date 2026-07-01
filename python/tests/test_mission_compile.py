from __future__ import annotations

import pytest
from biscuit_auth import Check, Fact

from vibap.mission_compile import (
    MissionCompileError,
    MissionPolicyNotImplementedError,
    SubpathPolicy,
    UrlAllowlistPolicy,
    compile_mission,
    load_resource_policy,
    lower_effect_policies,
    lower_flow_policies,
    lower_lineage_budgets,
    lower_resource_policies,
)

_ALL_CLASSES_BUDGET = {
    "per_effect_class": {
        "read": {"reserved": 0, "ceiling": 100},
        "write": {"reserved": 0, "ceiling": 50},
        "network": {"reserved": 0, "ceiling": 200},
        "exec": {"reserved": 0, "ceiling": 10},
        "external_send": {"reserved": 0, "ceiling": 5},
    }
}


def test_subpath_requires_absolute_root() -> None:
    with pytest.raises(MissionCompileError):
        SubpathPolicy.from_dict({"root": "data"})


def test_url_allowlist_requires_nonempty_domains() -> None:
    with pytest.raises(MissionCompileError):
        UrlAllowlistPolicy.from_dict({"allow_domains": []})


def test_load_rejects_unknown_type() -> None:
    with pytest.raises(MissionCompileError):
        load_resource_policy({"type": "made_up", "root": "/data"})


def test_lower_subpath_emits_two_facts_and_one_check() -> None:
    """Each SubpathPolicy emits (root, prefix) fact pair + ONE shared check
    (the check covers all SubpathPolicies via OR-joined fact matching)."""
    facts, checks = lower_resource_policies(
        [{"type": "subpath", "root": "/data/reports"}]
    )
    assert len(facts) == 2  # resource_subpath_root + resource_subpath_prefix
    assert all(isinstance(f, Fact) for f in facts)
    assert len(checks) == 1
    assert all(isinstance(c, Check) for c in checks)
    rendered = str(checks[0])
    assert "resource_subpath_root($r)" in rendered
    assert "resource_subpath_prefix($p)" in rendered
    assert "$r.starts_with($p)" in rendered
    assert '!$r.contains("/..")' in rendered


def test_subpath_boundary_prefix_fact_uses_slash_delimiter() -> None:
    """Regression: the emitted prefix fact must include a trailing ``/`` so
    ``/data`` matches ``/data`` and ``/data/x`` but NOT ``/dataplane``."""
    facts, _ = lower_resource_policies([{"type": "subpath", "root": "/data"}])
    rendered_facts = [str(f) for f in facts]
    assert any('resource_subpath_root("/data")' in r for r in rendered_facts)
    assert any('resource_subpath_prefix("/data/")' in r for r in rendered_facts)


def test_lower_url_allowlist_emits_one_fact_per_domain_and_one_check() -> None:
    facts, checks = lower_resource_policies(
        [{"type": "url_allowlist", "allow_domains": ["api.example.com", "docs.example.com"]}]
    )
    assert len(facts) == 2
    assert len(checks) == 1


def test_lower_mixed_policies_concatenates() -> None:
    facts, checks = lower_resource_policies(
        [
            {"type": "subpath", "root": "/data"},
            {"type": "url_allowlist", "allow_domains": ["api.example.com"]},
        ]
    )
    assert len(facts) == 3
    assert len(checks) == 2


def test_lower_empty_returns_empty() -> None:
    facts, checks = lower_resource_policies([])
    assert facts == []
    assert checks == []


def test_subpath_with_parser_hostile_chars_still_binds_via_parameters() -> None:
    """Verifies we go through parameter binding (not f-string) -- a root
    containing quotes or backslashes must not crash the Biscuit parser."""
    facts, checks = lower_resource_policies(
        [{"type": "subpath", "root": '/data/with "quote" and \\ backslash'}]
    )
    assert len(facts) == 2
    assert len(checks) == 1


def test_multiple_subpath_policies_emit_single_combined_check() -> None:
    """2026-04-21 audit fix #10: two SubpathPolicy entries with different
    roots previously emitted TWO separate Biscuit checks; Biscuit ANDs
    checks, so a resource couldn't be under both roots simultaneously
    and the authorizer rejected every call. The compiler now emits ONE
    check that matches if the resource is under ANY declared root."""
    facts, checks = lower_resource_policies(
        [
            {"type": "subpath", "root": "/data/reports"},
            {"type": "subpath", "root": "/logs"},
        ]
    )
    assert len(facts) == 4
    rendered_facts = [str(f) for f in facts]
    assert any('resource_subpath_root("/data/reports")' in r for r in rendered_facts)
    assert any('resource_subpath_root("/logs")' in r for r in rendered_facts)
    assert len(checks) == 1


def test_subpath_rejects_dot_dot_segment_in_root() -> None:
    """2026-04-21 audit fix #11."""
    for bad_root in ("/data/..", "/safe/../secret", "/../etc", "/..", "/a/../b"):
        with pytest.raises(MissionCompileError, match=r"'\.\.'"):
            SubpathPolicy.from_dict({"root": bad_root})
    ok = SubpathPolicy.from_dict({"root": "/data/v..recent"})
    assert ok.root == "/data/v..recent"


def test_subpath_check_has_anti_traversal_guard_in_rendered_source() -> None:
    """Defense-in-depth."""
    _, checks = lower_resource_policies([{"type": "subpath", "root": "/safe"}])
    rendered = str(checks[0])
    assert '!$r.contains("/..")' in rendered


class TestEffectPolicies:
    def test_empty_returns_empty(self) -> None:
        facts, checks = lower_effect_policies([])
        assert facts == []
        assert checks == []

    def test_emits_one_fact_per_entry(self) -> None:
        policies = [
            {"side_effect_class": "read", "limit": 100},
            {"side_effect_class": "write", "limit": 50},
        ]
        facts, checks = lower_effect_policies(policies)
        assert len(facts) == 2
        assert all(isinstance(f, Fact) for f in facts)

    def test_emits_single_check(self) -> None:
        policies = [
            {"side_effect_class": "read", "limit": 100},
            {"side_effect_class": "write", "limit": 50},
        ]
        _, checks = lower_effect_policies(policies)
        assert len(checks) == 1
        assert isinstance(checks[0], Check)

    def test_check_references_budget_delta_and_effect_limit(self) -> None:
        _, checks = lower_effect_policies([{"side_effect_class": "exec", "limit": 5}])
        rendered = str(checks[0])
        assert "budget_delta" in rendered
        assert "effect_limit" in rendered
        assert "$delta <= $limit" in rendered

    def test_fact_encodes_class_and_limit(self) -> None:
        facts, _ = lower_effect_policies([{"side_effect_class": "network", "limit": 200}])
        rendered = str(facts[0])
        assert '"network"' in rendered
        assert "200" in rendered

    def test_zero_limit_is_valid(self) -> None:
        facts, checks = lower_effect_policies([{"side_effect_class": "exec", "limit": 0}])
        assert len(facts) == 1
        assert len(checks) == 1
        rendered = str(facts[0])
        assert '"exec"' in rendered
        assert ", 0)" in rendered

    def test_rejects_unknown_side_effect_class(self) -> None:
        with pytest.raises(MissionCompileError, match="side_effect_class"):
            lower_effect_policies([{"side_effect_class": "bogus", "limit": 10}])

    def test_rejects_negative_limit(self) -> None:
        with pytest.raises(MissionCompileError, match="non-negative"):
            lower_effect_policies([{"side_effect_class": "read", "limit": -1}])

    def test_rejects_duplicate_class(self) -> None:
        with pytest.raises(MissionCompileError, match="duplicate"):
            lower_effect_policies([
                {"side_effect_class": "read", "limit": 10},
                {"side_effect_class": "read", "limit": 20},
            ])

    def test_all_five_classes_accepted(self) -> None:
        policies = [
            {"side_effect_class": cls, "limit": i * 10}
            for i, cls in enumerate(
                ["read", "write", "network", "exec", "external_send"]
            )
        ]
        facts, checks = lower_effect_policies(policies)
        assert len(facts) == 5
        assert len(checks) == 1

    def test_parameter_binding_not_fstring(self) -> None:
        """Fact must use parameter binding so special chars do not crash the parser."""
        facts, _ = lower_effect_policies([{"side_effect_class": "write", "limit": 99}])
        assert len(facts) == 1

    def test_error_class_hierarchy(self) -> None:
        assert issubclass(MissionPolicyNotImplementedError, NotImplementedError)


class TestFlowPolicies:
    def test_empty_returns_empty(self) -> None:
        facts, checks = lower_flow_policies([])
        assert facts == []
        assert checks == []

    def test_allow_rule_emits_flow_allow_fact(self) -> None:
        facts, _ = lower_flow_policies([
            {"from_class": "pii", "to_class": "analytics", "action": "allow"}
        ])
        assert len(facts) == 1
        rendered = str(facts[0])
        assert '"pii"' in rendered
        assert '"analytics"' in rendered

    def test_allow_rule_emits_single_check(self) -> None:
        _, checks = lower_flow_policies([
            {"from_class": "pii", "to_class": "analytics", "action": "allow"}
        ])
        assert len(checks) == 1
        rendered = str(checks[0])
        assert "information_flow" in rendered
        assert "flow_allow" in rendered

    def test_deny_only_emits_no_flow_allow_fact_but_emits_check(self) -> None:
        """A deny-only rule produces no flow_allow facts; the check blocks all
        flows by having no matching allow entries."""
        facts, checks = lower_flow_policies([
            {"from_class": "pii", "to_class": "external", "action": "deny"}
        ])
        rendered_facts = [str(f) for f in facts]
        assert not any("flow_allow" in r for r in rendered_facts)
        assert len(checks) == 1

    def test_deny_beats_allow_on_same_pair(self) -> None:
        """When both allow and deny exist for the same (from, to), deny wins:
        the pair is absent from the emitted flow_allow facts."""
        facts, checks = lower_flow_policies([
            {"from_class": "pii", "to_class": "analytics", "action": "allow"},
            {"from_class": "pii", "to_class": "analytics", "action": "deny"},
        ])
        rendered_facts = [str(f) for f in facts]
        assert not any("flow_allow" in r for r in rendered_facts)
        assert len(checks) == 1

    def test_allow_survives_when_no_conflicting_deny(self) -> None:
        facts, _ = lower_flow_policies([
            {"from_class": "internal", "to_class": "analytics", "action": "allow"},
            {"from_class": "pii", "to_class": "external", "action": "deny"},
        ])
        rendered_facts = [str(f) for f in facts]
        assert any("flow_allow" in r and '"internal"' in r for r in rendered_facts)
        assert not any('"pii"' in r for r in rendered_facts)

    def test_multiple_allow_rules_emit_one_fact_each(self) -> None:
        facts, checks = lower_flow_policies([
            {"from_class": "A", "to_class": "B", "action": "allow"},
            {"from_class": "C", "to_class": "D", "action": "allow"},
        ])
        assert len(facts) == 2
        assert len(checks) == 1

    def test_rejects_empty_from_class(self) -> None:
        with pytest.raises(MissionCompileError, match="from_class"):
            lower_flow_policies([{"from_class": "", "to_class": "B", "action": "allow"}])

    def test_rejects_empty_to_class(self) -> None:
        with pytest.raises(MissionCompileError, match="to_class"):
            lower_flow_policies([{"from_class": "A", "to_class": "", "action": "allow"}])

    def test_rejects_invalid_action(self) -> None:
        with pytest.raises(MissionCompileError, match="action"):
            lower_flow_policies([
                {"from_class": "A", "to_class": "B", "action": "permit"}
            ])

    def test_parameter_binding_not_fstring(self) -> None:
        """from_class/to_class with special chars must not crash the parser."""
        facts, _ = lower_flow_policies([
            {"from_class": 'cls "with" quotes', "to_class": "sink", "action": "allow"}
        ])
        assert len(facts) == 1


class TestLineageBudgets:
    def test_empty_dict_returns_empty(self) -> None:
        facts, checks = lower_lineage_budgets({})
        assert facts == []
        assert checks == []

    def test_none_via_compile_mission_returns_empty(self) -> None:
        facts, checks = compile_mission()
        assert facts == []
        assert checks == []

    def test_emits_one_fact_per_class(self) -> None:
        facts, _ = lower_lineage_budgets(_ALL_CLASSES_BUDGET)
        assert len(facts) == 5
        assert all(isinstance(f, Fact) for f in facts)

    def test_emits_single_check(self) -> None:
        _, checks = lower_lineage_budgets(_ALL_CLASSES_BUDGET)
        assert len(checks) == 1
        assert isinstance(checks[0], Check)

    def test_check_references_budget_spent_and_lineage_ceiling(self) -> None:
        _, checks = lower_lineage_budgets(_ALL_CLASSES_BUDGET)
        rendered = str(checks[0])
        assert "budget_spent" in rendered
        assert "lineage_ceiling" in rendered
        assert "$total <= $ceiling" in rendered

    def test_fact_encodes_class_and_ceiling(self) -> None:
        budget = {
            "per_effect_class": {
                "read": {"reserved": 0, "ceiling": 999},
                "write": {"reserved": 0, "ceiling": 50},
                "network": {"reserved": 0, "ceiling": 200},
                "exec": {"reserved": 0, "ceiling": 10},
                "external_send": {"reserved": 0, "ceiling": 5},
            }
        }
        facts, _ = lower_lineage_budgets(budget)
        rendered = [str(f) for f in facts]
        assert any('"read"' in r and "999" in r for r in rendered)

    def test_rejects_reserved_exceeds_ceiling(self) -> None:
        budget = {
            "per_effect_class": {
                "read": {"reserved": 200, "ceiling": 100},
                "write": {"reserved": 0, "ceiling": 50},
                "network": {"reserved": 0, "ceiling": 200},
                "exec": {"reserved": 0, "ceiling": 10},
                "external_send": {"reserved": 0, "ceiling": 5},
            }
        }
        with pytest.raises(MissionCompileError, match="reserved.*ceiling"):
            lower_lineage_budgets(budget)

    def test_reserved_equals_ceiling_is_valid(self) -> None:
        budget = {
            "per_effect_class": {
                "read": {"reserved": 100, "ceiling": 100},
                "write": {"reserved": 50, "ceiling": 50},
                "network": {"reserved": 200, "ceiling": 200},
                "exec": {"reserved": 10, "ceiling": 10},
                "external_send": {"reserved": 5, "ceiling": 5},
            }
        }
        facts, checks = lower_lineage_budgets(budget)
        assert len(facts) == 5
        assert len(checks) == 1

    def test_rejects_missing_per_effect_class(self) -> None:
        with pytest.raises(MissionCompileError, match="per_effect_class"):
            lower_lineage_budgets({"something_else": {}})

    def test_rejects_missing_class_key(self) -> None:
        incomplete = {
            "per_effect_class": {
                "read": {"reserved": 0, "ceiling": 100},
            }
        }
        with pytest.raises(MissionCompileError, match="missing classes"):
            lower_lineage_budgets(incomplete)

    def test_rejects_negative_ceiling(self) -> None:
        budget = {
            "per_effect_class": {
                "read": {"reserved": 0, "ceiling": -1},
                "write": {"reserved": 0, "ceiling": 50},
                "network": {"reserved": 0, "ceiling": 200},
                "exec": {"reserved": 0, "ceiling": 10},
                "external_send": {"reserved": 0, "ceiling": 5},
            }
        }
        with pytest.raises(MissionCompileError, match="non-negative"):
            lower_lineage_budgets(budget)

    def test_ceiling_only_encoded_not_reserved(self) -> None:
        """The ceiling is encoded in the Biscuit fact; reserved is
        validated at compile time but not emitted (it is not a runtime limit)."""
        budget = {
            "per_effect_class": {
                "read": {"reserved": 30, "ceiling": 100},
                "write": {"reserved": 0, "ceiling": 50},
                "network": {"reserved": 0, "ceiling": 200},
                "exec": {"reserved": 0, "ceiling": 10},
                "external_send": {"reserved": 0, "ceiling": 5},
            }
        }
        facts, _ = lower_lineage_budgets(budget)
        rendered = [str(f) for f in facts]
        read_fact = next(r for r in rendered if '"read"' in r)
        assert "100" in read_fact
        assert "30" not in read_fact


class TestCompileMissionAggregator:
    def test_resource_only_compiles_ok(self) -> None:
        facts, checks = compile_mission(
            resource_policies=[{"type": "subpath", "root": "/data"}]
        )
        assert len(facts) == 2
        assert len(checks) == 1

    def test_effect_policies_at_aggregator_compiles(self) -> None:
        facts, checks = compile_mission(
            effect_policies=[{"side_effect_class": "write", "limit": 100}]
        )
        assert len(facts) == 1
        assert len(checks) == 1

    def test_flow_policies_at_aggregator_compiles(self) -> None:
        facts, checks = compile_mission(
            flow_policies=[
                {"from_class": "pii", "to_class": "analytics", "action": "allow"}
            ]
        )
        assert len(facts) == 1
        assert len(checks) == 1

    def test_lineage_budgets_at_aggregator_compiles(self) -> None:
        facts, checks = compile_mission(lineage_budgets=_ALL_CLASSES_BUDGET)
        assert len(facts) == 5
        assert len(checks) == 1

    def test_all_four_policy_types_compile_together(self) -> None:
        facts, checks = compile_mission(
            resource_policies=[{"type": "subpath", "root": "/data"}],
            effect_policies=[{"side_effect_class": "write", "limit": 50}],
            flow_policies=[
                {"from_class": "internal", "to_class": "analytics", "action": "allow"}
            ],
            lineage_budgets=_ALL_CLASSES_BUDGET,
        )
        assert len(facts) > 0
        assert len(checks) > 0
        assert all(isinstance(f, Fact) for f in facts)
        assert all(isinstance(c, Check) for c in checks)

    def test_all_empty_returns_empty(self) -> None:
        facts, checks = compile_mission()
        assert facts == []
        assert checks == []
