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
    lower_resource_policies,
)


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
    # New check uses fact matching, not literal string interpolation.
    assert "resource_subpath_root($r)" in rendered
    assert "resource_subpath_prefix($p)" in rendered
    assert "$r.starts_with($p)" in rendered
    # Anti-traversal guard (2026-04-21 audit fix #11).
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
    # 2 facts for the subpath (root + prefix) + 1 per allowed domain
    assert len(facts) == 3
    # One check per distinct policy type (subpath, url_allowlist)
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
    # Post-audit-fix: each SubpathPolicy emits root + prefix facts.
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
    # 2 policies * (root + prefix) = 4 facts
    assert len(facts) == 4
    rendered_facts = [str(f) for f in facts]
    assert any('resource_subpath_root("/data/reports")' in r for r in rendered_facts)
    assert any('resource_subpath_root("/logs")' in r for r in rendered_facts)
    # CRITICAL: ONE combined check, not two.
    assert len(checks) == 1


def test_subpath_rejects_dot_dot_segment_in_root() -> None:
    """2026-04-21 audit fix #11: policy-time rejection of traversal-shaped
    roots like ``/safe/..`` or ``/data/../secret``. Complements the
    check-time ``!$r.contains("/..")`` guard so operators cannot
    accidentally author a policy whose matched resources resolve
    outside the intended subtree after executor normalization."""
    for bad_root in ("/data/..", "/safe/../secret", "/../etc", "/..", "/a/../b"):
        with pytest.raises(MissionCompileError, match=r"'\.\.'"):
            SubpathPolicy.from_dict({"root": bad_root})
    # Segments that merely contain ``..`` as a substring (not a whole
    # path segment) are accepted — the check is segment-wise, not
    # substring-wise, to avoid false-positives on legitimate names.
    ok = SubpathPolicy.from_dict({"root": "/data/v..recent"})
    assert ok.root == "/data/v..recent"


def test_subpath_check_has_anti_traversal_guard_in_rendered_source() -> None:
    """Defense-in-depth: even if a caller asserts ``resource("/safe/../x")``
    at runtime, the rendered Biscuit check refuses to match any resource
    whose raw string contains ``/..`` — so an executor that canonicalizes
    paths after the check cannot smuggle a traversal past it."""
    _, checks = lower_resource_policies([{"type": "subpath", "root": "/safe"}])
    rendered = str(checks[0])
    assert '!$r.contains("/..")' in rendered


# H1 guards: effect_policies and flow_policies lowering is intentionally
# unimplemented, and must raise a loud NotImplementedError rather than silently
# producing an empty policy. A silent no-op is a footgun: mission authors
# expect their declared bounds to be enforced.

class TestEffectPolicyGuard:
    def test_empty_effect_policies_returns_empty(self) -> None:
        facts, checks = lower_effect_policies([])
        assert facts == []
        assert checks == []

    def test_non_empty_effect_policies_raises_not_implemented(self) -> None:
        with pytest.raises(MissionPolicyNotImplementedError, match="effect_policies"):
            lower_effect_policies([{"type": "max_invocations", "limit": 3}])

    def test_error_is_subclass_of_NotImplementedError(self) -> None:
        assert issubclass(MissionPolicyNotImplementedError, NotImplementedError)


class TestFlowPolicyGuard:
    def test_empty_flow_policies_returns_empty(self) -> None:
        facts, checks = lower_flow_policies([])
        assert facts == []
        assert checks == []

    def test_non_empty_flow_policies_raises_not_implemented(self) -> None:
        with pytest.raises(MissionPolicyNotImplementedError, match="flow_policies"):
            lower_flow_policies([{"type": "no_external_egress"}])


class TestCompileMissionAggregator:
    def test_resource_only_compiles_ok(self) -> None:
        facts, checks = compile_mission(
            resource_policies=[{"type": "subpath", "root": "/data"}]
        )
        assert len(facts) == 2
        assert len(checks) == 1

    def test_lineage_budgets_at_aggregator_raises_phase1_deferred(self) -> None:
        with pytest.raises(
            MissionPolicyNotImplementedError,
            match=r"lineage_budgets.*Phase 1.*deferred",
        ):
            compile_mission(
                lineage_budgets=[{"type": "max_child_tool_calls", "limit": 3}]
            )

    def test_effect_policies_at_aggregator_raises(self) -> None:
        with pytest.raises(MissionPolicyNotImplementedError, match="effect_policies"):
            compile_mission(
                resource_policies=[{"type": "subpath", "root": "/data"}],
                effect_policies=[{"type": "max_invocations", "limit": 3}],
            )

    def test_flow_policies_at_aggregator_raises(self) -> None:
        with pytest.raises(MissionPolicyNotImplementedError, match="flow_policies"):
            compile_mission(
                resource_policies=[],
                flow_policies=[{"type": "no_external_egress"}],
            )

    def test_all_empty_returns_empty(self) -> None:
        facts, checks = compile_mission()
        assert facts == []
        assert checks == []
