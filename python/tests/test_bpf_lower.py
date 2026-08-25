"""Golden tests for bpf_lower.lower_to_bpf_policy_plan.

Design mirrors test_mission_compile.py: each logical lowering rule gets
dedicated tests, then aggregator tests verify the combined result.
"""

from __future__ import annotations

import pytest

from vibap.bpf_lower import (
    BpfLowerError,
    _FILE_ALLOW_MAX_ANCESTOR_DEPTH,
    lower_to_bpf_policy_plan,
)
from vibap.bpf_types import (
    ACT_ALLOW,
    ACT_ALLOWLIST,
    ACT_DENY,
    ALL_SIDE_EFFECT_CLASSES,
    ENFORCE_MODE_ENFORCE,
    ENFORCE_MODE_PERMISSIVE,
    OP_EXEC,
    OP_EXTERNAL_SEND,
    OP_FILE_READ,
    OP_FILE_WRITE,
    OP_NET_CONNECT,
    SEC_TO_OPS,
)
from vibap.mission_compile import MissionPolicyNotImplementedError


# ---------------------------------------------------------------------------
# 4.0 — taxonomy constants
# ---------------------------------------------------------------------------


class TestTaxonomyConstants:
    def test_five_op_codes_are_distinct(self) -> None:
        ops = [OP_EXEC, OP_FILE_READ, OP_FILE_WRITE, OP_NET_CONNECT, OP_EXTERNAL_SEND]
        assert len(set(ops)) == 5

    def test_actions_are_distinct(self) -> None:
        assert len({ACT_ALLOW, ACT_DENY, ACT_ALLOWLIST}) == 3

    def test_enforce_modes_are_distinct(self) -> None:
        assert ENFORCE_MODE_PERMISSIVE != ENFORCE_MODE_ENFORCE

    def test_sec_to_ops_covers_all_side_effect_classes(self) -> None:
        assert set(SEC_TO_OPS.keys()) == ALL_SIDE_EFFECT_CLASSES

    def test_sec_to_ops_values_are_non_empty_frozensets(self) -> None:
        for sec, ops in SEC_TO_OPS.items():
            assert ops, f"{sec} maps to empty op set"

    def test_sec_read_maps_to_file_read(self) -> None:
        assert OP_FILE_READ in SEC_TO_OPS["read"]

    def test_sec_write_maps_to_file_write(self) -> None:
        assert OP_FILE_WRITE in SEC_TO_OPS["write"]

    def test_sec_exec_maps_to_exec(self) -> None:
        assert OP_EXEC in SEC_TO_OPS["exec"]

    def test_sec_network_maps_to_net_connect(self) -> None:
        assert OP_NET_CONNECT in SEC_TO_OPS["network"]

    def test_sec_external_send_maps_to_external_send(self) -> None:
        assert OP_EXTERNAL_SEND in SEC_TO_OPS["external_send"]


# ---------------------------------------------------------------------------
# Empty mission → empty plan
# ---------------------------------------------------------------------------


class TestEmptyMission:
    def test_all_empty_returns_empty_plan(self) -> None:
        plan = lower_to_bpf_policy_plan()
        assert plan.op_policies == ()
        assert plan.path_allow == ()
        assert plan.net_allow == ()
        assert plan.tier2_ops == ()

    def test_empty_plan_has_no_kernel_enforcement(self) -> None:
        plan = lower_to_bpf_policy_plan()
        assert not plan.has_kernel_enforcement()


# ---------------------------------------------------------------------------
# 4.1 — allowed_side_effect_classes → class-level deny
# ---------------------------------------------------------------------------


class TestAllowedSideEffectClasses:
    def test_empty_list_produces_no_denies(self) -> None:
        plan = lower_to_bpf_policy_plan(allowed_side_effect_classes=[])
        assert plan.op_policies == ()

    def test_all_five_classes_allowed_produces_no_denies(self) -> None:
        plan = lower_to_bpf_policy_plan(
            allowed_side_effect_classes=["read", "write", "network", "exec", "external_send"]
        )
        assert not any(e.action == ACT_DENY for e in plan.op_policies)

    def test_deny_absent_class_exec(self) -> None:
        # All classes allowed EXCEPT exec → OP_EXEC must be ACT_DENY.
        plan = lower_to_bpf_policy_plan(
            allowed_side_effect_classes=["read", "write", "network", "external_send"]
        )
        assert plan.denies_op(OP_EXEC)

    def test_deny_absent_class_external_send(self) -> None:
        plan = lower_to_bpf_policy_plan(
            allowed_side_effect_classes=["read", "write", "network", "exec"]
        )
        assert plan.denies_op(OP_EXTERNAL_SEND)

    def test_deny_absent_class_network(self) -> None:
        plan = lower_to_bpf_policy_plan(
            allowed_side_effect_classes=["read", "write", "exec", "external_send"]
        )
        assert plan.denies_op(OP_NET_CONNECT)

    def test_no_deny_for_present_class(self) -> None:
        plan = lower_to_bpf_policy_plan(
            allowed_side_effect_classes=["exec"]
        )
        # exec is allowed; read/write/network/external_send are denied
        assert not plan.denies_op(OP_EXEC)

    def test_deny_all_five_absent_classes_single_allowed(self) -> None:
        # Only exec allowed → all other 4 classes get ACT_DENY.
        plan = lower_to_bpf_policy_plan(allowed_side_effect_classes=["exec"])
        denied_ops = {e.op for e in plan.op_policies if e.action == ACT_DENY}
        # Absent classes: read→OP_FILE_READ, write→OP_FILE_WRITE,
        # network→OP_NET_CONNECT, external_send→OP_EXTERNAL_SEND
        assert OP_FILE_READ in denied_ops
        assert OP_FILE_WRITE in denied_ops
        assert OP_NET_CONNECT in denied_ops
        assert OP_EXTERNAL_SEND in denied_ops
        assert OP_EXEC not in denied_ops

    def test_rejects_unknown_side_effect_class(self) -> None:
        with pytest.raises(BpfLowerError, match="unknown side_effect_class"):
            lower_to_bpf_policy_plan(allowed_side_effect_classes=["bogus"])

    def test_enforce_mode_propagates_to_deny_entries(self) -> None:
        plan = lower_to_bpf_policy_plan(
            allowed_side_effect_classes=["read"],
            enforce_mode=ENFORCE_MODE_ENFORCE,
        )
        for entry in plan.op_policies:
            if entry.action == ACT_DENY:
                assert entry.enforce_mode == ENFORCE_MODE_ENFORCE

    def test_plan_has_kernel_enforcement_when_classes_restricted(self) -> None:
        plan = lower_to_bpf_policy_plan(
            allowed_side_effect_classes=["read"]
        )
        assert plan.has_kernel_enforcement()


# ---------------------------------------------------------------------------
# 4.1 — forbidden_tools → op-level deny
# ---------------------------------------------------------------------------


class TestForbiddenTools:
    def test_exec_tool_name_maps_to_op_exec_deny(self) -> None:
        plan = lower_to_bpf_policy_plan(forbidden_tools=["bash"])
        assert plan.denies_op(OP_EXEC)

    def test_external_send_tool_name_maps_to_op_external_send_deny(self) -> None:
        plan = lower_to_bpf_policy_plan(forbidden_tools=["send_email"])
        assert plan.denies_op(OP_EXTERNAL_SEND)

    def test_file_write_tool_name_maps_to_op_file_write_deny(self) -> None:
        plan = lower_to_bpf_policy_plan(forbidden_tools=["write_file"])
        assert plan.denies_op(OP_FILE_WRITE)

    def test_net_connect_tool_name_maps_to_op_net_connect_deny(self) -> None:
        plan = lower_to_bpf_policy_plan(forbidden_tools=["http_get"])
        assert plan.denies_op(OP_NET_CONNECT)

    def test_unmappable_tool_name_goes_to_tier2(self) -> None:
        plan = lower_to_bpf_policy_plan(forbidden_tools=["custom_analysis_tool"])
        assert any("custom_analysis_tool" in t for t in plan.tier2_ops)
        assert plan.op_policies == ()

    def test_multiple_forbidden_tools_mix_of_mapped_and_tier2(self) -> None:
        plan = lower_to_bpf_policy_plan(
            forbidden_tools=["bash", "custom_analysis_tool", "send_email"]
        )
        assert plan.denies_op(OP_EXEC)
        assert plan.denies_op(OP_EXTERNAL_SEND)
        assert any("custom_analysis_tool" in t for t in plan.tier2_ops)

    def test_empty_forbidden_tools_produces_no_entries(self) -> None:
        plan = lower_to_bpf_policy_plan(forbidden_tools=[])
        assert plan.op_policies == ()

    def test_execute_tool_name_maps_to_op_exec(self) -> None:
        plan = lower_to_bpf_policy_plan(forbidden_tools=["execute_command"])
        assert plan.denies_op(OP_EXEC)

    def test_run_tool_name_maps_to_op_exec(self) -> None:
        plan = lower_to_bpf_policy_plan(forbidden_tools=["run_script"])
        assert plan.denies_op(OP_EXEC)


# ---------------------------------------------------------------------------
# 4.1 — allowed_tools → op-level explicit allow or tier2
# ---------------------------------------------------------------------------


class TestAllowedTools:
    def test_unmappable_allowed_tool_goes_to_tier2(self) -> None:
        plan = lower_to_bpf_policy_plan(allowed_tools=["custom_read_tool"])
        assert any("custom_read_tool" in t for t in plan.tier2_ops)

    def test_mappable_allowed_tool_emits_explicit_allow(self) -> None:
        plan = lower_to_bpf_policy_plan(
            allowed_side_effect_classes=["write"],
            allowed_tools=["bash"],  # bash → OP_EXEC
        )
        # bash maps to OP_EXEC which is NOT denied by class policy (exec not in allowed but
        # wait — allowed_side_effect_classes=["write"] means everything except "write" is denied.
        # Actually exec was NOT in allowed_side_effect_classes so OP_EXEC is denied by class.
        # The allowed_tool override should land in tier2 since it's overriding a class deny.
        assert any("bash" in t for t in plan.tier2_ops)

    def test_allowed_tool_with_no_class_restrict_gets_explicit_allow(self) -> None:
        # No class restrictions at all → allowed_tool maps to ACT_ALLOW entry.
        plan = lower_to_bpf_policy_plan(allowed_tools=["bash"])
        assert any(e.op == OP_EXEC and e.action == ACT_ALLOW for e in plan.op_policies)


# ---------------------------------------------------------------------------
# 4.1 — resource_scope (legacy paths) → path_allow + ACT_ALLOWLIST
# ---------------------------------------------------------------------------


class TestResourceScope:
    def test_absolute_path_goes_to_path_allow(self) -> None:
        plan = lower_to_bpf_policy_plan(resource_scope=["/data/reports"])
        assert "/data/reports" in plan.path_allow

    def test_sets_file_read_to_allowlist(self) -> None:
        plan = lower_to_bpf_policy_plan(resource_scope=["/data"])
        assert plan.allowlists_op(OP_FILE_READ)

    def test_sets_file_write_to_allowlist(self) -> None:
        plan = lower_to_bpf_policy_plan(resource_scope=["/data"])
        assert plan.allowlists_op(OP_FILE_WRITE)

    def test_multiple_paths_all_go_to_path_allow(self) -> None:
        plan = lower_to_bpf_policy_plan(resource_scope=["/data", "/logs", "/tmp/work"])
        assert "/data" in plan.path_allow
        assert "/logs" in plan.path_allow
        assert "/tmp/work" in plan.path_allow

    def test_root_path_slash_accepted(self) -> None:
        plan = lower_to_bpf_policy_plan(resource_scope=["/"])
        assert "/" in plan.path_allow

    def test_trailing_slash_stripped(self) -> None:
        plan = lower_to_bpf_policy_plan(resource_scope=["/data/"])
        assert "/data" in plan.path_allow
        assert "/data/" not in plan.path_allow

    def test_relative_path_ignored(self) -> None:
        plan = lower_to_bpf_policy_plan(resource_scope=["data/relative"])
        assert plan.path_allow == ()

    def test_traversal_segment_ignored(self) -> None:
        plan = lower_to_bpf_policy_plan(resource_scope=["/safe/../etc"])
        assert plan.path_allow == ()

    def test_empty_resource_scope_produces_no_path_allow(self) -> None:
        plan = lower_to_bpf_policy_plan(resource_scope=[])
        assert plan.path_allow == ()
        assert not plan.allowlists_op(OP_FILE_READ)


# ---------------------------------------------------------------------------
# 4.1 — resource_policies (typed) → path_allow or tier2_ops
# ---------------------------------------------------------------------------


class TestResourcePoliciesTyped:
    def test_subpath_policy_goes_to_path_allow(self) -> None:
        plan = lower_to_bpf_policy_plan(
            resource_policies=[{"type": "subpath", "root": "/workspace"}]
        )
        assert "/workspace" in plan.path_allow

    def test_subpath_policy_sets_file_ops_to_allowlist(self) -> None:
        plan = lower_to_bpf_policy_plan(
            resource_policies=[{"type": "subpath", "root": "/workspace"}]
        )
        assert plan.allowlists_op(OP_FILE_READ)
        assert plan.allowlists_op(OP_FILE_WRITE)

    def test_url_allowlist_hostname_goes_to_tier2(self) -> None:
        expected_tier2 = "url_allowlist_hostname:api.example.com"
        plan = lower_to_bpf_policy_plan(
            resource_policies=[
                {"type": "url_allowlist", "allow_domains": ["api.example.com"]}
            ]
        )
        assert expected_tier2 in plan.tier2_ops
        assert "api.example.com" not in plan.net_allow

    def test_url_allowlist_ip_goes_to_net_allow(self) -> None:
        plan = lower_to_bpf_policy_plan(
            resource_policies=[
                {"type": "url_allowlist", "allow_domains": ["192.168.1.0/24"]}
            ]
        )
        assert "192.168.1.0/24" in plan.net_allow
        assert not any("192.168.1.0/24" in t for t in plan.tier2_ops)

    def test_url_allowlist_ip_sets_net_connect_to_allowlist(self) -> None:
        plan = lower_to_bpf_policy_plan(
            resource_policies=[
                {"type": "url_allowlist", "allow_domains": ["10.0.0.1"]}
            ]
        )
        assert plan.allowlists_op(OP_NET_CONNECT)

    def test_mixed_hostname_and_ip_in_url_allowlist(self) -> None:
        expected_tier2 = "url_allowlist_hostname:api.example.com"
        plan = lower_to_bpf_policy_plan(
            resource_policies=[
                {
                    "type": "url_allowlist",
                    "allow_domains": ["api.example.com", "10.0.0.1"],
                }
            ]
        )
        assert "10.0.0.1" in plan.net_allow
        assert expected_tier2 in plan.tier2_ops


# ---------------------------------------------------------------------------
# Slice 4.1/4.2 reconciliation — file-allow ancestor-depth bound.
#
# guard_file_open's sleepable hook enforces path_allow via a bounded
# ancestor-directory walk (ARDUR_FILE_ALLOW_MAX_ANCESTORS in
# process_guard.bpf.c), not the LPM trie the non-sleepable hooks use. A
# path_allow root nested deeper than that bound can never be matched by a
# real file access under it, so bpf_lower must not silently promise it's
# enforced — see _FILE_ALLOW_MAX_ANCESTOR_DEPTH's doc comment.
# ---------------------------------------------------------------------------


def _path_at_depth(depth: int) -> str:
    return "/" + "/".join(f"level{i}" for i in range(depth))


class TestFileAllowDepthBound:
    def test_shallow_resource_scope_path_is_enforceable(self) -> None:
        plan = lower_to_bpf_policy_plan(resource_scope=["/workspace/project"])
        assert "/workspace/project" in plan.path_allow
        assert not any("too_deep" in t for t in plan.tier2_ops)

    def test_path_at_exact_depth_bound_is_enforceable(self) -> None:
        at_bound = _path_at_depth(_FILE_ALLOW_MAX_ANCESTOR_DEPTH)
        plan = lower_to_bpf_policy_plan(resource_scope=[at_bound])
        assert at_bound in plan.path_allow
        assert not any("too_deep" in t for t in plan.tier2_ops)

    def test_resource_scope_path_past_depth_bound_goes_to_tier2(self) -> None:
        too_deep = _path_at_depth(_FILE_ALLOW_MAX_ANCESTOR_DEPTH + 1)
        plan = lower_to_bpf_policy_plan(resource_scope=[too_deep])
        assert too_deep not in plan.path_allow
        assert any(too_deep in t and "too_deep" in t for t in plan.tier2_ops)

    def test_subpath_policy_root_past_depth_bound_goes_to_tier2(self) -> None:
        too_deep = _path_at_depth(_FILE_ALLOW_MAX_ANCESTOR_DEPTH + 1)
        plan = lower_to_bpf_policy_plan(
            resource_policies=[{"type": "subpath", "root": too_deep}]
        )
        assert too_deep not in plan.path_allow
        assert any(too_deep in t and "too_deep" in t for t in plan.tier2_ops)

    def test_root_slash_is_always_enforceable_regardless_of_depth_bound(self) -> None:
        plan = lower_to_bpf_policy_plan(resource_scope=["/"])
        assert "/" in plan.path_allow
        assert not any("too_deep" in t for t in plan.tier2_ops)

    def test_enforce_strict_raises_on_deep_resource_scope_path(self) -> None:
        too_deep = _path_at_depth(_FILE_ALLOW_MAX_ANCESTOR_DEPTH + 1)
        with pytest.raises(MissionPolicyNotImplementedError, match="nested"):
            lower_to_bpf_policy_plan(
                resource_scope=[too_deep], enforce_mode=ENFORCE_MODE_ENFORCE
            )

    def test_enforce_strict_raises_on_deep_subpath_policy_root(self) -> None:
        too_deep = _path_at_depth(_FILE_ALLOW_MAX_ANCESTOR_DEPTH + 1)
        with pytest.raises(MissionPolicyNotImplementedError, match="nested"):
            lower_to_bpf_policy_plan(
                resource_policies=[{"type": "subpath", "root": too_deep}],
                enforce_mode=ENFORCE_MODE_ENFORCE,
            )

    def test_enforce_strict_tolerates_shallow_resource_scope_path(self) -> None:
        plan = lower_to_bpf_policy_plan(
            resource_scope=["/workspace"], enforce_mode=ENFORCE_MODE_ENFORCE
        )
        assert "/workspace" in plan.path_allow

    def test_enforce_strict_tolerates_shallow_subpath_policy_root(self) -> None:
        plan = lower_to_bpf_policy_plan(
            resource_policies=[{"type": "subpath", "root": "/workspace"}],
            enforce_mode=ENFORCE_MODE_ENFORCE,
        )
        assert "/workspace" in plan.path_allow


# ---------------------------------------------------------------------------
# 4.1 — net_prefixes → net_allow directly
# ---------------------------------------------------------------------------


class TestNetPrefixes:
    def test_valid_ipv4_cidr_goes_to_net_allow(self) -> None:
        plan = lower_to_bpf_policy_plan(net_prefixes=["203.0.113.0/24"])
        assert "203.0.113.0/24" in plan.net_allow

    def test_valid_ipv6_goes_to_net_allow(self) -> None:
        plan = lower_to_bpf_policy_plan(net_prefixes=["2001:db8::/32"])
        assert "2001:db8::/32" in plan.net_allow

    def test_invalid_prefix_goes_to_tier2(self) -> None:
        plan = lower_to_bpf_policy_plan(net_prefixes=["not-an-ip"])
        assert any("not-an-ip" in t for t in plan.tier2_ops)

    def test_net_prefixes_set_net_connect_to_allowlist(self) -> None:
        plan = lower_to_bpf_policy_plan(net_prefixes=["192.0.2.1"])
        assert plan.allowlists_op(OP_NET_CONNECT)


# ---------------------------------------------------------------------------
# 4.1 — semantic dimensions → tier2_ops (and ENFORCE_STRICT loud-guard)
# ---------------------------------------------------------------------------


class TestSemanticDimensionsTier2:
    def test_effect_policies_go_to_tier2(self) -> None:
        plan = lower_to_bpf_policy_plan(
            effect_policies=[{"side_effect_class": "write", "limit": 10}]
        )
        assert "effect_policies" in plan.tier2_ops

    def test_flow_policies_go_to_tier2(self) -> None:
        plan = lower_to_bpf_policy_plan(
            flow_policies=[{"from_class": "pii", "to_class": "sink", "action": "deny"}]
        )
        assert "flow_policies" in plan.tier2_ops

    def test_lineage_budgets_go_to_tier2(self) -> None:
        budget = {
            "per_effect_class": {
                "read": {"reserved": 0, "ceiling": 100},
                "write": {"reserved": 0, "ceiling": 50},
                "network": {"reserved": 0, "ceiling": 200},
                "exec": {"reserved": 0, "ceiling": 10},
                "external_send": {"reserved": 0, "ceiling": 5},
            }
        }
        plan = lower_to_bpf_policy_plan(lineage_budgets=budget)
        assert "lineage_budgets" in plan.tier2_ops

    def test_enforce_strict_raises_on_effect_policies(self) -> None:
        with pytest.raises(MissionPolicyNotImplementedError, match="effect_policies"):
            lower_to_bpf_policy_plan(
                effect_policies=[{"side_effect_class": "write", "limit": 10}],
                enforce_mode=ENFORCE_MODE_ENFORCE,
            )

    def test_enforce_strict_raises_on_flow_policies(self) -> None:
        with pytest.raises(MissionPolicyNotImplementedError, match="flow_policies"):
            lower_to_bpf_policy_plan(
                flow_policies=[{"from_class": "pii", "to_class": "sink", "action": "deny"}],
                enforce_mode=ENFORCE_MODE_ENFORCE,
            )

    def test_enforce_strict_raises_on_lineage_budgets(self) -> None:
        budget = {
            "per_effect_class": {
                "read": {"reserved": 0, "ceiling": 100},
                "write": {"reserved": 0, "ceiling": 50},
                "network": {"reserved": 0, "ceiling": 200},
                "exec": {"reserved": 0, "ceiling": 10},
                "external_send": {"reserved": 0, "ceiling": 5},
            }
        }
        with pytest.raises(MissionPolicyNotImplementedError, match="lineage_budgets"):
            lower_to_bpf_policy_plan(
                lineage_budgets=budget, enforce_mode=ENFORCE_MODE_ENFORCE
            )

    def test_enforce_strict_raises_lists_all_failing_dims(self) -> None:
        with pytest.raises(MissionPolicyNotImplementedError) as exc_info:
            lower_to_bpf_policy_plan(
                effect_policies=[{"side_effect_class": "write", "limit": 10}],
                flow_policies=[{"from_class": "A", "to_class": "B", "action": "deny"}],
                enforce_mode=ENFORCE_MODE_ENFORCE,
            )
        msg = str(exc_info.value)
        assert "effect_policies" in msg
        assert "flow_policies" in msg

    def test_permissive_mode_tolerates_semantic_dims(self) -> None:
        plan = lower_to_bpf_policy_plan(
            effect_policies=[{"side_effect_class": "write", "limit": 10}],
            enforce_mode=ENFORCE_MODE_PERMISSIVE,
        )
        assert "effect_policies" in plan.tier2_ops

    def test_empty_semantic_dims_produce_no_tier2_entries(self) -> None:
        plan = lower_to_bpf_policy_plan()
        assert not any(
            d in plan.tier2_ops
            for d in ["effect_policies", "flow_policies", "lineage_budgets"]
        )


# ---------------------------------------------------------------------------
# BpfPolicyPlan helper methods
# ---------------------------------------------------------------------------


class TestBpfPolicyPlanHelpers:
    def test_denies_op_true_for_denied_op(self) -> None:
        plan = lower_to_bpf_policy_plan(allowed_side_effect_classes=["read"])
        assert plan.denies_op(OP_EXEC)

    def test_denies_op_false_for_non_denied_op(self) -> None:
        plan = lower_to_bpf_policy_plan(allowed_side_effect_classes=["read"])
        assert not plan.denies_op(OP_FILE_READ)

    def test_allowlists_op_true_when_op_in_allowlist(self) -> None:
        plan = lower_to_bpf_policy_plan(resource_scope=["/data"])
        assert plan.allowlists_op(OP_FILE_READ)

    def test_allowlists_op_false_when_op_not_allowlisted(self) -> None:
        plan = lower_to_bpf_policy_plan(resource_scope=["/data"])
        assert not plan.allowlists_op(OP_EXEC)

    def test_has_kernel_enforcement_false_for_empty_plan(self) -> None:
        plan = lower_to_bpf_policy_plan()
        assert not plan.has_kernel_enforcement()

    def test_has_kernel_enforcement_true_with_class_deny(self) -> None:
        plan = lower_to_bpf_policy_plan(
            allowed_side_effect_classes=["read"]
        )
        assert plan.has_kernel_enforcement()


# ---------------------------------------------------------------------------
# Aggregator — combined inputs
# ---------------------------------------------------------------------------


class TestCombinedInputs:
    def test_class_deny_plus_path_scope(self) -> None:
        plan = lower_to_bpf_policy_plan(
            allowed_side_effect_classes=["read", "write"],
            resource_scope=["/workspace"],
        )
        # exec/network/external_send denied
        assert plan.denies_op(OP_EXEC)
        assert plan.denies_op(OP_NET_CONNECT)
        assert plan.denies_op(OP_EXTERNAL_SEND)
        # read and write set to allowlist (scope takes precedence over class-level allow)
        assert plan.allowlists_op(OP_FILE_READ)
        assert plan.allowlists_op(OP_FILE_WRITE)
        assert "/workspace" in plan.path_allow

    def test_class_deny_plus_forbidden_exec_tool(self) -> None:
        plan = lower_to_bpf_policy_plan(
            allowed_side_effect_classes=["read", "write", "network", "external_send"],
            forbidden_tools=["bash"],
        )
        assert plan.denies_op(OP_EXEC)
        assert not plan.denies_op(OP_FILE_READ)

    def test_class_deny_with_semantic_dims_in_permissive(self) -> None:
        plan = lower_to_bpf_policy_plan(
            allowed_side_effect_classes=["exec"],
            effect_policies=[{"side_effect_class": "exec", "limit": 5}],
            enforce_mode=ENFORCE_MODE_PERMISSIVE,
        )
        assert "effect_policies" in plan.tier2_ops
        assert plan.has_kernel_enforcement()

    def test_full_readonly_mission(self) -> None:
        """A read-only mission: only read allowed, scoped to /data."""
        plan = lower_to_bpf_policy_plan(
            allowed_side_effect_classes=["read"],
            resource_scope=["/data"],
        )
        assert plan.denies_op(OP_EXEC)
        assert plan.denies_op(OP_NET_CONNECT)
        assert plan.denies_op(OP_EXTERNAL_SEND)
        assert plan.denies_op(OP_FILE_WRITE)
        assert plan.allowlists_op(OP_FILE_READ)
        assert "/data" in plan.path_allow

    def test_class_restrict_and_typed_subpath(self) -> None:
        plan = lower_to_bpf_policy_plan(
            allowed_side_effect_classes=["read"],
            resource_policies=[{"type": "subpath", "root": "/workspace"}],
        )
        assert "/workspace" in plan.path_allow
        assert plan.allowlists_op(OP_FILE_READ)
        assert plan.denies_op(OP_EXEC)

    def test_all_allowed_with_no_scope_returns_minimal_plan(self) -> None:
        """All 5 classes allowed + no tool restrictions = no deny entries."""
        plan = lower_to_bpf_policy_plan(
            allowed_side_effect_classes=[
                "read", "write", "network", "exec", "external_send"
            ]
        )
        assert all(e.action != ACT_DENY for e in plan.op_policies)
        assert not plan.has_kernel_enforcement()
