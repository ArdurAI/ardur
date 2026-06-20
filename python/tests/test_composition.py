"""Verify session.check_and_record equals compose_decisions on identical inputs."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product

import pytest

import vibap.proxy as proxy_module
from vibap.passport import MissionPassport, issue_passport
from vibap.policy_backend import (
    PolicyDecision,
    clear_registry,
    compose_decisions,
    get_backend,
    register_backend,
    timed_evaluate,
)


@dataclass
class _FixedBackend:
    name: str
    returned: PolicyDecision

    def evaluate(self, **kwargs) -> PolicyDecision:
        return self.returned


def _pd(decision: str, *, backend: str, label: str = "", reasons: tuple[str, ...] = ()) -> PolicyDecision:
    return PolicyDecision(
        backend=backend,
        label=label,
        decision=decision,
        reasons=reasons,
    )


def _spec(pd: PolicyDecision) -> dict[str, str]:
    return {
        "backend": pd.backend,
        "label": pd.label,
        "policy_inline": "",
        "policy_sha256": "x",
    }


def _expected_decision(decisions: list[PolicyDecision]) -> proxy_module.Decision:
    final, _ = compose_decisions(decisions)
    return proxy_module.Decision.PERMIT if final == "Allow" else proxy_module.Decision.DENY


def _expected_event_backends(
    native_decision: PolicyDecision,
    extra_decisions: list[PolicyDecision],
) -> list[str]:
    """Post Phase-3 external-review-G-CRITICAL fix (2026-04-17): the proxy no longer
    short-circuits on first Deny. Every registered backend is evaluated
    on every call so the receipt audit trail is complete; deny-wins
    semantics are handled internally by compose_decisions."""
    if not extra_decisions:
        return []
    backends = ["native_claims"]
    for pd in extra_decisions:
        backends.append(pd.backend)
    return backends


def _assert_matches_compose(
    *,
    decision: proxy_module.Decision,
    reason: str,
    event,
    native_decision: PolicyDecision,
    extra_decisions: list[PolicyDecision],
) -> None:
    all_decisions = [native_decision, *extra_decisions]
    final, first_denier = compose_decisions(all_decisions)
    assert decision == _expected_decision(all_decisions)
    assert [pd["backend"] for pd in event.policy_decisions] == _expected_event_backends(
        native_decision,
        extra_decisions,
    )
    if final == "Allow":
        assert reason == "within scope"
        return
    if first_denier is None:
        assert "fail-closed" in reason
        return
    if first_denier.backend == "native":
        assert all(r in reason for r in first_denier.reasons)
        return
    assert (first_denier.label or first_denier.backend) in reason
    assert all(r in reason for r in first_denier.reasons)


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_registry()
    yield
    clear_registry()


def _run_case(
    proxy,
    private_key,
    *,
    tool_name: str,
    arguments: dict[str, str],
    native_decision: PolicyDecision,
    extra_decisions: list[PolicyDecision],
) -> tuple[proxy_module.Decision, str, object]:
    register_backend(_FixedBackend(name="native", returned=native_decision))
    for pd in extra_decisions:
        register_backend(_FixedBackend(name=pd.backend, returned=pd))

    mission = MissionPassport(
        agent_id="composition-test",
        mission="composition-test",
        allowed_tools=[tool_name],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=10,
        max_duration_s=60,
        additional_policies=[_spec(pd) for pd in extra_decisions],
    )
    session = proxy.start_session(issue_passport(mission, private_key, ttl_s=60))
    return session.check_and_record(tool_name, arguments)


class TestCompositionEquivalence:
    def test_proxy_output_equals_compose_decisions_on_allow_case(self, proxy, private_key):
        native = _pd("Allow", backend="native", reasons=("within scope",))
        decision, reason, event = _run_case(
            proxy,
            private_key,
            tool_name="read_file",
            arguments={"path": "x"},
            native_decision=native,
            extra_decisions=[],
        )
        _assert_matches_compose(
            decision=decision,
            reason=reason,
            event=event,
            native_decision=native,
            extra_decisions=[],
        )

    def test_proxy_output_equals_compose_decisions_on_native_deny(self, proxy, private_key):
        native = _pd("Deny", backend="native", reasons=("native veto",))
        decision, reason, event = _run_case(
            proxy,
            private_key,
            tool_name="read_file",
            arguments={"path": "x"},
            native_decision=native,
            extra_decisions=[],
        )
        _assert_matches_compose(
            decision=decision,
            reason=reason,
            event=event,
            native_decision=native,
            extra_decisions=[],
        )

    def test_proxy_output_equals_compose_decisions_on_cedar_deny(self, proxy, private_key):
        native = _pd("Allow", backend="native", reasons=("within scope",))
        cedar = _pd("Deny", backend="cedar", label="security_team", reasons=("cedar deny",))
        decision, reason, event = _run_case(
            proxy,
            private_key,
            tool_name="read_file",
            arguments={"path": "x"},
            native_decision=native,
            extra_decisions=[cedar],
        )
        _assert_matches_compose(
            decision=decision,
            reason=reason,
            event=event,
            native_decision=native,
            extra_decisions=[cedar],
        )

    def test_proxy_output_equals_compose_decisions_on_forbid_rules_deny(self, proxy, private_key):
        native = _pd("Allow", backend="native", reasons=("within scope",))
        forbid = _pd("Deny", backend="forbid_rules", label="compliance", reasons=("rule matched",))
        decision, reason, event = _run_case(
            proxy,
            private_key,
            tool_name="read_file",
            arguments={"path": "x"},
            native_decision=native,
            extra_decisions=[forbid],
        )
        _assert_matches_compose(
            decision=decision,
            reason=reason,
            event=event,
            native_decision=native,
            extra_decisions=[forbid],
        )

    def test_proxy_output_equals_compose_decisions_on_all_abstain_fails_closed(self, proxy, private_key):
        native = _pd("Abstain", backend="native")
        abstain = _pd("Abstain", backend="cedar", label="security_team")
        decision, reason, event = _run_case(
            proxy,
            private_key,
            tool_name="read_file",
            arguments={"path": "x"},
            native_decision=native,
            extra_decisions=[abstain],
        )
        _assert_matches_compose(
            decision=decision,
            reason=reason,
            event=event,
            native_decision=native,
            extra_decisions=[abstain],
        )

    def test_proxy_output_equals_compose_decisions_on_native_allow_cedar_deny(self, proxy, private_key):
        native = _pd("Allow", backend="native", reasons=("within scope",))
        cedar = _pd("Deny", backend="cedar", label="security_team", reasons=("explicit forbid",))
        decision, reason, event = _run_case(
            proxy,
            private_key,
            tool_name="read_file",
            arguments={"path": "x"},
            native_decision=native,
            extra_decisions=[cedar],
        )
        _assert_matches_compose(
            decision=decision,
            reason=reason,
            event=event,
            native_decision=native,
            extra_decisions=[cedar],
        )

    def test_proxy_output_equals_compose_decisions_on_deny_precedence_ordering(self, proxy, private_key):
        native = _pd("Allow", backend="native", reasons=("within scope",))
        allow = _pd("Allow", backend="cedar", label="security_team")
        first_deny = _pd("Deny", backend="forbid_rules", label="compliance", reasons=("first deny",))
        second_deny = _pd("Deny", backend="extra", label="later", reasons=("second deny",))
        decision, reason, event = _run_case(
            proxy,
            private_key,
            tool_name="read_file",
            arguments={"path": "x"},
            native_decision=native,
            extra_decisions=[allow, first_deny, second_deny],
        )
        _assert_matches_compose(
            decision=decision,
            reason=reason,
            event=event,
            native_decision=native,
            extra_decisions=[allow, first_deny, second_deny],
        )

    def test_proxy_output_equals_compose_decisions_on_budget_exhaustion(self, proxy, private_key):
        mission = MissionPassport(
            agent_id="budget-composition",
            mission="budget-composition",
            allowed_tools=["read_file"],
            forbidden_tools=[],
            resource_scope=[],
            max_tool_calls=1,
            max_duration_s=60,
        )
        session = proxy.start_session(issue_passport(mission, private_key, ttl_s=60))
        first_decision, _, _ = session.check_and_record("read_file", {"path": "x"})
        assert first_decision == proxy_module.Decision.PERMIT

        tool_name = "read_file"
        arguments = {"path": "x"}
        target = proxy_module._policy_event_target(tool_name, arguments)
        action_class = proxy_module._policy_action_class(tool_name)
        resource_family = proxy_module._policy_resource_family(tool_name, arguments, target, action_class)
        side_effect_class = proxy_module._policy_side_effect_class(tool_name, action_class, resource_family)
        native = timed_evaluate(
            get_backend("native"),
            tool_name=tool_name,
            arguments=arguments,
            principal=str(session.passport_claims.get("sub", "unknown")),
            target=target,
            context={
                "passport": dict(session.passport_claims),
                "session": {
                    "tool_call_count": session.tool_call_count,
                    "tool_call_count_by_class": dict(session.tool_call_count_by_class),
                    "side_effect_counts": dict(session.tool_call_count_by_class),
                    "delegated_budget_reserved": session.delegated_budget_reserved,
                    "delegation_depth": len(session.passport_claims.get("delegation_chain", []) or []),
                    "elapsed_s": session.elapsed_s,
                    "cwd": session.passport_claims.get("cwd"),
                },
                "elapsed_s": session.elapsed_s,
                "tool_call_count": session.tool_call_count,
                "action_class": action_class,
                "side_effect_class": side_effect_class,
            },
            policy_spec={},
        )
        decision, reason, event = session.check_and_record(tool_name, arguments)
        assert native.decision == "Deny"
        _assert_matches_compose(
            decision=decision,
            reason=reason,
            event=event,
            native_decision=native,
            extra_decisions=[],
        )

    def test_proxy_output_equals_compose_decisions_over_z3_property_inputs(self, proxy, private_key):
        for native_label, b1_label, b2_label in product(("Allow", "Deny", "Abstain"), repeat=3):
            native = _pd(native_label, backend="native", reasons=(native_label.lower(),) if native_label != "Abstain" else ())
            b1 = _pd(b1_label, backend="b1", label="L1", reasons=(b1_label.lower(),) if b1_label != "Abstain" else ())
            b2 = _pd(b2_label, backend="b2", label="L2", reasons=(b2_label.lower(),) if b2_label != "Abstain" else ())
            decision, reason, event = _run_case(
                proxy,
                private_key,
                tool_name="read_file",
                arguments={"path": "x"},
                native_decision=native,
                extra_decisions=[b1, b2],
            )
            _assert_matches_compose(
                decision=decision,
                reason=reason,
                event=event,
                native_decision=native,
                extra_decisions=[b1, b2],
            )
