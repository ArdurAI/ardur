"""Pure native governance checks shared by proxy composition and NativeBackend."""

from __future__ import annotations

from typing import Any, Mapping

from .passport import MAX_DELEGATION_DEPTH


def _proxy_module():
    from . import proxy as proxy_module

    return proxy_module


def _policy_metadata(
    tool_name: str,
    arguments: dict[str, Any],
    target: str,
    policy_metadata: Mapping[str, Any] | None = None,
) -> tuple[str, str, str]:
    if isinstance(policy_metadata, Mapping):
        action_class = policy_metadata.get("action_class")
        resource_family = policy_metadata.get("resource_family")
        side_effect_class = policy_metadata.get("side_effect_class")
        if all(isinstance(item, str) and item for item in (action_class, resource_family, side_effect_class)):
            return str(action_class), str(resource_family), str(side_effect_class)

    proxy_module = _proxy_module()
    action_class = proxy_module._policy_action_class(tool_name)
    resource_family = proxy_module._policy_resource_family(
        tool_name,
        arguments,
        target,
        action_class,
    )
    side_effect_class = proxy_module._policy_side_effect_class(
        tool_name,
        action_class,
        resource_family,
    )
    return action_class, resource_family, side_effect_class


def _check_delegation_depth(
    passport_dict: dict[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
    target: str,
    session_state: dict[str, Any],
) -> list[str]:
    del tool_name, arguments, target, session_state
    chain = passport_dict.get("delegation_chain") or []
    if isinstance(chain, list) and len(chain) > MAX_DELEGATION_DEPTH:
        return ["delegation depth exceeded"]
    return []


def _check_forbidden_tools(
    passport_dict: dict[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
    target: str,
    session_state: dict[str, Any],
) -> list[str]:
    del arguments, target, session_state
    forbidden = passport_dict.get("forbidden_tools", [])
    if tool_name in forbidden:
        return [f"tool '{tool_name}' is in forbidden_tools"]
    return []


def _check_tool_scope(
    passport_dict: dict[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
    target: str,
    session_state: dict[str, Any],
) -> list[str]:
    del arguments, target, session_state
    allowed = passport_dict.get("allowed_tools", [])
    if "*" in allowed:
        return []
    if tool_name not in allowed:
        return [f"tool '{tool_name}' is not in allowed_tools"]
    return []


def _check_session_budget(
    passport_dict: dict[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
    target: str,
    session_state: dict[str, Any],
) -> list[str]:
    del tool_name, arguments, target
    max_calls = int(passport_dict.get("max_tool_calls", 50))
    delegated_budget_reserved = int(session_state.get("delegated_budget_reserved", 0))
    effective_max_calls = max(0, max_calls - delegated_budget_reserved)
    tool_call_count = int(session_state.get("tool_call_count", 0))
    if tool_call_count >= effective_max_calls:
        return [
            (
                f"budget exceeded: {tool_call_count}/{effective_max_calls} tool calls used "
                f"({delegated_budget_reserved} reserved for delegated children from ceiling {max_calls})"
            )
        ]

    max_duration = int(passport_dict.get("max_duration_s", 600))
    elapsed_s = float(session_state.get("elapsed_s", 0.0))
    if elapsed_s >= max_duration:
        return [f"duration exceeded: {elapsed_s:.0f}s / {max_duration}s"]
    return []


def _check_resource_scope(
    passport_dict: dict[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
    target: str,
    session_state: dict[str, Any],
) -> list[str]:
    del tool_name, target, session_state
    proxy_module = _proxy_module()
    resource_scope = list(passport_dict.get("resource_scope", []) or [])
    cwd = passport_dict.get("cwd")
    ok, reason = proxy_module._check_resource_scope(arguments, resource_scope, cwd=cwd)
    if ok:
        return []
    return [reason]


def _check_cwd_confinement(
    passport_dict: dict[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
    target: str,
    session_state: dict[str, Any],
) -> list[str]:
    del passport_dict, tool_name, arguments, target, session_state
    # Relative path confinement against the passport cwd is enforced inside
    # proxy._check_resource_scope(..., cwd=passport["cwd"]).
    return []


def _check_side_effect_class(
    passport_dict: dict[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
    target: str,
    session_state: dict[str, Any],
    *,
    policy_metadata: Mapping[str, Any] | None = None,
) -> list[str]:
    del session_state
    _action_class, _resource_family, side_effect_class = _policy_metadata(
        tool_name,
        arguments,
        target,
        policy_metadata,
    )
    allowed_side_effect_classes = list(
        passport_dict.get("allowed_side_effect_classes", []) or []
    )
    if allowed_side_effect_classes and side_effect_class not in allowed_side_effect_classes:
        return [
            (
                f"side_effect_class '{side_effect_class}' not in allowed "
                f"{allowed_side_effect_classes} for tool '{tool_name}'"
            )
        ]
    return []


def _check_per_class_budget(
    passport_dict: dict[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
    target: str,
    session_state: dict[str, Any],
    *,
    policy_metadata: Mapping[str, Any] | None = None,
) -> list[str]:
    _action_class, _resource_family, side_effect_class = _policy_metadata(
        tool_name,
        arguments,
        target,
        policy_metadata,
    )
    per_class_caps = dict(passport_dict.get("max_tool_calls_per_class", {}) or {})
    if side_effect_class not in per_class_caps:
        return []
    current = int(
        (
            session_state.get("tool_call_count_by_class")
            or session_state.get("side_effect_counts")
            or {}
        ).get(side_effect_class, 0)
    )
    cap = int(per_class_caps[side_effect_class])
    if current >= cap:
        return [
            (
                f"per-class budget exhausted for '{side_effect_class}': "
                f"{current}/{cap} (tool '{tool_name}')"
            )
        ]
    return []


def evaluate_native_denials(
    passport_dict: dict[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
    target: str,
    session_state: dict[str, Any],
    policy_metadata: Mapping[str, Any] | None = None,
) -> list[str]:
    """Return the first native denial reason, or [] when native policy allows."""
    checks = (
        _check_delegation_depth,
        _check_forbidden_tools,
        _check_tool_scope,
        _check_session_budget,
        _check_resource_scope,
        _check_cwd_confinement,
    )
    for check in checks:
        reasons = check(passport_dict, tool_name, arguments, target, session_state)
        if reasons:
            return reasons
    for check in (_check_side_effect_class, _check_per_class_budget):
        reasons = check(
            passport_dict,
            tool_name,
            arguments,
            target,
            session_state,
            policy_metadata=policy_metadata,
        )
        if reasons:
            return reasons
    return []
