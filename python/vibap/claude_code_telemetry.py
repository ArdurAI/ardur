"""Claude Code tool → 11 declared-telemetry fields mapper.

This module is pure data + pure functions. No I/O, no side effects. It
exists so the proxy's fail-closed gate (proxy.DECLARED_TELEMETRY_FIELDS)
can be satisfied for every Claude Code tool call.

The mapper output is the ``arguments`` dict that goes into a PolicyEvent.
The 11 telemetry fields are INJECTED on top of the original tool input —
the gate (proxy._missing_declared_telemetry) reads them from
``arguments``, NOT from PolicyEvent first-class fields.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

ToolMapper = Callable[[Mapping[str, Any]], dict[str, Any]]

# Mirror of proxy.DECLARED_TELEMETRY_FIELDS. Kept as a local constant so this
# module has zero non-trivial imports and can be tested in isolation. The
# test test_declared_telemetry_fields_match_proxy_contract verifies the two
# stay in sync.
DECLARED_TELEMETRY_FIELDS: tuple[str, ...] = (
    "action_class",
    "tool_name",
    "target",
    "resource_family",
    "content_class",
    "content_provenance",
    "side_effect_class",
    "visibility",
    "sensitivity",
    "instruction_bearing",
    "budget_delta",
    "envelope_signature_valid",
    "observed_manifest_digest",
)


_VISIBILITY_FULL = "full"  # proxy._missing_declared_telemetry requires this exact string.
_PROVENANCE = "claude_code_tool_input"
_UNKNOWN_TARGET = "<unknown>"


def _safe_str(value: Any, *, default: str = "") -> str:
    """Coerce ``value`` to a string, treating None as the default.

    ``str(None)`` returns the literal string ``"None"`` which passes the
    proxy's non-empty gate but produces misleading audit receipts
    (``target="None"`` instead of ``target="<unknown>"``). This helper
    keeps the audit trail honest about missing fields.
    """
    if value is None:
        return default
    return str(value)


def _read_mapping(tool_input: Mapping[str, Any]) -> dict[str, Any]:
    file_path = _safe_str(tool_input.get("file_path")).strip()
    return {
        "action_class": "read",
        "target": file_path or _UNKNOWN_TARGET,
        "resource_family": "filesystem",
        "content_class": "user_input",
        "content_provenance": _PROVENANCE,
        "side_effect_class": "none",
        "visibility": _VISIBILITY_FULL,
        "sensitivity": "low",
        "instruction_bearing": False,
        "budget_delta": 1,
    }


def _filesystem_write_mapping(tool_input: Mapping[str, Any]) -> dict[str, Any]:
    """Shared mapping for Write and Edit. Both are bounded filesystem
    writes with ``file_path`` as the target.

    If Write or Edit ever need to diverge (e.g. different sensitivity for
    in-place mutation vs. full overwrite), split into two functions and
    update ``_TOOL_MAPPERS`` to point at them separately.
    """
    file_path = _safe_str(tool_input.get("file_path")).strip()
    return {
        "action_class": "write",
        "target": file_path or _UNKNOWN_TARGET,
        "resource_family": "filesystem",
        "content_class": "user_input",
        "content_provenance": _PROVENANCE,
        "side_effect_class": "filesystem_write",
        "visibility": _VISIBILITY_FULL,
        "sensitivity": "medium",
        "instruction_bearing": False,
        "budget_delta": 2,
    }


def _filesystem_search_mapping(tool_input: Mapping[str, Any]) -> dict[str, Any]:
    """Shared mapping for Glob and Grep. Both are read-only filesystem
    searches with target derived from ``path:pattern``."""
    path = _safe_str(tool_input.get("path"), default="<cwd>") or "<cwd>"
    pattern = _safe_str(tool_input.get("pattern"))
    return {
        "action_class": "search",
        "target": f"{path}:{pattern}",
        "resource_family": "filesystem",
        "content_class": "user_input",
        "content_provenance": _PROVENANCE,
        "side_effect_class": "none",
        "visibility": _VISIBILITY_FULL,
        "sensitivity": "low",
        "instruction_bearing": False,
        "budget_delta": 1,
    }


def _bash_mapping(tool_input: Mapping[str, Any]) -> dict[str, Any]:
    command = _safe_str(tool_input.get("command"))
    return {
        "action_class": "execute",
        "target": command or _UNKNOWN_TARGET,
        "resource_family": "shell",
        "content_class": "user_instruction",
        "content_provenance": _PROVENANCE,
        "side_effect_class": "process_launch",
        "visibility": _VISIBILITY_FULL,
        "sensitivity": "high",
        "instruction_bearing": True,
        "budget_delta": 5,
    }


def _agent_dispatch_mapping(tool_input: Mapping[str, Any]) -> dict[str, Any]:
    """Map Claude Code subagent dispatch tools.

    Claude Code has exposed this surface as both ``Task`` and ``Agent`` across
    versions/contexts. Treat both as the same governed action so subagent
    launches are always classified as agent dispatches instead of falling back
    to the generic MCP/external-tool mapper.
    """
    subagent_type = (
        _safe_str(tool_input.get("subagent_type"))
        or _safe_str(tool_input.get("agent_type"))
        or _safe_str(tool_input.get("type"))
        or "<unknown>"
    )
    description = (
        _safe_str(tool_input.get("description"))
        or _safe_str(tool_input.get("prompt"))
        or _safe_str(tool_input.get("task"))
        or _safe_str(tool_input.get("request"))
    )[:64]
    return {
        "action_class": "dispatch",
        "target": f"{subagent_type}:{description}",
        "resource_family": "agent",
        "content_class": "user_instruction",
        "content_provenance": _PROVENANCE,
        "side_effect_class": "subagent_launch",
        "visibility": _VISIBILITY_FULL,
        "sensitivity": "medium",
        "instruction_bearing": True,
        "budget_delta": 10,
    }


def _webfetch_mapping(tool_input: Mapping[str, Any]) -> dict[str, Any]:
    url = _safe_str(tool_input.get("url"))
    return {
        "action_class": "fetch",
        "target": url or _UNKNOWN_TARGET,
        "resource_family": "network",
        "content_class": "user_input",
        "content_provenance": _PROVENANCE,
        "side_effect_class": "network_read",
        "visibility": _VISIBILITY_FULL,
        "sensitivity": "medium",
        "instruction_bearing": False,
        "budget_delta": 3,
    }


def _websearch_mapping(tool_input: Mapping[str, Any]) -> dict[str, Any]:
    query = _safe_str(tool_input.get("query"))[:128]
    return {
        "action_class": "search",
        "target": query or _UNKNOWN_TARGET,
        "resource_family": "network",
        "content_class": "user_input",
        "content_provenance": _PROVENANCE,
        "side_effect_class": "network_read",
        "visibility": _VISIBILITY_FULL,
        "sensitivity": "low",
        "instruction_bearing": False,
        "budget_delta": 2,
    }


def _notebook_edit_mapping(tool_input: Mapping[str, Any]) -> dict[str, Any]:
    notebook_path = _safe_str(tool_input.get("notebook_path")) or _UNKNOWN_TARGET
    cell_id = _safe_str(tool_input.get("cell_id"))
    return {
        "action_class": "write",
        "target": f"{notebook_path}#{cell_id}",
        "resource_family": "filesystem",
        "content_class": "user_input",
        "content_provenance": _PROVENANCE,
        "side_effect_class": "filesystem_write",
        "visibility": _VISIBILITY_FULL,
        "sensitivity": "medium",
        "instruction_bearing": False,
        "budget_delta": 2,
    }


def _mcp_fallback_mapping(tool_input: Mapping[str, Any]) -> dict[str, Any]:
    target = (
        _safe_str(tool_input.get("uri"))
        or _safe_str(tool_input.get("name"))
        or "<mcp>"
    )
    return {
        "action_class": "invoke",
        "target": target,
        "resource_family": "external_tool",
        "content_class": "user_input",
        "content_provenance": _PROVENANCE,
        "side_effect_class": "network_read",
        "visibility": _VISIBILITY_FULL,
        "sensitivity": "medium",
        "instruction_bearing": False,
        "budget_delta": 3,
    }


_TOOL_MAPPERS: dict[str, ToolMapper] = {
    "Read": _read_mapping,
    "Write": _filesystem_write_mapping,
    "Edit": _filesystem_write_mapping,
    "Glob": _filesystem_search_mapping,
    "Grep": _filesystem_search_mapping,
    "Bash": _bash_mapping,
    "Task": _agent_dispatch_mapping,
    "Agent": _agent_dispatch_mapping,
    "WebFetch": _webfetch_mapping,
    "WebSearch": _websearch_mapping,
    "NotebookEdit": _notebook_edit_mapping,
}


def map_tool_call(*, tool_name: str, tool_input: Mapping[str, Any]) -> dict[str, Any]:
    """Map a Claude Code hook payload to a PolicyEvent ``arguments`` dict.

    Returns a new dict containing the original ``tool_input`` keys PLUS
    the declared-telemetry fields. ``tool_name`` is also injected so
    proxy.DECLARED_TELEMETRY_FIELDS is fully satisfied.

    Unknown tools (e.g. MCP tools following the ``mcp__<server>__<tool>``
    naming convention) fall back to the MCP mapper rather than raising.
    """
    mapper = _TOOL_MAPPERS.get(tool_name, _mcp_fallback_mapping)
    arguments: dict[str, Any] = dict(tool_input)
    arguments.update(mapper(tool_input))
    arguments["tool_name"] = tool_name
    arguments.setdefault("envelope_signature_valid", True)
    arguments.setdefault("observed_manifest_digest", "not-observed")
    return arguments
