"""Telemetry mapper tests for the Claude Code hook."""

from __future__ import annotations

import pytest

from vibap.claude_code_telemetry import (
    DECLARED_TELEMETRY_FIELDS,
    map_tool_call,
)


# Sanity: the local tuple must match proxy.py's contract exactly.
def test_declared_telemetry_fields_match_proxy_contract() -> None:
    from vibap.proxy import DECLARED_TELEMETRY_FIELDS as PROXY_FIELDS
    assert DECLARED_TELEMETRY_FIELDS == PROXY_FIELDS


def test_read_tool_maps_to_filesystem_read_low_sensitivity() -> None:
    arguments = map_tool_call(
        tool_name="Read",
        tool_input={"file_path": "/tmp/x.txt"},
    )
    assert arguments["tool_name"] == "Read"
    assert arguments["action_class"] == "read"
    assert arguments["target"] == "/tmp/x.txt"
    assert arguments["resource_family"] == "filesystem"
    assert arguments["content_class"] == "user_input"
    assert arguments["content_provenance"] == "claude_code_tool_input"
    assert arguments["side_effect_class"] == "none"
    assert arguments["visibility"] == "full"
    assert arguments["sensitivity"] == "low"
    assert arguments["instruction_bearing"] is False
    assert arguments["budget_delta"] == 1
    # Original input keys must be preserved alongside telemetry.
    assert arguments["file_path"] == "/tmp/x.txt"


def test_all_eleven_declared_fields_are_present_for_read() -> None:
    arguments = map_tool_call(
        tool_name="Read",
        tool_input={"file_path": "/tmp/x.txt"},
    )
    for field in DECLARED_TELEMETRY_FIELDS:
        assert field in arguments, f"missing {field}"
        value = arguments[field]
        assert value not in (None, ""), f"empty {field}"


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------

def test_write_tool_maps_to_filesystem_write_with_side_effect() -> None:
    arguments = map_tool_call(
        tool_name="Write",
        tool_input={"file_path": "/tmp/out.txt", "content": "hello"},
    )
    assert arguments["action_class"] == "write"
    assert arguments["target"] == "/tmp/out.txt"
    assert arguments["resource_family"] == "filesystem"
    assert arguments["side_effect_class"] == "filesystem_write"
    assert arguments["sensitivity"] == "medium"
    assert arguments["instruction_bearing"] is False
    assert arguments["budget_delta"] == 2
    assert arguments["content"] == "hello"  # original input preserved


# ---------------------------------------------------------------------------
# Edit
# ---------------------------------------------------------------------------

def test_edit_tool_maps_to_filesystem_write_with_side_effect() -> None:
    arguments = map_tool_call(
        tool_name="Edit",
        tool_input={"file_path": "/src/main.py", "old_string": "foo", "new_string": "bar"},
    )
    assert arguments["action_class"] == "write"
    assert arguments["target"] == "/src/main.py"
    assert arguments["resource_family"] == "filesystem"
    assert arguments["side_effect_class"] == "filesystem_write"
    assert arguments["sensitivity"] == "medium"
    assert arguments["instruction_bearing"] is False
    assert arguments["budget_delta"] == 2
    assert arguments["old_string"] == "foo"  # original input preserved


# ---------------------------------------------------------------------------
# Glob
# ---------------------------------------------------------------------------

def test_glob_tool_maps_to_filesystem_search_no_side_effect() -> None:
    arguments = map_tool_call(
        tool_name="Glob",
        tool_input={"path": "/src", "pattern": "**/*.py"},
    )
    assert arguments["action_class"] == "search"
    assert arguments["target"] == "/src:**/*.py"
    assert arguments["resource_family"] == "filesystem"
    assert arguments["side_effect_class"] == "none"
    assert arguments["sensitivity"] == "low"
    assert arguments["instruction_bearing"] is False
    assert arguments["budget_delta"] == 1
    assert arguments["pattern"] == "**/*.py"  # original input preserved


def test_glob_tool_uses_cwd_placeholder_when_path_absent() -> None:
    arguments = map_tool_call(
        tool_name="Glob",
        tool_input={"pattern": "*.txt"},
    )
    assert arguments["target"] == "<cwd>:*.txt"


# ---------------------------------------------------------------------------
# Grep
# ---------------------------------------------------------------------------

def test_grep_tool_maps_to_filesystem_search_no_side_effect() -> None:
    arguments = map_tool_call(
        tool_name="Grep",
        tool_input={"path": "/src", "pattern": "def foo"},
    )
    assert arguments["action_class"] == "search"
    assert arguments["target"] == "/src:def foo"
    assert arguments["resource_family"] == "filesystem"
    assert arguments["side_effect_class"] == "none"
    assert arguments["sensitivity"] == "low"
    assert arguments["instruction_bearing"] is False
    assert arguments["budget_delta"] == 1
    assert arguments["pattern"] == "def foo"  # original input preserved


def test_grep_tool_uses_cwd_placeholder_when_path_absent() -> None:
    arguments = map_tool_call(
        tool_name="Grep",
        tool_input={"pattern": "import os"},
    )
    assert arguments["target"] == "<cwd>:import os"


# ---------------------------------------------------------------------------
# Bash
# ---------------------------------------------------------------------------

def test_bash_tool_maps_to_shell_execute_high_sensitivity_instruction_bearing() -> None:
    arguments = map_tool_call(
        tool_name="Bash",
        tool_input={"command": "ls -la /tmp"},
    )
    assert arguments["action_class"] == "execute"
    assert arguments["target"] == "ls -la /tmp"
    assert arguments["resource_family"] == "shell"
    assert arguments["content_class"] == "user_instruction"
    assert arguments["side_effect_class"] == "process_launch"
    assert arguments["sensitivity"] == "high"
    assert arguments["instruction_bearing"] is True
    assert arguments["budget_delta"] == 5
    assert arguments["command"] == "ls -la /tmp"  # original input preserved


def test_bash_tool_keeps_full_command_as_policy_target() -> None:
    long_command = "echo " + "x" * 200
    arguments = map_tool_call(
        tool_name="Bash",
        tool_input={"command": long_command},
    )
    assert arguments["target"] == long_command


# ---------------------------------------------------------------------------
# Task
# ---------------------------------------------------------------------------

def test_task_tool_maps_to_agent_dispatch_medium_sensitivity_instruction_bearing() -> None:
    arguments = map_tool_call(
        tool_name="Task",
        tool_input={"subagent_type": "general-purpose", "description": "Summarise the repo"},
    )
    assert arguments["action_class"] == "dispatch"
    assert arguments["target"] == "general-purpose:Summarise the repo"
    assert arguments["resource_family"] == "agent"
    assert arguments["content_class"] == "user_instruction"
    assert arguments["side_effect_class"] == "subagent_launch"
    assert arguments["sensitivity"] == "medium"
    assert arguments["instruction_bearing"] is True
    assert arguments["budget_delta"] == 10
    assert arguments["description"] == "Summarise the repo"  # original input preserved


def test_agent_tool_maps_to_agent_dispatch_alias() -> None:
    arguments = map_tool_call(
        tool_name="Agent",
        tool_input={
            "agent_type": "general-purpose",
            "description": "Read README title",
            "prompt": "Read README.md and report the title",
        },
    )
    assert arguments["action_class"] == "dispatch"
    assert arguments["target"] == "general-purpose:Read README title"
    assert arguments["resource_family"] == "agent"
    assert arguments["side_effect_class"] == "subagent_launch"
    assert arguments["instruction_bearing"] is True
    assert arguments["budget_delta"] == 10
    assert arguments["prompt"] == "Read README.md and report the title"


def test_task_tool_truncates_description_to_64_chars() -> None:
    long_desc = "Do this thing " + "y" * 100
    arguments = map_tool_call(
        tool_name="Task",
        tool_input={"subagent_type": "general-purpose", "description": long_desc},
    )
    expected_target = "general-purpose:" + long_desc[:64]
    assert arguments["target"] == expected_target


# ---------------------------------------------------------------------------
# WebFetch
# ---------------------------------------------------------------------------

def test_webfetch_tool_maps_to_network_fetch_medium_sensitivity() -> None:
    arguments = map_tool_call(
        tool_name="WebFetch",
        tool_input={"url": "https://example.com/page"},
    )
    assert arguments["action_class"] == "fetch"
    assert arguments["target"] == "https://example.com/page"
    assert arguments["resource_family"] == "network"
    assert arguments["content_class"] == "user_input"
    assert arguments["side_effect_class"] == "network_read"
    assert arguments["sensitivity"] == "medium"
    assert arguments["instruction_bearing"] is False
    assert arguments["budget_delta"] == 3
    assert arguments["url"] == "https://example.com/page"  # original input preserved


# ---------------------------------------------------------------------------
# WebSearch
# ---------------------------------------------------------------------------

def test_websearch_tool_maps_to_network_search_low_sensitivity() -> None:
    arguments = map_tool_call(
        tool_name="WebSearch",
        tool_input={"query": "python typing hints"},
    )
    assert arguments["action_class"] == "search"
    assert arguments["target"] == "python typing hints"
    assert arguments["resource_family"] == "network"
    assert arguments["content_class"] == "user_input"
    assert arguments["side_effect_class"] == "network_read"
    assert arguments["sensitivity"] == "low"
    assert arguments["instruction_bearing"] is False
    assert arguments["budget_delta"] == 2
    assert arguments["query"] == "python typing hints"  # original input preserved


def test_websearch_tool_truncates_query_to_128_chars() -> None:
    long_query = "search " + "z" * 200
    arguments = map_tool_call(
        tool_name="WebSearch",
        tool_input={"query": long_query},
    )
    assert len(arguments["target"]) == 128
    assert arguments["target"] == long_query[:128]


# ---------------------------------------------------------------------------
# NotebookEdit
# ---------------------------------------------------------------------------

def test_notebookedit_tool_maps_to_filesystem_write_with_cell_target() -> None:
    arguments = map_tool_call(
        tool_name="NotebookEdit",
        tool_input={"notebook_path": "/work/analysis.ipynb", "cell_id": "cell-42"},
    )
    assert arguments["action_class"] == "write"
    assert arguments["target"] == "/work/analysis.ipynb#cell-42"
    assert arguments["resource_family"] == "filesystem"
    assert arguments["side_effect_class"] == "filesystem_write"
    assert arguments["sensitivity"] == "medium"
    assert arguments["instruction_bearing"] is False
    assert arguments["budget_delta"] == 2
    assert arguments["notebook_path"] == "/work/analysis.ipynb"  # original input preserved


def test_notebookedit_tool_target_has_trailing_hash_when_cell_id_absent() -> None:
    arguments = map_tool_call(
        tool_name="NotebookEdit",
        tool_input={"notebook_path": "/work/analysis.ipynb"},
    )
    assert arguments["target"] == "/work/analysis.ipynb#"


# ---------------------------------------------------------------------------
# MCP fallback
# ---------------------------------------------------------------------------

def test_unknown_tool_uses_mcp_fallback_and_preserves_input() -> None:
    arguments = map_tool_call(
        tool_name="mcp__github__create_issue",
        tool_input={"title": "bug", "body": "broken", "repo": "owner/r"},
    )
    assert arguments["tool_name"] == "mcp__github__create_issue"
    assert arguments["action_class"] == "invoke"
    assert arguments["resource_family"] == "external_tool"
    assert arguments["side_effect_class"] == "network_read"
    assert arguments["sensitivity"] == "medium"
    assert arguments["budget_delta"] == 3
    assert arguments["title"] == "bug"  # original input preserved


def test_mcp_fallback_uses_uri_as_target_when_present() -> None:
    arguments = map_tool_call(
        tool_name="mcp__custom__read",
        tool_input={"uri": "custom://resource/path"},
    )
    assert arguments["target"] == "custom://resource/path"


def test_mcp_fallback_uses_name_as_target_when_uri_absent() -> None:
    arguments = map_tool_call(
        tool_name="mcp__custom__op",
        tool_input={"name": "my-resource"},
    )
    assert arguments["target"] == "my-resource"


def test_mcp_fallback_uses_mcp_placeholder_when_no_uri_or_name() -> None:
    arguments = map_tool_call(
        tool_name="mcp__custom__op",
        tool_input={"value": 42},
    )
    assert arguments["target"] == "<mcp>"


# ---------------------------------------------------------------------------
# Cross-mapper completeness gate
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "tool_name,tool_input",
    [
        ("Read", {"file_path": "/tmp/x.txt"}),
        ("Write", {"file_path": "/tmp/x.txt", "content": "y"}),
        ("Edit", {"file_path": "/tmp/x.txt", "old_string": "a", "new_string": "b"}),
        ("Glob", {"path": "/src", "pattern": "**/*.py"}),
        ("Grep", {"path": "/src", "pattern": "foo"}),
        ("Bash", {"command": "ls"}),
        ("Task", {"subagent_type": "general-purpose", "description": "do x"}),
        ("WebFetch", {"url": "https://example.com"}),
        ("WebSearch", {"query": "x"}),
        ("NotebookEdit", {"notebook_path": "/n.ipynb", "cell_id": "c1"}),
        ("mcp__custom__op", {"name": "x"}),
    ],
)
def test_every_mapper_emits_all_eleven_declared_fields(tool_name, tool_input) -> None:
    arguments = map_tool_call(tool_name=tool_name, tool_input=tool_input)
    for field in DECLARED_TELEMETRY_FIELDS:
        assert field in arguments, f"missing {field} for {tool_name}"
        value = arguments[field]
        # ``not in (None, "")`` accepts False and 0 (legitimate values for
        # instruction_bearing / budget_delta) but rejects None and empty
        # string — matching proxy._missing_declared_telemetry semantics.
        assert value not in (None, ""), f"empty {field} for {tool_name}"


@pytest.mark.parametrize(
    "tool_name,tool_input",
    [
        ("Bash", {"command": None}),
        ("WebFetch", {"url": None}),
        ("WebSearch", {"query": None}),
        ("NotebookEdit", {"notebook_path": None, "cell_id": None}),
    ],
)
def test_none_valued_inputs_yield_unknown_target_not_string_None(tool_name, tool_input) -> None:
    """A caller passing ``None`` for a target-deriving field must produce a
    ``<unknown>``-style target, not the literal string ``"None"`` that
    ``str(None)`` would otherwise emit. Misleading audit receipts are worse
    than explicitly missing ones."""
    arguments = map_tool_call(tool_name=tool_name, tool_input=tool_input)
    assert "None" not in arguments["target"], (
        f"target for {tool_name} contains literal 'None': {arguments['target']!r}"
    )
