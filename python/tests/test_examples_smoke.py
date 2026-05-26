from __future__ import annotations

import json
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLES_DIR = REPO_ROOT / "examples"


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_mission_examples_are_valid_offline_fixtures() -> None:
    """Keep the checked-in, no-key mission examples runnable as CI fixtures."""

    mission_files = sorted((EXAMPLES_DIR / "missions").glob("*.json"))
    assert mission_files, "expected committed mission JSON examples"

    required_fields = {
        "agent_id",
        "mission",
        "allowed_tools",
        "forbidden_tools",
        "resource_scope",
        "max_tool_calls",
        "max_duration_s",
        "delegation_allowed",
        "max_delegation_depth",
    }

    for path in mission_files:
        data = _read_json(path)
        missing_fields = required_fields.difference(data)
        assert not missing_fields, f"{path.relative_to(REPO_ROOT)} missing {sorted(missing_fields)}"

        assert isinstance(data["agent_id"], str) and data["agent_id"].strip()
        assert isinstance(data["mission"], str) and data["mission"].strip()
        assert isinstance(data["allowed_tools"], list)
        assert all(isinstance(tool, str) and tool for tool in data["allowed_tools"])
        assert isinstance(data["forbidden_tools"], list)
        assert all(isinstance(tool, str) and tool for tool in data["forbidden_tools"])
        assert isinstance(data["resource_scope"], list)
        assert all(isinstance(scope, str) for scope in data["resource_scope"])
        assert isinstance(data["max_tool_calls"], int) and data["max_tool_calls"] > 0
        assert isinstance(data["max_duration_s"], int) and data["max_duration_s"] > 0
        assert isinstance(data["delegation_allowed"], bool)
        assert isinstance(data["max_delegation_depth"], int) and data["max_delegation_depth"] >= 0

        if not data["delegation_allowed"]:
            assert data["max_delegation_depth"] == 0


def test_examples_ci_claim_matches_repo_wide_python_workflow() -> None:
    """Document the chosen source of truth: repo-wide Python CI, not a dedicated workflow."""

    tests_workflow = (REPO_ROOT / ".github/workflows/tests.yml").read_text(encoding="utf-8")
    examples_readme = (EXAMPLES_DIR / "README.md").read_text(encoding="utf-8")

    assert "python -m pytest tests/ -q --tb=short" in tests_workflow
    assert not (REPO_ROOT / ".github/workflows/examples-smoke.yml").exists()
    assert "python/tests/test_examples_smoke.py" in examples_readme
    assert ".github/workflows/examples-smoke.yml" in examples_readme
    assert "live-provider demos" in examples_readme
