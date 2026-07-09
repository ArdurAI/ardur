from __future__ import annotations

import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
GO_MOD = REPO_ROOT / "go" / "go.mod"
WORKFLOWS = (
    REPO_ROOT / ".github" / "workflows" / "tests.yml",
    REPO_ROOT / ".github" / "workflows" / "kernel-enforce.yml",
)
WORKFLOW_MIRRORS = tuple(
    REPO_ROOT / "site" / "static" / "repo" / workflow.relative_to(REPO_ROOT)
    for workflow in WORKFLOWS
)
DEMO_DOCKERFILE = REPO_ROOT / "docs" / "demo" / "enforce-e2e" / "Dockerfile"


def _go_module_version() -> str:
    match = re.search(
        r"^go (?P<version>\d+\.\d+\.\d+)$",
        GO_MOD.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert match, "go/go.mod must declare an exact Go toolchain version"
    return match.group("version")


def _workflow_versions(workflow: Path) -> list[str]:
    return re.findall(
        r"^\s*go-version:\s*['\"]?(?P<version>\d+\.\d+\.\d+)['\"]?\s*$",
        workflow.read_text(encoding="utf-8"),
        re.MULTILINE,
    )


def test_go_toolchain_versions_stay_in_lockstep() -> None:
    """Keep the module, CI workflows, published mirrors, and demo builder aligned."""

    expected_version = _go_module_version()

    for workflow, mirror in zip(WORKFLOWS, WORKFLOW_MIRRORS, strict=True):
        assert _workflow_versions(workflow), (
            f"expected at least one Go setup in {workflow.relative_to(REPO_ROOT)}"
        )
        assert set(_workflow_versions(workflow)) == {expected_version}
        assert mirror.read_text(encoding="utf-8") == workflow.read_text(
            encoding="utf-8"
        )

    dockerfile = DEMO_DOCKERFILE.read_text(encoding="utf-8")
    assert f"FROM golang:{expected_version}-bookworm AS build" in dockerfile
