from __future__ import annotations

import runpy
from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "dependabot-workflow-mirrors.yml"
TESTS_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "tests.yml"
SYNC_SCRIPT = REPO_ROOT / "scripts" / "sync-dependabot-workflow-mirrors.py"
REQUIRED_WORKFLOWS = {
    "codeql.yml",
    "hugo-site.yml",
    "link-check.yml",
    "secret-scan.yml",
    "tests.yml",
    "validate-formats.yml",
}
CHECKOUT_SHA = "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"


def _sync_condition_applies(
    condition: str,
    *,
    actor: str,
    author: str,
    head_repo: str,
    repository: str,
    head_ref: str,
) -> bool:
    predicates = {
        "github.actor == 'dependabot[bot]'": actor == "dependabot[bot]",
        "github.event.pull_request.user.login == 'dependabot[bot]'": (
            author == "dependabot[bot]"
        ),
        "github.event.pull_request.head.repo.full_name == github.repository": (
            head_repo == repository
        ),
        "startsWith(github.event.pull_request.head.ref, "
        "'dependabot/github_actions/')": head_ref.startswith(
            "dependabot/github_actions/"
        ),
    }
    terms = [" ".join(term.split()) for term in condition.split("&&")]
    unknown = set(terms) - predicates.keys()
    assert not unknown, f"unsupported sync condition terms: {sorted(unknown)}"
    return all(predicates[term] for term in terms)


def _contains_secret_reference(value: object) -> bool:
    if isinstance(value, str):
        return "${{ secrets." in value
    if isinstance(value, dict):
        return any(_contains_secret_reference(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_secret_reference(item) for item in value)
    return False


def _e2e_showcase_applies(
    condition: str,
    *,
    event_name: str,
    ref: str,
    recheck_mode: str,
) -> bool:
    normalized = " ".join(condition.split())
    assert normalized == (
        "(github.event_name != 'workflow_dispatch' && "
        "github.ref == 'refs/heads/main') || "
        "(github.event_name == 'workflow_dispatch' && "
        "inputs.recheck_mode == 'full')"
    )
    return (
        event_name != "workflow_dispatch" and ref == "refs/heads/main"
    ) or (event_name == "workflow_dispatch" and recheck_mode == "full")


def test_mirror_sync_workflow_is_bot_only_and_least_privilege() -> None:
    with WORKFLOW.open(encoding="utf-8") as handle:
        workflow = yaml.load(handle, Loader=yaml.BaseLoader)

    assert set(workflow["on"]) == {"pull_request_target"}
    trigger = workflow["on"]["pull_request_target"]
    assert trigger["types"] == ["opened", "reopened", "synchronize"]
    assert trigger["paths"] == [".github/workflows/*.yml"]
    assert workflow["permissions"] == {"actions": "write", "contents": "write"}

    assert set(workflow["jobs"]) == {"sync"}
    job = workflow["jobs"]["sync"]
    condition = " ".join(job["if"].split())
    assert "github.event.pull_request.user.login == 'dependabot[bot]'" in condition
    assert "github.actor" not in condition
    assert "github.event.pull_request.head.repo.full_name == github.repository" in condition
    assert (
        "startsWith(github.event.pull_request.head.ref, 'dependabot/github_actions/')"
        in condition
    )

    checkout = job["steps"][0]
    assert checkout["uses"] == f"actions/checkout@{CHECKOUT_SHA}"
    assert checkout["with"] == {
        "fetch-depth": "0",
        "ref": "${{ github.event.pull_request.base.sha }}",
    }

    run_blocks = "\n".join(step.get("run", "") for step in job["steps"])
    assert "${{ github.event.pull_request" not in run_blocks
    assert "python3 scripts/sync-dependabot-workflow-mirrors.py" in run_blocks
    assert 'git push origin "HEAD:refs/heads/$HEAD_REF"' in run_blocks
    assert "--force" not in run_blocks

    dispatch = job["steps"][-1]
    assert "if" not in dispatch
    assert set(dispatch["env"]["REQUIRED_WORKFLOWS"].split()) == REQUIRED_WORKFLOWS
    assert dispatch["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert dispatch["env"]["PR_NUMBER"] == "${{ github.event.pull_request.number }}"
    assert dispatch["env"]["RUN_ID"] == "${{ github.run_id }}"
    assert 'git ls-remote origin "refs/heads/$HEAD_REF"' in dispatch["run"]
    assert 'if [ "$remote_sha" != "$expected_sha" ]; then' in dispatch["run"]
    assert 'git push origin "$expected_sha:refs/tags/$CHECK_REF"' in dispatch["run"]
    assert 'trap cleanup_check_ref EXIT' in dispatch["run"]
    assert 'gh workflow run "$workflow" --ref "$CHECK_REF"' in dispatch["run"]
    assert 'gh workflow run "$workflow" --ref "$HEAD_REF"' not in dispatch["run"]


def test_sync_runs_for_dependabot_pr_when_human_updates_base() -> None:
    with WORKFLOW.open(encoding="utf-8") as handle:
        workflow = yaml.load(handle, Loader=yaml.BaseLoader)

    condition = workflow["jobs"]["sync"]["if"]
    assert _sync_condition_applies(
        condition,
        actor="maintainer",
        author="dependabot[bot]",
        head_repo="ArdurAI/ardur",
        repository="ArdurAI/ardur",
        head_ref="dependabot/github_actions/actions-checkout-7.0.1",
    )


def test_bot_dispatch_mode_skips_secret_bearing_jobs() -> None:
    with WORKFLOW.open(encoding="utf-8") as handle:
        mirror_workflow = yaml.load(handle, Loader=yaml.BaseLoader)
    with TESTS_WORKFLOW.open(encoding="utf-8") as handle:
        tests_workflow = yaml.load(handle, Loader=yaml.BaseLoader)

    dispatch_config = tests_workflow["on"]["workflow_dispatch"]
    assert isinstance(dispatch_config, dict)
    recheck_mode = dispatch_config["inputs"]["recheck_mode"]
    assert recheck_mode["required"] == "true"
    assert recheck_mode["default"] == "full"
    assert recheck_mode["type"] == "choice"
    assert recheck_mode["options"] == ["full", "secretless"]

    dispatch_run = mirror_workflow["jobs"]["sync"]["steps"][-1]["run"]
    assert 'if [ "$workflow" = "tests.yml" ]; then' in dispatch_run
    assert (
        'gh workflow run "$workflow" --ref "$CHECK_REF" '
        "-f recheck_mode=secretless" in dispatch_run
    )

    secret_jobs = {
        name
        for name, job in tests_workflow["jobs"].items()
        if _contains_secret_reference(job)
    }
    assert secret_jobs == {"e2e-showcase"}
    condition = tests_workflow["jobs"]["e2e-showcase"]["if"]
    assert not _e2e_showcase_applies(
        condition,
        event_name="workflow_dispatch",
        ref="refs/heads/dependabot/github_actions/actions-checkout-7.0.1",
        recheck_mode="secretless",
    )
    assert not _e2e_showcase_applies(
        condition,
        event_name="workflow_dispatch",
        ref="refs/heads/main",
        recheck_mode="secretless",
    )
    assert _e2e_showcase_applies(
        condition,
        event_name="workflow_dispatch",
        ref="refs/heads/manual-validation",
        recheck_mode="full",
    )


def test_every_dispatched_workflow_exposes_its_protected_aggregate() -> None:
    for workflow_name in REQUIRED_WORKFLOWS:
        workflow_path = REPO_ROOT / ".github" / "workflows" / workflow_name
        with workflow_path.open(encoding="utf-8") as handle:
            workflow = yaml.load(handle, Loader=yaml.BaseLoader)

        assert "workflow_dispatch" in workflow["on"], workflow_name
        protected_job = Path(workflow_name).stem
        assert protected_job in workflow["jobs"], workflow_name
        job_condition = workflow["jobs"][protected_job].get("if", "")
        assert "github.event_name == 'pull_request'" not in job_condition, workflow_name


def test_change_validator_allows_only_workflow_sources_and_their_mirrors() -> None:
    validator = runpy.run_path(str(SYNC_SCRIPT))["validate_changed_paths"]

    source = Path(".github/workflows/tests.yml")
    mirror = Path("site/static/repo/.github/workflows/tests.yml")
    assert validator([("M", source)]) == [source]
    assert validator([("M", source), ("M", mirror)]) == [source]


@pytest.mark.parametrize(
    "changes",
    [
        [("A", Path(".github/workflows/new.yml"))],
        [("M", Path("site/scripts/sync_source_docs.py"))],
        [("M", Path(".github/workflows/tests.yaml"))],
        [("D", Path(".github/workflows/tests.yml"))],
        [("M", Path("site/static/repo/.github/workflows/tests.yml"))],
    ],
)
def test_change_validator_fails_closed_for_unexpected_pr_changes(
    changes: list[tuple[str, Path]],
) -> None:
    validator = runpy.run_path(str(SYNC_SCRIPT))["validate_changed_paths"]

    with pytest.raises(ValueError, match="Dependabot workflow mirror sync refused"):
        validator(changes)
