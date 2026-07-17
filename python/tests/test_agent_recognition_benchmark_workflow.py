from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "agent-recognition-benchmark.yml"
WORKFLOW_MIRROR = REPO_ROOT / "site" / "static" / "repo" / WORKFLOW.relative_to(REPO_ROOT)


def test_required_ci_profile_always_supplies_reviewed_budget() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "BUDGET_FILE: go/pkg/kernelcapture/testdata/agent-recognition-benchmark-budget-v0.2.json" in workflow
    assert 'if [ "$BENCHMARK_PROFILE" = "ci" ]; then' in workflow
    assert 'args+=(--budget "$BUDGET_FILE")' in workflow
    assert '[ -f "$BUDGET_FILE" ]' not in workflow


def test_published_recognition_workflow_matches_authoritative_workflow() -> None:
    assert WORKFLOW_MIRROR.read_text(encoding="utf-8") == WORKFLOW.read_text(encoding="utf-8")
