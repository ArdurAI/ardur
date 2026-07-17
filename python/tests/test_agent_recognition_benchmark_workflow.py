from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "agent-recognition-benchmark.yml"
WORKFLOW_MIRROR = REPO_ROOT / "site" / "static" / "repo" / WORKFLOW.relative_to(REPO_ROOT)
BUDGET = REPO_ROOT / "go" / "pkg" / "kernelcapture" / "testdata" / "agent-recognition-benchmark-budget-v0.3.json"


def test_automatic_ci_requires_v3_budget_and_manual_ci_is_explicit_evidence_only() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert BUDGET.is_file()
    assert "BUDGET_FILE: go/pkg/kernelcapture/testdata/agent-recognition-benchmark-budget-v0.3.json" in workflow
    assert "EVIDENCE_ONLY: ${{ github.event_name == 'workflow_dispatch' && inputs.profile == 'ci' }}" in workflow
    assert "if: github.event_name != 'workflow_dispatch'" in workflow
    assert 'test -f "$BUDGET_FILE"' in workflow
    assert 'if [ "$BENCHMARK_PROFILE" = "ci" ] && [ "$EVIDENCE_ONLY" != "true" ]; then' in workflow
    assert 'args+=(--budget "$BUDGET_FILE")' in workflow


def test_workflow_builds_and_records_an_exact_same_vm_reference() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "fetch-depth: 0" in workflow
    assert 'reference_sha="$(git merge-base "$SOURCE_SHA" origin/dev)"' in workflow
    assert "ref: ${{ steps.reference.outputs.source_sha }}" in workflow
    assert "path: reference" in workflow
    assert 'GOWORK: "off"' in workflow
    assert 'if [ "$(git rev-parse HEAD)" != "$EXPECTED_REFERENCE_SOURCE_SHA" ]; then' in workflow
    assert 'if [ -n "$(git status --porcelain --untracked-files=all)" ]; then' in workflow
    assert 'reference_build_root="$(mktemp -d "$RUNNER_TEMP/ardur-reference-build.XXXXXX")"' in workflow
    assert 'GOMODCACHE="$reference_build_root/modcache" GOCACHE="$reference_build_root/buildcache" go mod download' in workflow
    assert 'GOMODCACHE="$reference_build_root/modcache" GOCACHE="$reference_build_root/buildcache" go mod verify' in workflow
    assert 'go build -trimpath -o "$reference_build_root/ardur-kernelcaptured-reference" ./cmd/ardur-kernelcaptured' in workflow
    assert "REFERENCE_DAEMON_PATH: ${{ steps.reference_build.outputs.daemon_path }}" in workflow
    assert '--reference-daemon-bin "$REFERENCE_DAEMON_PATH"' in workflow
    assert '--reference-source-sha "$REFERENCE_SOURCE_SHA"' in workflow

    candidate_tests = workflow.index("- name: Run race-sensitive benchmark tests")
    reference_checkout = workflow.index("- name: Check out exact reference source")
    reference_build = workflow.index("- name: Build exact reference daemon")
    benchmark = workflow.index("- name: Run paired recognition benchmark")
    assert candidate_tests < reference_checkout < reference_build < benchmark


def test_published_recognition_workflow_matches_authoritative_workflow() -> None:
    assert WORKFLOW_MIRROR.read_text(encoding="utf-8") == WORKFLOW.read_text(encoding="utf-8")
