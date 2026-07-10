from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_SCRIPT = REPO_ROOT / "docs" / "demo" / "enforce-e2e" / "run.sh"
VNG_METRIC_SCRIPT = (
    REPO_ROOT / "docs" / "demo" / "enforce-e2e" / "ci-vng-observability-gap.sh"
)
KERNEL_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "kernel-enforce.yml"


def test_bpf_demo_uses_writable_run_home_and_propagates_failures() -> None:
    script = RUN_SCRIPT.read_text(encoding="utf-8")

    assert "set -euo pipefail" in script
    assert 'RUN_HOME="${OUT_BASE}/home-${MODE}"' in script
    assert '--home "$RUN_HOME"' in script
    assert 'verify-observability-gap.py" "$RUN_HOME"' in script
    assert 'python3 - "$RUN_HOME"' in script
    assert 'trap cleanup EXIT' in script
    assert '"/out/home-${MODE}"' not in script


def test_kvm_metric_proof_uses_permissive_data_plane() -> None:
    wrapper = VNG_METRIC_SCRIPT.read_text(encoding="utf-8")
    workflow = KERNEL_WORKFLOW.read_text(encoding="utf-8")

    assert 'run.sh" permissive' in wrapper
    assert "ci-vng-observability-gap.sh" in workflow
    assert "ci-vng-enforce.sh" not in workflow
