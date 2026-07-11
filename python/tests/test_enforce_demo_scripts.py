from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_SCRIPT = REPO_ROOT / "docs" / "demo" / "enforce-e2e" / "run.sh"
VNG_METRIC_SCRIPT = (
    REPO_ROOT / "docs" / "demo" / "enforce-e2e" / "ci-vng-observability-gap.sh"
)
KERNEL_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "kernel-enforce.yml"
SYSTEMD_UNIT = REPO_ROOT / "packaging" / "systemd" / "ardur-kernelcaptured.service"


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


def test_systemd_profile_allows_seccomp_control_plane_socket_emulation() -> None:
    unit = SYSTEMD_UNIT.read_text(encoding="utf-8")

    ambient = next(line for line in unit.splitlines() if line.startswith("AmbientCapabilities="))
    bounding = next(line for line in unit.splitlines() if line.startswith("CapabilityBoundingSet="))
    syscall_filter = next(line for line in unit.splitlines() if line.startswith("SystemCallFilter="))

    assert "CAP_SYS_PTRACE" in ambient.split("=", 1)[1].split()
    assert "CAP_SYS_PTRACE" in bounding.split("=", 1)[1].split()
    assert "pidfd_open" in syscall_filter.split("=", 1)[1].split()
    assert "pidfd_getfd" in syscall_filter.split("=", 1)[1].split()
