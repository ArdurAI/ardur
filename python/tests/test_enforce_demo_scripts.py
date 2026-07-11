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
    assert "if ! ardur run" in script
    assert 'cat "$OUT/ardur-run.log"' in script
    assert '"/out/home-${MODE}"' not in script
    assert 'AGENT: RESULT=DENIED_EPERM' in script
    assert 'tool calls[[:space:]]+1 evaluated' in script
    assert 'receipts[[:space:]]+1 signed' in script
    assert 'agent exit[[:space:]]+0' in script


def test_kvm_metric_proof_uses_strict_bpf_launch_handoff() -> None:
    wrapper = VNG_METRIC_SCRIPT.read_text(encoding="utf-8")
    workflow = KERNEL_WORKFLOW.read_text(encoding="utf-8")

    assert 'run.sh" enforce' in wrapper
    assert "ci-vng-observability-gap.sh" in workflow
    assert "verify strict ardur-run E2E" in workflow
    assert "PTRACE_EVENT_EXEC" in workflow


def test_systemd_profile_allows_seccomp_control_plane_socket_emulation() -> None:
    unit = SYSTEMD_UNIT.read_text(encoding="utf-8")

    ambient = next(line for line in unit.splitlines() if line.startswith("AmbientCapabilities="))
    bounding = next(line for line in unit.splitlines() if line.startswith("CapabilityBoundingSet="))
    syscall_filter = next(line for line in unit.splitlines() if line.startswith("SystemCallFilter="))

    assert "CAP_SYS_PTRACE" in ambient.split("=", 1)[1].split()
    assert "CAP_SYS_PTRACE" in bounding.split("=", 1)[1].split()
    assert "pidfd_open" in syscall_filter.split("=", 1)[1].split()
    assert "pidfd_getfd" in syscall_filter.split("=", 1)[1].split()
