"""Integration + unit tests for the ``ardur run`` governance bridge.

The headline test (:func:`test_ardur_run_governs_launched_agent_zero_setup`)
proves the bridge's contract end to end: ``ardur run`` of a stand-in agent that
makes a PERMIT-able and a DENY-able tool call results in a started session,
evaluated calls, a verifiable signed receipt chain, and a verifiable behavioral
attestation — with **zero** manual ``ardur protect`` setup and no edit to the
user's ``~/.claude/settings.json``.
"""

from __future__ import annotations

from argparse import Namespace
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path

import pytest

from vibap import kernel_correlation as kc
from vibap import run_bridge
from vibap.attestation import ATTESTATION_SCHEMA_VERSION, verify_attestation
from vibap.passport import load_public_key
from vibap.receipt import RECEIPT_SCHEMA_VERSION, verify_chain
from vibap.run_bridge import (
    DEFAULT_MAX_DURATION_S,
    DEFAULT_MAX_TOOL_CALLS,
    ClaudeCodeAdapter,
    EnvProxyAdapter,
    KernelPolicyEnforcementError,
    RunContext,
    SeccompShimPlan,
    TransparentInterceptAdapter,
    _kernel_enforcement_claim,
    _plan_seccomp_shim,
    _verify_seccomp_listener_attached,
    _wrap_command_with_seccomp_shim,
    run_governed,
    run_governed_cli,
    run_governed_mission_invalid_next_steps,
    select_adapter,
)

# A self-contained stand-in agent. It speaks the documented env contract
# (ARDUR_PROXY_URL / ARDUR_API_TOKEN / ARDUR_SESSION_ID) and routes three tool
# calls through the governance proxy: one PERMIT-able (Read), one DENY-able
# (Bash, which the mission forbids), one PERMIT-able (Glob).
STANDIN_AGENT = '''\
import json, os, sys, urllib.request

proxy = os.environ["ARDUR_PROXY_URL"]
token = os.environ["ARDUR_API_TOKEN"]
session = os.environ["ARDUR_SESSION_ID"]


def evaluate(tool, args):
    body = json.dumps({"session_id": session, "tool_name": tool, "arguments": args}).encode()
    req = urllib.request.Request(
        proxy + "/evaluate", data=body, method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


decisions = {}
for tool, args in [
    ("Read", {"file_path": "README.md"}),
    ("Bash", {"command": "rm -rf /"}),
    ("Glob", {"pattern": "*.py"}),
]:
    decisions[tool] = evaluate(tool, args)["decision"]

sys.stdout.write(json.dumps(decisions))
'''


@pytest.fixture
def standin_agent(tmp_path: Path) -> Path:
    path = tmp_path / "standin_agent.py"
    path.write_text(STANDIN_AGENT, encoding="utf-8")
    return path


@pytest.fixture
def fake_exec_shim(tmp_path: Path) -> Path:
    """A stand-in ``ardur-exec-shim``: parses the real CLI shape
    (``--session-id ID --seccomp-socket PATH --control-socket PATH --
    CMD ARGS...``) and execs the remainder unmodified.

    It installs no real seccomp filter and talks to no daemon — tests using
    it prove the *orchestration* wiring around the shim (issue #104: is it
    invoked at all, does the run correctly notice when its handoff never
    completes), not the shim binary's own kernel behavior. That is covered
    separately by go/cmd/ardur-seccomp-smoke.
    """
    path = tmp_path / "fake-exec-shim.sh"
    path.write_text(
        "#!/bin/sh\nset -e\nshift 6\nshift\nexec \"$@\"\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _hermetic_kernel_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Force kernel correlation to degrade deterministically on any platform.

    Points the cgroup root at a directory with no ``cgroup.controllers`` (so
    cgroup v2 looks unavailable) and the daemon socket at a path that does not
    exist — so the bridge takes its graceful-degradation path without touching
    the host's real ``/sys/fs/cgroup`` or any live daemon.
    """
    fake_cgroup_root = tmp_path / "fake-cgroup"
    fake_cgroup_root.mkdir()
    monkeypatch.setenv(kc.CGROUP_ROOT_ENV, str(fake_cgroup_root))
    monkeypatch.setenv(kc.DAEMON_SOCKET_ENV, str(tmp_path / "no-such-daemon.sock"))


class _FakeKernelDaemon:
    """A multi-turn AF_UNIX stand-in for the kernelcapture daemon.

    Unlike a one-shot fake, this accepts a full ``ardur run`` sequence —
    ``register_session``, ``apply_policy``, and (on cleanup) ``end_session`` —
    each over its own connection (matching ``KernelCaptureClient._roundtrip``,
    which opens one connection per call), and records every request it saw.
    """

    def __init__(self, socket_path: Path, responses: dict[str, dict] | None = None) -> None:
        self.socket_path = socket_path
        self.responses = responses or {}
        self.received: list[dict] = []
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(str(socket_path))
        self._server.listen(5)
        self._server.settimeout(0.2)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _serve_forever(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except OSError:
                continue
            with conn:
                buf = b""
                while b"\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                line = buf.split(b"\n", 1)[0]
                try:
                    request = json.loads(line.decode("utf-8"))
                except ValueError:
                    continue
                self.received.append(request)
                method = request.get("method")
                default_response = {
                    "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
                    "ok": True,
                    "method": method,
                }
                response = self.responses.get(method, default_response)
                conn.sendall(json.dumps(response).encode("utf-8") + b"\n")

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._server.close()


@pytest.fixture
def sockdir():
    """A short-pathed temp dir for AF_UNIX sockets.

    AF_UNIX paths are capped (104 bytes on macOS, 108 on Linux); the deep
    pytest ``tmp_path`` blows past that on macOS, so bind sockets under /tmp.
    """
    path = Path(tempfile.mkdtemp(dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _live_kernel_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, sockdir: Path) -> Path:
    """Point cgroup v2 + the daemon socket at fakes that look "available".

    Returns the socket path a :class:`_FakeKernelDaemon` should bind to.
    """
    fake_cgroup_root = tmp_path / "fake-cgroup"
    fake_cgroup_root.mkdir()
    (fake_cgroup_root / "cgroup.controllers").write_text("cpu memory\n", encoding="utf-8")
    monkeypatch.setenv(kc.CGROUP_ROOT_ENV, str(fake_cgroup_root))
    socket_path = sockdir / "daemon.sock"
    monkeypatch.setenv(kc.DAEMON_SOCKET_ENV, str(socket_path))
    return socket_path


def test_embedded_server_health_does_not_disclose_session_id() -> None:
    server = run_bridge._build_embedded_server(
        proxy=object(),
        session_id="sensitive-session-id",
        api_token="api-token",
        private_key=object(),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address

    try:
        for path in ("/health", "/healthz"):
            with urllib.request.urlopen(  # noqa: S310 - loopback test server
                f"http://{host}:{port}{path}", timeout=2
            ) as response:
                assert response.status == 200
                assert json.load(response) == {"status": "ok"}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_ardur_run_governs_launched_agent_zero_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, standin_agent: Path
) -> None:
    _hermetic_kernel_env(monkeypatch, tmp_path)
    home = tmp_path / "ardur-home"

    result = run_governed(
        command=[sys.executable, str(standin_agent)],
        mission="Integration: govern a launched stand-in agent.",
        allowed_tools=["Read", "Glob", "Grep"],
        forbidden_tools=["Bash"],
        max_tool_calls=10,
        home=home,
        via="env",
    )

    # — a session started —
    assert result.session_id
    assert result.mission_id
    assert result.exit_code == 0
    assert result.adapter == "env-proxy"

    # — calls were evaluated (PERMIT + DENY) —
    assert result.total_events == 3
    assert result.permits == 2
    assert result.denials == 1

    # — a signed receipt chain was produced and verifies cryptographically —
    public_key = load_public_key(keys_dir=home / "keys")
    receipts_path = Path(result.receipts_path)
    assert receipts_path.is_file()
    entries = [json.loads(line) for line in receipts_path.read_text().splitlines() if line.strip()]
    assert len(entries) == 3
    verified = verify_chain(entries, public_key)
    assert len(verified) == 3
    assert {entry["schema_version"] for entry in verified} == {RECEIPT_SCHEMA_VERSION}
    verdicts = [c.get("verdict") for c in verified]
    # Signed receipts record a compliant (PERMIT) and a violation (DENY) verdict.
    assert "compliant" in verdicts
    assert "violation" in verdicts

    # — a behavioral attestation was issued and verifies —
    assert result.attestation_token
    assert result.attestation_digest.startswith("sha-256:")
    att = verify_attestation(result.attestation_token, public_key)
    assert att["schema_version"] == ATTESTATION_SCHEMA_VERSION
    assert att["passport_jti"] == result.session_id
    assert int(att["permits"]) == 2
    assert int(att["denials"]) == 1
    assert att["receipt_chain_head"] == {
        "hash_algorithm": "sha-256",
        "receipt_id": entries[-1]["receipt_id"],
        "receipt_jwt_sha256": hashlib.sha256(
            entries[-1]["jwt"].encode("ascii")
        ).hexdigest(),
    }
    # No kernel daemon was reachable (hermetic test host), so the attestation
    # must not claim kernel-enforcement data it never actually observed.
    assert "kernel_enforcement" not in att

    # — ZERO manual ardur protect: governance ran from an isolated ephemeral
    #   home with its own passport; nothing was written to ~/.claude/settings.json —
    passport_file = home / "active_mission.jwt"
    assert passport_file.is_file()
    assert (passport_file.stat().st_mode & 0o777) == 0o600
    assert not (home / "settings.json").exists()

    # — kernel correlation degraded gracefully (no daemon on the test host) —
    assert result.correlation["available"] is False
    assert "governing via env/hook" in result.correlation["reason"]


def test_ardur_run_denies_when_no_tools_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, standin_agent: Path
) -> None:
    """A mission with an empty allowlist denies every call but still attests."""
    _hermetic_kernel_env(monkeypatch, tmp_path)
    home = tmp_path / "deny-home"

    result = run_governed(
        command=[sys.executable, str(standin_agent)],
        mission="Deny everything.",
        allowed_tools=[],
        forbidden_tools=["Bash"],
        max_tool_calls=10,
        home=home,
        via="env",
    )
    assert result.total_events == 3
    assert result.denials >= 1
    assert result.receipt_count == 3
    assert result.attestation_token


# ── kernel policy wiring (Slice 4.2 apply_policy bridge) ────────────────────────


def test_ardur_run_applies_kernel_policy_when_daemon_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, standin_agent: Path, sockdir: Path
) -> None:
    """End to end: a real cgroup + a live (fake) daemon get a lowered BPF plan.

    Proves the plan is actually encoded and sent over the socket by the
    run_bridge orchestration, not just by the client method in isolation.
    """
    socket_path = _live_kernel_env(monkeypatch, tmp_path, sockdir)
    daemon = _FakeKernelDaemon(
        socket_path,
        responses={
            "register_session": {
                "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
                "ok": True,
                "method": "register_session",
                "status": "registered",
            },
            "apply_policy": {
                "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
                "ok": True,
                "method": "apply_policy",
                "status": "applied",
            },
        },
    )
    daemon.start()
    try:
        result = run_governed(
            command=[sys.executable, str(standin_agent)],
            mission="Kernel policy applied end to end.",
            allowed_tools=["Read", "Glob", "Grep"],
            forbidden_tools=["Bash"],
            max_tool_calls=10,
            home=tmp_path / "kernel-home",
            via="env",
            enforce=True,
        )
    finally:
        daemon.close()

    assert result.correlation["available"] is True
    assert result.kernel_policy["applied"] is True
    assert result.kernel_policy["generation"] == 1

    methods = [req.get("method") for req in daemon.received]
    assert "register_session" in methods
    assert "apply_policy" in methods
    # apply_policy must follow register_session (called "after cgroup registration").
    assert methods.index("apply_policy") > methods.index("register_session")

    apply_req = next(req["apply_policy"] for req in daemon.received if req.get("method") == "apply_policy")
    assert apply_req["session_id"] == result.session_id
    assert apply_req["generation"] == 1
    assert apply_req["enforce_mode"] == 1  # ENFORCE_MODE_ENFORCE

    from vibap.bpf_types import ACT_DENY, OP_EXEC

    op_by_code = {entry["op"]: entry for entry in apply_req["op_policies"]}
    assert op_by_code[OP_EXEC]["action"] == ACT_DENY  # forbidden_tools=["Bash"] -> OP_EXEC deny


def test_ardur_run_permissive_records_degradation_note_without_daemon(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, standin_agent: Path
) -> None:
    """Default (permissive) mode: no daemon -> a recorded note, run still succeeds."""
    _hermetic_kernel_env(monkeypatch, tmp_path)
    home = tmp_path / "permissive-home"

    result = run_governed(
        command=[sys.executable, str(standin_agent)],
        mission="Permissive kernel policy degrades gracefully.",
        allowed_tools=["Read", "Glob", "Grep"],
        forbidden_tools=["Bash"],
        max_tool_calls=10,
        home=home,
        via="env",
        # enforce defaults to False
    )
    assert result.exit_code == 0
    assert result.kernel_policy["applied"] is False
    assert "kernel policy not applied" in result.kernel_policy["reason"]
    assert any("kernel policy not applied" in note for note in result.notes)


def test_ardur_run_enforce_aborts_when_kernel_daemon_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, standin_agent: Path
) -> None:
    """--enforce with no daemon present: the run aborts loudly, agent is killed."""
    _hermetic_kernel_env(monkeypatch, tmp_path)
    home = tmp_path / "enforce-abort-home"

    with pytest.raises(KernelPolicyEnforcementError, match="kernel policy not applied"):
        run_governed(
            command=[sys.executable, str(standin_agent)],
            mission="Enforce mode requires kernel policy or the run must abort.",
            allowed_tools=["Read"],
            forbidden_tools=["Bash"],
            max_tool_calls=10,
            home=home,
            via="env",
            enforce=True,
        )


def test_ardur_run_enforce_aborts_when_daemon_rejects_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, standin_agent: Path, sockdir: Path
) -> None:
    """--enforce with a daemon present that rejects apply_policy also aborts."""
    socket_path = _live_kernel_env(monkeypatch, tmp_path, sockdir)
    daemon = _FakeKernelDaemon(
        socket_path,
        responses={
            "register_session": {
                "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
                "ok": True,
                "method": "register_session",
                "status": "registered",
            },
            "apply_policy": {
                "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
                "ok": False,
                "method": "apply_policy",
                "error": "no BPF-LSM guard loaded on this host",
            },
        },
    )
    daemon.start()
    try:
        with pytest.raises(KernelPolicyEnforcementError, match="no BPF-LSM guard loaded"):
            run_governed(
                command=[sys.executable, str(standin_agent)],
                mission="Enforce mode aborts on daemon rejection.",
                allowed_tools=["Read"],
                forbidden_tools=["Bash"],
                max_tool_calls=10,
                home=tmp_path / "enforce-reject-home",
                via="env",
                enforce=True,
            )
    finally:
        daemon.close()

    methods = [req.get("method") for req in daemon.received]
    assert methods.count("apply_policy") == 1
    # Cleanup still runs (finally-block end_session) even though the run aborted.
    assert "end_session" in methods


# ── seccomp-tier shim wiring (issue #104: false-success on seccomp-only hosts) ──


def _seccomp_health_response() -> dict:
    return {
        "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
        "ok": True,
        "method": "health",
        "enforcement_tier": kc.ENFORCEMENT_TIER_SECCOMP,
    }


def test_plan_seccomp_shim_disabled_by_caller() -> None:
    plan = _plan_seccomp_shim(enabled=False)
    assert plan == SeccompShimPlan(tier=None, wrapped=False, reason="kernel correlation disabled by caller")


def test_plan_seccomp_shim_no_daemon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(kc.DAEMON_SOCKET_ENV, str(tmp_path / "no-such-daemon.sock"))
    plan = _plan_seccomp_shim(enabled=True)
    assert plan.tier is None
    assert plan.wrapped is False
    assert "socket not present" in plan.reason


def test_plan_seccomp_shim_bpf_lsm_tier_does_not_wrap(monkeypatch: pytest.MonkeyPatch, sockdir: Path) -> None:
    socket_path = sockdir / "daemon.sock"
    monkeypatch.setenv(kc.DAEMON_SOCKET_ENV, str(socket_path))
    daemon = _FakeKernelDaemon(
        socket_path,
        responses={
            "health": {
                "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
                "ok": True,
                "method": "health",
                "enforcement_tier": kc.ENFORCEMENT_TIER_BPF_LSM,
            }
        },
    )
    daemon.start()
    try:
        plan = _plan_seccomp_shim(enabled=True)
    finally:
        daemon.close()
    assert plan.tier == kc.ENFORCEMENT_TIER_BPF_LSM
    assert plan.wrapped is False


def test_plan_seccomp_shim_seccomp_tier_resolves_shim(
    monkeypatch: pytest.MonkeyPatch, sockdir: Path, fake_exec_shim: Path
) -> None:
    socket_path = sockdir / "daemon.sock"
    monkeypatch.setenv(kc.DAEMON_SOCKET_ENV, str(socket_path))
    monkeypatch.setattr(kc, "exec_shim_path", lambda: fake_exec_shim)
    daemon = _FakeKernelDaemon(socket_path, responses={"health": _seccomp_health_response()})
    daemon.start()
    try:
        plan = _plan_seccomp_shim(enabled=True)
    finally:
        daemon.close()
    assert plan.tier == kc.ENFORCEMENT_TIER_SECCOMP
    assert plan.wrapped is True
    assert plan.shim_path == fake_exec_shim


def test_plan_seccomp_shim_seccomp_tier_missing_binary(monkeypatch: pytest.MonkeyPatch, sockdir: Path) -> None:
    socket_path = sockdir / "daemon.sock"
    monkeypatch.setenv(kc.DAEMON_SOCKET_ENV, str(socket_path))
    monkeypatch.setattr(kc, "exec_shim_path", lambda: None)
    daemon = _FakeKernelDaemon(socket_path, responses={"health": _seccomp_health_response()})
    daemon.start()
    try:
        plan = _plan_seccomp_shim(enabled=True)
    finally:
        daemon.close()
    assert plan.tier == kc.ENFORCEMENT_TIER_SECCOMP
    assert plan.wrapped is False
    assert "not found" in plan.reason


def test_wrap_command_with_seccomp_shim_builds_expected_argv(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(kc.SECCOMP_SOCKET_ENV, "/run/ardur/kernelcapture/seccomp.sock")
    shim_path = tmp_path / "ardur-exec-shim"
    ready_file = tmp_path / "seccomp-ready-sess-1"
    wrapped = _wrap_command_with_seccomp_shim(
        ["claude", "--foo"], session_id="sess-1", shim_path=shim_path, ready_file=ready_file
    )
    assert wrapped == [
        str(shim_path),
        "--session-id",
        "sess-1",
        "--seccomp-socket",
        "/run/ardur/kernelcapture/seccomp.sock",
        "--ready-file",
        str(ready_file),
        "--",
        "claude",
        "--foo",
    ]


def test_wrap_command_with_launch_gate_builds_expected_argv() -> None:
    assert run_bridge._wrap_command_with_launch_gate(["agent", "--flag"], ready_fd=17) == [
        sys.executable,
        "-I",
        str(Path(run_bridge.__file__).with_name("launch_gate.py")),
        "--ready-fd",
        "17",
        "--",
        "agent",
        "--flag",
    ]


def test_launch_gate_fails_closed_when_parent_does_not_release(tmp_path: Path) -> None:
    marker = tmp_path / "target-ran"
    read_fd, write_fd = os.pipe()
    proc = subprocess.Popen(
        run_bridge._wrap_command_with_launch_gate(
            [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"],
            ready_fd=read_fd,
        ),
        pass_fds=(read_fd,),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    os.close(read_fd)
    os.close(write_fd)

    _stdout, stderr = proc.communicate(timeout=5)
    assert proc.returncode == 125
    assert b"parent exited before releasing target" in stderr
    assert not marker.exists()


def test_launch_gate_ignores_project_local_module_shadow(tmp_path: Path) -> None:
    shadow_marker = tmp_path / "shadow-ran"
    target_marker = tmp_path / "target-ran"
    shadow_package = tmp_path / "vibap"
    shadow_package.mkdir()
    (shadow_package / "__init__.py").write_text("", encoding="utf-8")
    (shadow_package / "launch_gate.py").write_text(
        f"from pathlib import Path\nPath({str(shadow_marker)!r}).touch()\n",
        encoding="utf-8",
    )

    read_fd, write_fd = os.pipe()
    proc = subprocess.Popen(
        run_bridge._wrap_command_with_launch_gate(
            [sys.executable, "-c", f"from pathlib import Path; Path({str(target_marker)!r}).touch()"],
            ready_fd=read_fd,
        ),
        cwd=tmp_path,
        pass_fds=(read_fd,),
    )
    os.close(read_fd)
    os.write(write_fd, b"\x01")
    os.close(write_fd)

    assert proc.wait(timeout=5) == 0
    assert target_marker.is_file()
    assert not shadow_marker.exists()


def test_ardur_run_gates_target_through_registration_and_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "target-ran"
    target = tmp_path / "target.py"
    target.write_text(
        f"import os\nfrom pathlib import Path\nPath({str(marker)!r}).write_text(str(os.getpid()))\n",
        encoding="utf-8",
    )
    cgroup_path = tmp_path / "run-cgroup"
    cgroup_path.mkdir()

    class FakeCgroup:
        cgroup_id = 4242
        path = cgroup_path
        adopted_pid: int | None = None
        cleaned = False

        def adopt_pid(self, pid: int) -> None:
            self.adopted_pid = pid

        def cleanup(self) -> None:
            self.cleaned = True

    fake_cgroup = FakeCgroup()
    monkeypatch.setattr(kc, "create_run_cgroup", lambda _session_id: fake_cgroup)
    monkeypatch.setattr(
        run_bridge,
        "_plan_seccomp_shim",
        lambda *, enabled: SeccompShimPlan(tier=kc.ENFORCEMENT_TIER_BPF_LSM, wrapped=False),
    )

    def correlate(**kwargs: object) -> kc.CorrelationResult:
        assert fake_cgroup.adopted_pid == kwargs["pid"]
        assert not marker.exists(), "target executed before daemon registration completed"
        return kc.CorrelationResult(
            available=True,
            reason="test registration complete",
            method="test",
            cgroup_id=fake_cgroup.cgroup_id,
            cgroup_path=str(fake_cgroup.path),
        )

    def apply_policy(**_kwargs: object) -> dict[str, object]:
        assert not marker.exists(), "target executed before BPF policy application completed"
        return {"applied": True, "reason": "test policy applied"}

    monkeypatch.setattr(run_bridge, "_correlate_launch", correlate)
    monkeypatch.setattr(run_bridge, "_apply_kernel_policy", apply_policy)

    result = run_governed(
        command=[sys.executable, str(target)],
        mission="Gate target exec through kernel registration.",
        home=tmp_path / "gate-home",
        via="env",
    )

    assert result.exit_code == 0
    assert marker.is_file()
    assert int(marker.read_text(encoding="utf-8")) == fake_cgroup.adopted_pid
    assert fake_cgroup.cleaned is True


def test_verify_seccomp_listener_attached_true(monkeypatch: pytest.MonkeyPatch, sockdir: Path) -> None:
    sock = sockdir / "c.sock"
    monkeypatch.setenv(kc.DAEMON_SOCKET_ENV, str(sock))
    daemon = _FakeSessionStatusDaemon(
        sock,
        {
            "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
            "ok": True,
            "method": "session_status",
            "session_id": "sess-1",
            "seccomp_listener_attached": True,
        },
    )
    try:
        assert _verify_seccomp_listener_attached("sess-1", timeout_s=1.0, poll_interval_s=0.05) is True
    finally:
        daemon.close()


def test_verify_seccomp_listener_attached_times_out_when_never_true(
    monkeypatch: pytest.MonkeyPatch, sockdir: Path
) -> None:
    sock = sockdir / "c.sock"
    monkeypatch.setenv(kc.DAEMON_SOCKET_ENV, str(sock))
    daemon = _FakeKernelDaemon(
        sock,
        responses={
            "session_status": {
                "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
                "ok": True,
                "method": "session_status",
                "session_id": "sess-1",
                "seccomp_listener_attached": False,
            }
        },
    )
    daemon.start()
    try:
        assert _verify_seccomp_listener_attached("sess-1", timeout_s=0.3, poll_interval_s=0.05) is False
    finally:
        daemon.close()
    # Genuinely polled more than once before giving up, not just a single
    # failed round trip — proves the retry loop actually ran, not just that
    # a connection failure short-circuited it.
    assert len([r for r in daemon.received if r.get("method") == "session_status"]) >= 2


def test_verify_seccomp_listener_attached_false_when_daemon_unreachable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(kc.DAEMON_SOCKET_ENV, str(tmp_path / "no-such-daemon.sock"))
    assert _verify_seccomp_listener_attached("sess-1", timeout_s=1.0, poll_interval_s=0.05) is False


def _seccomp_daemon_responses(*, listener_attached: bool) -> dict[str, dict]:
    return {
        "health": _seccomp_health_response(),
        "register_session": {
            "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
            "ok": True,
            "method": "register_session",
            "status": "registered",
        },
        "apply_policy": {
            "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
            "ok": True,
            "method": "apply_policy",
            "status": "applied_seccomp_tier",
        },
        "session_status": {
            "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
            "ok": True,
            "method": "session_status",
            "seccomp_listener_attached": listener_attached,
        },
    }


def test_ardur_run_launches_via_shim_and_confirms_enforcement_on_seccomp_tier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, standin_agent: Path, sockdir: Path, fake_exec_shim: Path
) -> None:
    """The headline #104 fix, the success path: on a seccomp-tier host the
    agent actually runs *through* ardur-exec-shim, and a genuinely-attached
    listener is confirmed before the run reports enforcement as applied.
    """
    socket_path = _live_kernel_env(monkeypatch, tmp_path, sockdir)
    monkeypatch.setattr(kc, "exec_shim_path", lambda: fake_exec_shim)
    daemon = _FakeKernelDaemon(socket_path, responses=_seccomp_daemon_responses(listener_attached=True))
    daemon.start()
    try:
        result = run_governed(
            command=[sys.executable, str(standin_agent)],
            mission="Seccomp tier launches through the shim.",
            allowed_tools=["Read", "Glob", "Grep"],
            forbidden_tools=["Bash"],
            max_tool_calls=10,
            home=tmp_path / "seccomp-home",
            via="env",
            enforce=True,
        )
    finally:
        daemon.close()

    assert result.exit_code == 0
    assert result.kernel_policy["applied"] is True
    assert any("ardur-exec-shim" in note for note in result.notes)
    # The standin agent still ran correctly *through* the fake shim's exec
    # passthrough — proves the wrapping didn't break the governed launch.
    assert result.total_events == 3
    assert result.denials == 1


def test_no_resource_scope_omits_file_ops_from_lowered_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, standin_agent: Path, sockdir: Path, fake_exec_shim: Path
) -> None:
    """``no_resource_scope=True`` is what makes a mission genuinely
    seccomp-tier-coverable end to end: without it, every mission's default
    cwd-based file resource_scope adds OP_FILE_READ/OP_FILE_WRITE entries the
    seccomp tier can never satisfy, so apply_policy would reject it outright
    regardless of the shim wiring this test suite otherwise verifies.
    """
    socket_path = _live_kernel_env(monkeypatch, tmp_path, sockdir)
    monkeypatch.setattr(kc, "exec_shim_path", lambda: fake_exec_shim)
    daemon = _FakeKernelDaemon(socket_path, responses=_seccomp_daemon_responses(listener_attached=True))
    daemon.start()
    try:
        result = run_governed(
            command=[sys.executable, str(standin_agent)],
            mission="Network-only mission, no file scope needed.",
            allowed_tools=["Read", "Glob", "Grep"],
            forbidden_tools=["fetch"],
            max_tool_calls=10,
            home=tmp_path / "seccomp-net-only-home",
            via="env",
            enforce=True,
            no_resource_scope=True,
        )
    finally:
        daemon.close()

    assert result.kernel_policy["applied"] is True
    apply_req = next(req["apply_policy"] for req in daemon.received if req.get("method") == "apply_policy")
    assert "path_allow" not in apply_req
    ops = {entry["op"] for entry in apply_req["op_policies"]}
    from vibap.bpf_types import OP_FILE_READ, OP_FILE_WRITE, OP_NET_CONNECT

    assert ops == {OP_NET_CONNECT}
    assert OP_FILE_READ not in ops
    assert OP_FILE_WRITE not in ops


def test_ardur_run_enforce_aborts_when_seccomp_listener_never_attaches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, standin_agent: Path, sockdir: Path, fake_exec_shim: Path
) -> None:
    """The false-success bug (#104), closed: apply_policy reporting
    ``applied_seccomp_tier`` must not be trusted on its own. Here the shim
    resolves and "runs" (the fake shim is a pure passthrough — exactly what
    a shim binary that never actually talks to the daemon would look like
    from the outside), but no listener ever attaches; --enforce must abort
    loudly instead of reporting success.
    """
    socket_path = _live_kernel_env(monkeypatch, tmp_path, sockdir)
    monkeypatch.setattr(kc, "exec_shim_path", lambda: fake_exec_shim)
    monkeypatch.setattr(run_bridge, "SECCOMP_LISTENER_VERIFY_TIMEOUT_S", 0.3)
    monkeypatch.setattr(run_bridge, "SECCOMP_LISTENER_VERIFY_POLL_INTERVAL_S", 0.05)
    daemon = _FakeKernelDaemon(socket_path, responses=_seccomp_daemon_responses(listener_attached=False))
    daemon.start()
    try:
        with pytest.raises(KernelPolicyEnforcementError, match="seccomp listener never attached"):
            run_governed(
                command=[sys.executable, str(standin_agent)],
                mission="Seccomp listener never attaches, must abort under --enforce.",
                allowed_tools=["Read"],
                forbidden_tools=["Bash"],
                max_tool_calls=10,
                home=tmp_path / "seccomp-unattached-home",
                via="env",
                enforce=True,
            )
    finally:
        daemon.close()


def test_ardur_run_permissive_degrades_when_seccomp_listener_never_attaches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, standin_agent: Path, sockdir: Path, fake_exec_shim: Path
) -> None:
    """Same unattached-listener scenario, permissive mode: a recorded
    degrade, not an abort — the run still completes and still governs via
    the hook/env path, matching every other kernel-policy degrade case.
    """
    socket_path = _live_kernel_env(monkeypatch, tmp_path, sockdir)
    monkeypatch.setattr(kc, "exec_shim_path", lambda: fake_exec_shim)
    monkeypatch.setattr(run_bridge, "SECCOMP_LISTENER_VERIFY_TIMEOUT_S", 0.3)
    monkeypatch.setattr(run_bridge, "SECCOMP_LISTENER_VERIFY_POLL_INTERVAL_S", 0.05)
    daemon = _FakeKernelDaemon(socket_path, responses=_seccomp_daemon_responses(listener_attached=False))
    daemon.start()
    try:
        result = run_governed(
            command=[sys.executable, str(standin_agent)],
            mission="Seccomp listener never attaches, permissive degrade.",
            allowed_tools=["Read", "Glob", "Grep"],
            forbidden_tools=["Bash"],
            max_tool_calls=10,
            home=tmp_path / "seccomp-permissive-home",
            via="env",
            # enforce defaults to False
        )
    finally:
        daemon.close()

    assert result.exit_code == 0
    assert result.kernel_policy["applied"] is False
    assert "listener never attached" in result.kernel_policy["reason"]


def test_ardur_run_enforce_aborts_when_seccomp_tier_active_but_shim_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, standin_agent: Path, sockdir: Path
) -> None:
    """A different way #104's tier-not-wired case can happen: the daemon is
    on the seccomp tier but ``ardur-exec-shim`` was never installed
    (``exec_shim_path()`` returns ``None``) — no shim, no wrapping, but the
    mission still has kernel-enforceable policy. --enforce must abort.
    """
    socket_path = _live_kernel_env(monkeypatch, tmp_path, sockdir)
    monkeypatch.setattr(kc, "exec_shim_path", lambda: None)
    daemon = _FakeKernelDaemon(
        socket_path,
        responses={
            "health": _seccomp_health_response(),
            "register_session": {
                "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
                "ok": True,
                "method": "register_session",
                "status": "registered",
            },
            "apply_policy": {
                "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
                "ok": True,
                "method": "apply_policy",
                "status": "applied_seccomp_tier",
            },
        },
    )
    daemon.start()
    try:
        with pytest.raises(KernelPolicyEnforcementError, match="seccomp tier active but not wired"):
            run_governed(
                command=[sys.executable, str(standin_agent)],
                mission="Seccomp tier active, shim missing, must abort under --enforce.",
                allowed_tools=["Read"],
                forbidden_tools=["Bash"],
                max_tool_calls=10,
                home=tmp_path / "seccomp-no-shim-home",
                via="env",
                enforce=True,
            )
    finally:
        daemon.close()


def test_run_governed_rejects_empty_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _hermetic_kernel_env(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="requires a command"):
        run_governed(command=[], mission="x", home=tmp_path / "h")


def test_run_governed_rejects_unknown_via(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _hermetic_kernel_env(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="unknown --via"):
        run_governed(command=["true"], via="bogus", home=tmp_path / "h")


def test_resolve_run_resource_scope_narrows_relative_roots(tmp_path: Path) -> None:
    work_dir = tmp_path / "project"
    source = work_dir / "src"
    source.mkdir(parents=True)

    patterns = run_bridge._resolve_run_resource_scope(
        work_dir,
        resource_scope=["src", str(source)],
        disabled=False,
    )

    assert patterns == [str(source), f"{source}/*"]

    from vibap.proxy import _check_resource_scope

    assert _check_resource_scope({"file_path": str(source / "main.py")}, patterns, cwd=str(work_dir))[0] is True
    assert _check_resource_scope({"file_path": str(work_dir / "README.md")}, patterns, cwd=str(work_dir))[0] is False

    from vibap.bpf_lower import lower_to_bpf_policy_plan

    plan = lower_to_bpf_policy_plan(resource_scope=patterns)
    assert str(source) in plan.path_allow


@pytest.mark.parametrize(
    ("resource_scope", "disabled", "message"),
    [
        (["../outside"], False, "inside the governed cwd"),
        (["src/*"], False, "not glob patterns"),
        ([], False, "at least one path root"),
        (["src"], True, "cannot be combined"),
    ],
)
def test_resolve_run_resource_scope_rejects_unsafe_or_ambiguous_inputs(
    tmp_path: Path,
    resource_scope: list[str],
    disabled: bool,
    message: str,
) -> None:
    work_dir = tmp_path / "project"
    work_dir.mkdir()
    with pytest.raises(ValueError, match=message):
        run_bridge._resolve_run_resource_scope(
            work_dir,
            resource_scope=resource_scope,
            disabled=disabled,
        )


def test_run_governed_rejects_invalid_resource_scope_before_artifacts(tmp_path: Path) -> None:
    work_dir = tmp_path / "project"
    work_dir.mkdir()
    home = tmp_path / "ardur-home"

    with pytest.raises(ValueError, match="inside the governed cwd"):
        run_governed(
            command=["true"],
            mission="Reject scope escape before setup.",
            resource_scope=["../outside"],
            cwd=work_dir,
            home=home,
        )

    assert not home.exists()


class _FakeSessionStatusDaemon:
    """A one-shot AF_UNIX server that replays a canned session_status response."""

    def __init__(self, socket_path: Path, response: dict) -> None:
        self.socket_path = socket_path
        self.response = response
        self.received: dict | None = None
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(str(socket_path))
        self._server.listen(1)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        try:
            conn, _ = self._server.accept()
        except OSError:
            return
        with conn:
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            line = buf.split(b"\n", 1)[0]
            try:
                self.received = json.loads(line.decode("utf-8"))
            except ValueError:
                self.received = None
            conn.sendall(json.dumps(self.response).encode("utf-8") + b"\n")

    def close(self) -> None:
        self._server.close()


class TestKernelEnforcementClaim:
    """Epic A #63 / plan E3 phase b: the run bridge must be able to fetch a
    session's kernel-enforcement rollup before folding it into the
    attestation — and must never let that fetch block finalization.
    """

    def test_returns_none_when_correlation_was_never_established(self) -> None:
        correlation = kc.CorrelationResult(available=False, reason="cgroup v2 unavailable")
        assert _kernel_enforcement_claim("sess-x", correlation) is None

    def test_fetches_enforcement_summary_when_daemon_reachable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sock_dir = Path(tempfile.mkdtemp(dir="/tmp"))
        try:
            sock = sock_dir / "c.sock"
            monkeypatch.setenv(kc.DAEMON_SOCKET_ENV, str(sock))
            daemon = _FakeSessionStatusDaemon(
                sock,
                {
                    "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
                    "ok": True,
                    "method": "session_status",
                    "session_id": "sess-x",
                    "status": "active",
                    "enforcement": {
                        "total_events": 2,
                        "verdict_counts": {"denied": 2},
                        "tamper_chain_start_seq": 4,
                        "tamper_chain_last_seq": 6,
                        "tamper_chain_digest": "feedface",
                        "kill_switch_change_count": 2,
                        "kill_switch_engaged_during_session": True,
                        "kill_switch_evidence_gap": False,
                    },
                    "lifecycle_capture": {
                        "coverage_status": "degraded",
                        "ringbuf_dropped": 2,
                        "daemon_queue_dropped": 0,
                        "loss_epoch_start": 4,
                        "loss_epoch_end": 5,
                    },
                },
            )
            try:
                correlation = kc.CorrelationResult(
                    available=True, reason="registered", method="cgroup_daemon_register"
                )
                result = _kernel_enforcement_claim("sess-x", correlation)
            finally:
                daemon.close()
        finally:
            shutil.rmtree(sock_dir, ignore_errors=True)

        assert result == {
            "total_events": 2,
            "verdict_counts": {"denied": 2},
            "tamper_chain_start_seq": 4,
            "tamper_chain_last_seq": 6,
            "tamper_chain_digest": "feedface",
            "kill_switch_change_count": 2,
            "kill_switch_engaged_during_session": True,
            "kill_switch_evidence_gap": False,
            "lifecycle_capture": {
                "coverage_status": "degraded",
                "ringbuf_dropped": 2,
                "daemon_queue_dropped": 0,
                "loss_epoch_start": 4,
                "loss_epoch_end": 5,
            },
        }
        assert daemon.received is not None
        assert daemon.received["method"] == "session_status"
        assert daemon.received["session_status"]["session_id"] == "sess-x"

    def test_degrades_to_none_when_daemon_unreachable(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv(kc.DAEMON_SOCKET_ENV, str(tmp_path / "no-such-daemon.sock"))
        correlation = kc.CorrelationResult(available=True, reason="registered")
        assert _kernel_enforcement_claim("sess-x", correlation) is None

    def test_degrades_to_none_when_daemon_returns_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sock_dir = Path(tempfile.mkdtemp(dir="/tmp"))
        try:
            sock = sock_dir / "c.sock"
            monkeypatch.setenv(kc.DAEMON_SOCKET_ENV, str(sock))
            daemon = _FakeSessionStatusDaemon(
                sock,
                {
                    "protocol_version": kc.DAEMON_PROTOCOL_VERSION,
                    "ok": False,
                    "method": "session_status",
                    "error": "session not found",
                },
            )
            try:
                correlation = kc.CorrelationResult(available=True, reason="registered")
                result = _kernel_enforcement_claim("sess-x", correlation)
            finally:
                daemon.close()
        finally:
            shutil.rmtree(sock_dir, ignore_errors=True)

        assert result is None


@pytest.mark.parametrize("unset_field", ["max_tool_calls", "max_duration_s"])
def test_run_governed_cli_coerces_unset_numeric_budgets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, unset_field: str
) -> None:
    """A plain `ardur run` (no --max-tool-calls / --max-duration-s) must not crash.

    The `run` subparser defaults these to None so an explicit 0 is
    distinguishable from "unset"; run_governed_cli must coerce None to the
    documented default rather than calling ``int(None)`` (which raised
    TypeError before the fix, aborting every default-flag `ardur run`).
    """
    captured: dict[str, object] = {}

    class _Stop(Exception):
        pass

    def fake_run_governed(**kwargs: object) -> None:
        captured.update(kwargs)
        raise _Stop

    monkeypatch.setattr("vibap.run_bridge.run_governed", fake_run_governed)

    fields = {"max_tool_calls": 7, "max_duration_s": 123}
    fields[unset_field] = None  # simulate the argparse default for the run subparser

    with pytest.raises(_Stop):
        run_governed_cli(
            Namespace(
                command=["--", "true"],
                mission="budget coercion smoke",
                allowed_tools=["Read"],
                forbidden_tools=None,
                home=tmp_path / "h",
                via="env",
                no_kernel_correlation=True,
                enforce=False,
                **fields,
            )
        )

    # The unset field falls back to its module default; the other is passed through.
    assert captured["max_tool_calls"] == (
        DEFAULT_MAX_TOOL_CALLS if unset_field == "max_tool_calls" else 7
    )
    assert captured["max_duration_s"] == (
        DEFAULT_MAX_DURATION_S if unset_field == "max_duration_s" else 123
    )


def test_run_governed_cli_passes_explicit_resource_scope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}

    class Stop(Exception):
        pass

    def fake_run_governed(**kwargs: object) -> None:
        captured.update(kwargs)
        raise Stop

    monkeypatch.setattr("vibap.run_bridge.run_governed", fake_run_governed)

    with pytest.raises(Stop):
        run_governed_cli(
            Namespace(
                command=["--", "true"],
                mission="scope override smoke",
                allowed_tools=["Read"],
                forbidden_tools=None,
                max_tool_calls=7,
                max_duration_s=123,
                home=tmp_path / "h",
                via="env",
                no_kernel_correlation=True,
                enforce=False,
                resource_scope=["src", "tests"],
                no_resource_scope=False,
            )
        )

    assert captured["resource_scope"] == ["src", "tests"]
    assert captured["no_resource_scope"] is False


@pytest.mark.parametrize("command", ([], ["--"]))
def test_run_governed_cli_missing_command_reports_placeholder_next_steps(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    command: list[str],
) -> None:
    home = tmp_path / "raw-home-should-not-be-created"
    sentinel = tmp_path / "child-ran.txt"
    raw_mission = "cron smoke missing command"

    def fail_run_governed(**_kwargs: object) -> None:
        sentinel.write_text("ran", encoding="utf-8")
        raise AssertionError("missing command must fail before governed launch")

    monkeypatch.setattr("vibap.run_bridge.run_governed", fail_run_governed)

    exit_code = run_governed_cli(
        Namespace(
            command=command,
            mission=raw_mission,
            allowed_tools=["Read"],
            forbidden_tools=None,
            max_tool_calls=5,
            max_duration_s=60,
            home=home,
            via="env",
            no_kernel_correlation=True,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert not sentinel.exists()
    assert not home.exists()
    assert "ardur run requires a command to govern after --" in captured.err
    assert "usage: ardur run" in captured.err
    assert "Next steps:" in captured.err
    remediation = captured.err.split("Next steps:", 1)[1]
    assert "ardur run --mission <mission> --allowed-tools <tools> -- <command>" in remediation
    assert "ardur run --home <ardur-home> --mission <mission> --via env -- <command>" in remediation
    assert "ardur doctor --home <ardur-home>" in remediation
    assert raw_mission not in remediation
    assert str(home) not in remediation
    assert "Traceback" not in remediation


@pytest.mark.parametrize("bad_mission", ["", "   ", "\t\n"])
def test_run_governed_cli_empty_or_whitespace_mission_is_rejected(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    bad_mission: str,
) -> None:
    """Empty/whitespace --mission must fail before keys/passports are created."""
    home = tmp_path / "raw-home-should-not-be-created"
    sentinel = tmp_path / "child-ran.txt"

    def fail_run_governed(**_kwargs: object) -> None:
        sentinel.write_text("ran", encoding="utf-8")
        raise AssertionError("invalid mission must fail before governed launch")

    monkeypatch.setattr("vibap.run_bridge.run_governed", fail_run_governed)

    exit_code = run_governed_cli(
        Namespace(
            command=["echo", "ok"],
            mission=bad_mission,
            allowed_tools=["Read"],
            forbidden_tools=None,
            max_tool_calls=5,
            max_duration_s=60,
            home=home,
            via="env",
            no_kernel_correlation=True,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert not sentinel.exists()
    assert not home.exists()
    assert "ardur run --mission must be a non-empty string." in captured.err
    assert "Next steps:" in captured.err
    remediation = captured.err.split("Next steps:", 1)[1]
    assert "ardur run --mission <mission> --allowed-tools <tools> -- <command>" in remediation
    assert "ardur run -- <command>" in remediation
    # Remediation must be placeholder-only: no raw user input leaked.
    if bad_mission.strip():
        assert bad_mission not in remediation
    assert str(home) not in remediation
    assert "Traceback" not in remediation


def test_run_governed_mission_invalid_next_steps_are_deterministic() -> None:
    steps = run_governed_mission_invalid_next_steps()
    assert len(steps) == 2
    assert steps[0]["condition"] == "run_mission_invalid"
    assert steps[1]["condition"] == "run_mission_invalid"
    for step in steps:
        assert step["command"]
        assert "<" in step["command"]  # placeholder-only
        assert step["detail"]


# ── adapter unit tests ─────────────────────────────────────────────────────────


def _ctx(tmp_path: Path, plugin_dir: Path | None = None) -> RunContext:
    return RunContext(
        home=tmp_path,
        passport_token="tok",
        passport_path=tmp_path / "active_mission.jwt",
        session_id="sess-1",
        mission_id="mission-1",
        trace_id="sess-1",
        proxy_url="http://127.0.0.1:9",
        api_token="api-tok",
        plugin_dir=plugin_dir,
    )


def test_select_adapter_routes_by_mode_and_autodetect() -> None:
    assert isinstance(select_adapter(["python", "agent.py"], "env"), EnvProxyAdapter)
    assert isinstance(select_adapter(["claude"], "auto"), ClaudeCodeAdapter)
    assert isinstance(select_adapter(["/usr/bin/claude"], "auto"), ClaudeCodeAdapter)
    assert isinstance(select_adapter(["grok"], "auto"), EnvProxyAdapter)
    assert isinstance(select_adapter(["x"], "intercept"), TransparentInterceptAdapter)


def test_env_adapter_exports_governance_contract(tmp_path: Path) -> None:
    env, command, notes = EnvProxyAdapter().prepare(_ctx(tmp_path), ["python", "a.py"], {})
    assert env["ARDUR_PROXY_URL"] == "http://127.0.0.1:9"
    assert env["ARDUR_API_TOKEN"] == "api-tok"
    assert env["ARDUR_SESSION_ID"] == "sess-1"
    assert env["VIBAP_HOME"] == str(tmp_path)
    assert env["ARDUR_MISSION_PASSPORT"] == str(tmp_path / "active_mission.jwt")
    assert command == ["python", "a.py"]
    assert notes


def test_claude_adapter_injects_plugin_dir_scoped(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugins" / "claude-code"
    plugin_dir.mkdir(parents=True)
    env, command, notes = ClaudeCodeAdapter().prepare(
        _ctx(tmp_path, plugin_dir=plugin_dir), ["claude", "-p", "do work"], {}
    )
    assert command == ["claude", "--plugin-dir", str(plugin_dir), "-p", "do work"]
    # The hook is pointed at this run via env, not a settings.json edit.
    assert env["VIBAP_HOME"] == str(tmp_path)
    assert any("no settings.json edit" in note for note in notes)


def test_claude_adapter_does_not_double_inject_plugin_dir(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "p"
    plugin_dir.mkdir()
    _env, command, _notes = ClaudeCodeAdapter().prepare(
        _ctx(tmp_path, plugin_dir=plugin_dir), ["claude", "--plugin-dir", "/other"], {}
    )
    assert command == ["claude", "--plugin-dir", "/other"]


def test_transparent_intercept_is_scaffold_only(tmp_path: Path) -> None:
    with pytest.raises(NotImplementedError, match="scaffolded only"):
        TransparentInterceptAdapter().prepare(_ctx(tmp_path), ["grok"], {})


# ── CLI dispatch ───────────────────────────────────────────────────────────────


def test_claude_adapter_proxy_receives_zero_events_when_hook_governs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Document the hook↔proxy receipt gap on the claude-code path.

    ClaudeCodeAdapter inherits ARDUR_PROXY_URL from EnvProxyAdapter but the
    Claude Code hook evaluates tool calls locally via the plugin — it never
    POSTs to /evaluate.  Even when real tool calls are made through the hook,
    the embedded proxy's event counter stays at 0.  This test verifies the
    current (known-incomplete) behaviour with a noop subprocess so that any
    future change that wires the hook to also POST to /evaluate will cause an
    assertion failure here, prompting an update to expect total_events > 0.
    See: run_bridge.ClaudeCodeAdapter docstring and Epic A (#63).
    """
    _hermetic_kernel_env(monkeypatch, tmp_path)
    home = tmp_path / "cc-home"
    noop = tmp_path / "noop.py"
    noop.write_text("import sys; sys.exit(0)", encoding="utf-8")

    result = run_governed(
        command=[sys.executable, str(noop)],
        mission="ClaudeCode hook path: proxy gets 0 events.",
        allowed_tools=["Read"],
        home=home,
        via="claude-code",
    )
    assert result.adapter == "claude-code"
    # The subprocess made no calls to ARDUR_PROXY_URL/evaluate.
    # Even for a real `claude` subprocess governed via the hook, calls are
    # evaluated locally by the hook — the proxy never sees them.
    assert result.total_events == 0
    # An attestation is still issued (it covers the session, not only proxy hits).
    assert result.attestation_token


def test_run_dispatch_legacy_vs_governance() -> None:
    """`ardur run` stays on the legacy hub path until a governance flag appears."""
    from vibap.cli import _run_has_governance_intent, build_parser

    parser = build_parser()
    legacy = parser.parse_args(["run", "--", "echo", "hi"])
    assert _run_has_governance_intent(legacy) is False

    for argv in (
        ["run", "--mission", "x", "--", "echo"],
        ["run", "--allowed-tools", "Read", "--", "echo"],
        ["run", "--max-tool-calls", "5", "--", "echo"],
        ["run", "--max-duration-s", "60", "--", "echo"],
        ["run", "--via", "env", "--", "echo"],
        ["run", "--no-kernel-correlation", "--", "echo"],
        ["run", "--resource-scope", "src", "--", "echo"],
        ["run", "--no-resource-scope", "--", "echo"],
    ):
        args = parser.parse_args(argv)
        assert _run_has_governance_intent(args) is True, argv

    with pytest.raises(SystemExit):
        parser.parse_args(
            ["run", "--resource-scope", "src", "--no-resource-scope", "--", "echo"]
        )


# ── run governance budget validation ────────────────────────────────────────────


def test_run_governed_cli_negative_max_duration_returns_structured_json_without_artifacts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negative --max-duration-s must fail with structured JSON BEFORE key generation."""
    home = tmp_path / "ardur-home"
    sentinel = tmp_path / "child-ran.txt"

    def fail_run_governed(**_kwargs: object) -> None:
        sentinel.write_text("ran", encoding="utf-8")
        raise AssertionError("invalid budget must fail before governed launch")

    monkeypatch.setattr("vibap.run_bridge.run_governed", fail_run_governed)

    exit_code = run_governed_cli(
        Namespace(
            command=["echo", "hi"],
            mission="example-mission-placeholder",
            allowed_tools=["Read"],
            forbidden_tools=None,
            max_tool_calls=5,
            max_duration_s=-5,
            home=home,
            via="env",
            no_kernel_correlation=True,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert not sentinel.exists()
    assert not home.exists()

    # stdout must be structured JSON
    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["condition"] == "run_max_duration_invalid"
    assert response["error"] == "run_max_duration_invalid"
    assert "next_steps" in response
    assert len(response["next_steps"]) >= 1
    for step in response["next_steps"]:
        assert "<" in step["command"]  # placeholder-only

    # stderr must be empty
    assert captured.err == ""

    # No traceback or raw ValueError in either stream
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err
    assert "ttl_s must be positive" not in captured.out
    assert "ttl_s must be positive" not in captured.err

    # No local absolute paths leaked
    assert "/Users/" not in captured.out
    assert "/tmp/" not in captured.out


def test_run_governed_cli_negative_max_tool_calls_returns_structured_json_without_artifacts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negative --max-tool-calls must fail with structured JSON BEFORE key generation."""
    home = tmp_path / "ardur-home"
    sentinel = tmp_path / "child-ran.txt"

    def fail_run_governed(**_kwargs: object) -> None:
        sentinel.write_text("ran", encoding="utf-8")
        raise AssertionError("invalid budget must fail before governed launch")

    monkeypatch.setattr("vibap.run_bridge.run_governed", fail_run_governed)

    exit_code = run_governed_cli(
        Namespace(
            command=["echo", "hi"],
            mission="example-mission-placeholder",
            allowed_tools=["Read"],
            forbidden_tools=None,
            max_tool_calls=-5,
            max_duration_s=60,
            home=home,
            via="env",
            no_kernel_correlation=True,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert not sentinel.exists()
    assert not home.exists()

    response = json.loads(captured.out)
    assert response["ok"] is False
    assert response["condition"] == "run_max_tool_calls_invalid"
    assert response["error"] == "run_max_tool_calls_invalid"
    assert "next_steps" in response
    assert len(response["next_steps"]) >= 1
    for step in response["next_steps"]:
        assert "<" in step["command"]

    assert captured.err == ""
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err
    assert "/Users/" not in captured.out
    assert "/tmp/" not in captured.out


def test_run_governed_cli_zero_max_tool_calls_still_valid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--max-tool-calls 0 must NOT be rejected by the new check (consistent with cmd_issue)."""
    captured: dict[str, object] = {}

    class _Stop(Exception):
        pass

    def fake_run_governed(**kwargs: object) -> None:
        captured.update(kwargs)
        raise _Stop

    monkeypatch.setattr("vibap.run_bridge.run_governed", fake_run_governed)

    with pytest.raises(_Stop):
        run_governed_cli(
            Namespace(
                command=["echo", "hi"],
                mission="example-mission-placeholder",
                allowed_tools=["Read"],
                forbidden_tools=None,
                max_tool_calls=0,
                max_duration_s=60,
                home=tmp_path / "h",
                via="env",
                no_kernel_correlation=True,
            )
        )

    # run_governed was reached with max_tool_calls=0 (not rejected)
    assert captured["max_tool_calls"] == 0


def test_run_governed_cli_negative_max_duration_no_stderr_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negative --max-duration-s must not leak a traceback or raw ValueError to stderr."""
    home = tmp_path / "ardur-home"

    def fail_run_governed(**_kwargs: object) -> None:
        raise AssertionError("invalid budget must fail before governed launch")

    monkeypatch.setattr("vibap.run_bridge.run_governed", fail_run_governed)

    exit_code = run_governed_cli(
        Namespace(
            command=["echo", "hi"],
            mission="example-mission-placeholder",
            allowed_tools=["Read"],
            forbidden_tools=None,
            max_tool_calls=5,
            max_duration_s=-5,
            home=home,
            via="env",
            no_kernel_correlation=True,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.err == ""
    assert "Traceback" not in captured.out
    assert "Traceback" not in captured.err
    assert "ttl_s must be positive" not in captured.out
    assert "ttl_s must be positive" not in captured.err


# ---------------------------------------------------------------------------
# --home path pre-validation (existing non-directory rejection)
# ---------------------------------------------------------------------------


def test_run_governed_home_not_directory_next_steps_are_deterministic() -> None:
    """The ``next_steps`` list for ``run_home_not_directory`` must be
    deterministic and contain the expected ``condition`` field."""
    steps = run_bridge.run_governed_home_not_directory_next_steps()
    assert len(steps) == 2
    for step in steps:
        assert step["condition"] == "run_home_not_directory"
        assert "command" in step
        assert "detail" in step
        assert "action" in step


def test_run_governed_cli_existing_file_home_is_rejected_before_artifacts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--home <existing-file>`` must be rejected with exit 2, empty stdout,
    deterministic stderr + Next steps, no traceback, no raw path leak, and
    no artifacts created before rejection."""
    existing_file = tmp_path / "existing-file"
    existing_file.write_text("sentinel")

    def fail_run_governed(**_kwargs: object) -> None:
        raise AssertionError("existing-file home must be rejected before governed launch")

    monkeypatch.setattr("vibap.run_bridge.run_governed", fail_run_governed)

    exit_code = run_bridge.run_governed_cli(
        Namespace(
            command=["echo", "hi"],
            mission="example-mission-placeholder",
            allowed_tools=["Read"],
            forbidden_tools=None,
            max_tool_calls=5,
            max_duration_s=60,
            home=str(existing_file),
            via="env",
            no_kernel_correlation=True,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "Traceback" not in captured.err
    assert "Traceback" not in captured.out
    assert str(existing_file) not in captured.err
    assert "must point to a directory path" in captured.err
    assert "Next steps:" in captured.err
    # The existing file must be untouched.
    assert existing_file.read_text() == "sentinel"
    # No keys/ directory or other artifacts created beside the file.
    assert not (tmp_path / "keys").exists()
    assert not (tmp_path / "state").exists()
    assert not (tmp_path / "active_mission.jwt").exists()


def test_run_governed_cli_symlink_to_file_home_is_rejected_before_artifacts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--home <symlink-to-file>`` must also be rejected (resolve follows
    the link, ``is_dir()`` is False)."""
    real_file = tmp_path / "real-file"
    real_file.write_text("sentinel")
    symlink = tmp_path / "link-to-file"
    symlink.symlink_to(real_file)

    def fail_run_governed(**_kwargs: object) -> None:
        raise AssertionError("symlink-to-file home must be rejected before governed launch")

    monkeypatch.setattr("vibap.run_bridge.run_governed", fail_run_governed)

    exit_code = run_bridge.run_governed_cli(
        Namespace(
            command=["echo", "hi"],
            mission="example-mission-placeholder",
            allowed_tools=["Read"],
            forbidden_tools=None,
            max_tool_calls=5,
            max_duration_s=60,
            home=str(symlink),
            via="env",
            no_kernel_correlation=True,
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "Traceback" not in captured.err
    assert "must point to a directory path" in captured.err
    assert real_file.read_text() == "sentinel"


@pytest.mark.parametrize(
    "home_value",
    [
        "existing_dir",
        "nonexistent",
        "dangling_symlink",
    ],
)
def test_run_governed_cli_valid_home_paths_pass_through_to_run_governed(
    home_value: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Existing directories, nonexistent paths, and dangling symlinks must
    pass through to ``run_governed`` without printing the rejection message."""
    if home_value == "existing_dir":
        home = tmp_path / "ardur-home"
        home.mkdir()
    elif home_value == "nonexistent":
        home = tmp_path / "nonexistent-home"
    elif home_value == "dangling_symlink":
        home = tmp_path / "dangling-link"
        home.symlink_to(tmp_path / "nonexistent-target")
    else:
        raise AssertionError(f"unexpected home_value: {home_value}")

    # Stub run_governed to return a minimal result so format_summary succeeds.
    from vibap.run_bridge import GovernanceRunResult

    def stub_run_governed(**_kwargs: object) -> GovernanceRunResult:
        return GovernanceRunResult(
            exit_code=0,
            session_id="stub-session",
            mission_id="stub-mission",
            agent_id="stub-agent",
            adapter="stub-adapter",
            via="env",
            proxy_url="http://127.0.0.1:1",
            home=str(home),
            passport_path=str(tmp_path / "passport.jwt"),
            summary={"ok": True},
            permits=0,
            denials=0,
            total_events=0,
            attestation_token="stub-token",
            attestation_digest="sha-256:stub",
            receipts_path=str(tmp_path / "receipts.jsonl"),
            receipt_count=0,
            correlation={},
            kernel_policy={},
        )

    monkeypatch.setattr("vibap.run_bridge.run_governed", stub_run_governed)

    exit_code = run_bridge.run_governed_cli(
        Namespace(
            command=["echo", "hi"],
            mission="example-mission-placeholder",
            allowed_tools=["Read"],
            forbidden_tools=None,
            max_tool_calls=5,
            max_duration_s=60,
            home=str(home),
            via="env",
            no_kernel_correlation=True,
        )
    )

    assert exit_code == 0


def test_run_governed_cli_omitted_home_passes_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ``--home`` is omitted (``None``), the call must reach
    ``run_governed`` without printing the rejection message."""
    from vibap.run_bridge import GovernanceRunResult

    def stub_run_governed(**_kwargs: object) -> GovernanceRunResult:
        return GovernanceRunResult(
            exit_code=0,
            session_id="stub-session",
            mission_id="stub-mission",
            agent_id="stub-agent",
            adapter="stub-adapter",
            via="env",
            proxy_url="http://127.0.0.1:1",
            home=str(Path(tempfile.mkdtemp())),
            passport_path=str(Path(tempfile.mkdtemp()) / "passport.jwt"),
            summary={"ok": True},
            permits=0,
            denials=0,
            total_events=0,
            attestation_token="stub-token",
            attestation_digest="sha-256:stub",
            receipts_path=str(Path(tempfile.mkdtemp()) / "receipts.jsonl"),
            receipt_count=0,
            correlation={},
            kernel_policy={},
        )

    monkeypatch.setattr("vibap.run_bridge.run_governed", stub_run_governed)

    exit_code = run_bridge.run_governed_cli(
        Namespace(
            command=["echo", "hi"],
            mission="example-mission-placeholder",
            allowed_tools=["Read"],
            forbidden_tools=None,
            max_tool_calls=5,
            max_duration_s=60,
            home=None,
            via="env",
            no_kernel_correlation=True,
        )
    )

    assert exit_code == 0
