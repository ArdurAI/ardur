"""Gated latency baselines for Claude Code hook paths."""

from __future__ import annotations

import json
import math
import os
import statistics
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Iterable
from pathlib import Path

import pytest

from vibap.passport import MissionPassport, generate_keypair, issue_passport


pytestmark = pytest.mark.skipif(
    os.environ.get("ARDUR_RUN_LATENCY_BENCH") != "1",
    reason="set ARDUR_RUN_LATENCY_BENCH=1 to run latency benchmarks",
)


def _is_ci_environment() -> bool:
    """Detect GitHub Actions / generic CI shared runners.

    The p95<10ms hot-path and p95<20ms native-client gates are local-evidence
    thresholds measured on Apple Silicon macOS. On CI shared runners (2-core
    ubuntu-latest) the same paths run materially slower under CPU contention
    (Ed25519 signing alone jumps from ~2ms to ~33ms p95). CI runs use wider
    regression gates so the informational benchmark job stops flapping without
    loosening the local-evidence claim boundary.
    """
    return os.environ.get("CI") == "true" or os.environ.get("GITHUB_ACTIONS") == "true"


def _hot_path_p95_gate_ms() -> float:
    """In-process daemon compute p95 gate: <10ms locally, <50ms on CI.

    Local Apple Silicon baseline is ~2-3ms p95; the <10ms claim is defensible
    there. CI baseline is ~33ms p95 under CPU contention; 50ms catches a 1.5x
    regression without flapping on shared-runner jitter.
    """
    return 50.0 if _is_ci_environment() else 10.0


def _native_client_p95_gate_ms() -> float:
    """Native client -> daemon round-trip p95 gate: <20ms locally, <60ms on CI.

    Local Apple Silicon baseline is ~6-17ms p95. CI shared runners are slower
    and can hit EAGAIN under the 100ms socket timeout; the CI gate is widened
    to 60ms to catch a 2x regression once the timeout is relaxed.
    """
    return 60.0 if _is_ci_environment() else 20.0


def _daemon_timeout_ms_env() -> str:
    """SO_RCVTIMEO for the native daemon client.

    100ms is correct locally (p95 ~6-17ms). On CI shared runners the daemon
    thread cannot always process the request within 100ms under CPU contention,
    producing EAGAIN (exit 11, stage=response-read errno=11). 1000ms on CI is a
    safety bound only; it does not change the measured latency.
    """
    return "1000" if _is_ci_environment() else "100"


if _is_ci_environment():
    print(
        "CI environment detected: using wider p95 gates "
        "(local-evidence claim boundary unchanged)"
    )


def _benchmark_iterations() -> int:
    """Return benchmark sample count for p95/p99 evidence.

    Keep this high enough to be statistically meaningful for release claims.
    Process-spawn hook benchmarks have rare scheduler tail spikes; with n=30,
    nearest-rank p95 is effectively the second-slowest sample and can be
    dominated by one or two p99-ish outliers. A 100-sample floor keeps the gate
    strict on p95 while making the percentile estimate defensible.
    """
    raw = os.environ.get("ARDUR_LATENCY_BENCH_ITERATIONS", "100")
    try:
        return max(100, int(raw))
    except ValueError:
        return 100


def _nearest_rank(values: list[float], percentile: int) -> float:
    ordered = sorted(values)
    rank = math.ceil((percentile / 100) * len(ordered))
    return ordered[min(max(rank - 1, 0), len(ordered) - 1)]


def _issue_benchmark_passport(keys_dir: Path) -> str:
    private_key, _public_key = generate_keypair(keys_dir=keys_dir)
    mission = MissionPassport(
        agent_id="claude-code-latency-bench",
        mission="benchmark Claude Code hook latency",
        allowed_tools=["Read"],
        forbidden_tools=["Bash"],
        resource_scope=["/tmp/*"],
        max_tool_calls=10_000,
        max_duration_s=3600,
    )
    return issue_passport(mission, private_key, ttl_s=3600)


def _benchmark_env(tmp_path: Path, token: str) -> dict[str, str]:
    python_root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["ARDUR_MISSION_PASSPORT"] = token
    env["VIBAP_HOME"] = str(tmp_path)
    env["ARDUR_CC_HOOK_DIR"] = str(tmp_path / "chain")
    env["PYTHONPATH"] = (
        str(python_root)
        if not env.get("PYTHONPATH")
        else str(python_root) + os.pathsep + env["PYTHONPATH"]
    )
    return env


def _hook_input(call_index: int) -> str:
    return json.dumps(
        {
            "session_id": "latency-bench-session",
            "tool_name": "Read",
            "tool_input": {"file_path": f"/tmp/ardur-latency-{call_index}.txt"},
            "tool_use_id": f"latency-bench-call-{call_index}",
        }
    )


def test_claude_code_hook_subprocess_cold_path_latency_baseline(tmp_path: Path) -> None:
    keys_dir = tmp_path / "keys"
    token = _issue_benchmark_passport(keys_dir)
    env = _benchmark_env(tmp_path, token)
    iterations = _benchmark_iterations()

    durations_ms: list[float] = []
    returncodes: list[int] = []
    for i in range(iterations):
        started = time.perf_counter()
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "vibap.claude_code_hook",
                "pre",
                "--keys-dir",
                str(keys_dir),
            ],
            input=_hook_input(i),
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        durations_ms.append((time.perf_counter() - started) * 1000)
        returncodes.append(result.returncode)

        # Baseline current hook behavior without forcing a new exit-code
        # contract in this latency-only test.
        assert result.returncode in {0, 1}, result.stderr

    median_ms = statistics.median(durations_ms)
    p95_ms = _nearest_rank(durations_ms, 95)
    p99_ms = _nearest_rank(durations_ms, 99)
    print(
        "claude_code_hook subprocess cold path: "
        f"n={iterations} median={median_ms:.2f}ms "
        f"p95={p95_ms:.2f}ms p99={p99_ms:.2f}ms "
        f"returncodes={returncodes}"
    )


def test_claude_code_native_daemon_client_latency_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Gate the latency-critical native daemon-client command path.

    This is the low-overhead path installed by ``ardur protect claude-code``:
    native Unix-socket client -> daemon.  Measured reality on Apple Silicon
    macOS: p95 ~15-17ms end-to-end for the full client-to-daemon round-trip
    (subprocess exec + Unix-socket send/recv + response parse).  The local
    gate is p95<20ms to accommodate that measured baseline while still
    catching regressions.

    On CI shared runners (``CI=true`` / ``GITHUB_ACTIONS=true``) the same path
    runs slower under CPU contention and can hit EAGAIN under the 100ms socket
    timeout. CI runs widen the gate to p95<60ms and relax the safety timeout
    to 1000ms so the daemon thread has room to respond. The p95<20ms
    local-evidence threshold is unchanged on non-CI runs.

    The in-process hot-path target (``test_claude_code_daemon_hot_path_latency_target``)
    is the <10ms claim; it measures only compute inside the daemon with no
    subprocess or IPC overhead and applies to the pure in-process code path.

    The shell plugin wrapper test below is telemetry only because /bin/bash
    startup and workstation scheduler tails are outside Ardur's native hot
    path.
    """
    from vibap import claude_code_daemon as daemon_module

    native_pre_tool_use_command = daemon_module.install_native_pre_tool_use_command(home=tmp_path, force=True)
    if native_pre_tool_use_command is None:
        pytest.xfail("native PreToolUse daemon client could not be built on this host")

    keys_dir = tmp_path / "keys"
    token = _issue_benchmark_passport(keys_dir)
    env = _benchmark_env(tmp_path, token)
    socket_parent = Path(f"/tmp/ardur-wrapper-daemon-bench-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "hook.sock"
    timeout_ms_env = _daemon_timeout_ms_env()
    env.update(
        {
            "ARDUR_CC_HOOK_DAEMON": "1",
            "ARDUR_CC_HOOK_DAEMON_SOCKET": str(socket_path),
            "ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS": timeout_ms_env,
            "ARDUR_HOOK_PYTHON": sys.executable,
            "ARDUR_CC_HOOK_NATIVE_PRE_TOOL_USE": str(native_pre_tool_use_command),
            "ARDUR_CC_HOOK_STRICT_NATIVE": "1",
        }
    )
    for name in (
        "ARDUR_MISSION_PASSPORT",
        "VIBAP_HOME",
        "ARDUR_CC_HOOK_DIR",
        "ARDUR_CC_HOOK_DAEMON",
        "ARDUR_CC_HOOK_DAEMON_SOCKET",
        "ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS",
        "ARDUR_HOOK_PYTHON",
        "ARDUR_CC_HOOK_NATIVE_PRE_TOOL_USE",
        "ARDUR_CC_HOOK_STRICT_NATIVE",
    ):
        monkeypatch.setenv(name, env[name])

    # Measure only healthy native-fast-path behavior: if the wrapper ever falls
    # back to local Python, that call should fail fast (non-zero) instead of
    # silently inflating latency samples.
    env["ARDUR_HOOK_PYTHON"] = "/bin/false"

    iterations = _benchmark_iterations()
    warmup_calls = 5
    observed: dict[str, int] = {}
    failures: list[Exception] = []

    def _serve() -> None:
        try:
            observed["handled"] = daemon_module.serve_pre_tool_use_daemon(
                socket_path=socket_path,
                keys_dir=keys_dir,
                max_requests=iterations + warmup_calls,
            )
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            failures.append(exc)

    thread = threading.Thread(target=_serve, daemon=True)
    try:
        thread.start()
        for _ in range(100):
            if socket_path.exists():
                break
            time.sleep(0.01)
        assert socket_path.exists(), "daemon did not create Unix socket"

        # Warm up shell + native daemon-client path before sampling to reduce
        # first-call loader/cache noise in the measured steady-state p95 gate.
        for warmup_idx in range(5):
            warmup = subprocess.run(
                [str(native_pre_tool_use_command), str(socket_path), timeout_ms_env],
                input=_hook_input(-(warmup_idx + 1)).encode("utf-8"),
                capture_output=True,
                text=False,
                env=env,
                check=False,
            )
            assert warmup.returncode == 0, warmup.stderr.decode("utf-8", errors="replace")
            assert json.loads(warmup.stdout.decode("utf-8")).get("continue") is True

        durations_ms: list[float] = []
        for i in range(iterations):
            started = time.perf_counter()
            result = subprocess.run(
                [str(native_pre_tool_use_command), str(socket_path), timeout_ms_env],
                input=_hook_input(i).encode("utf-8"),
                capture_output=True,
                text=False,
                env=env,
                check=False,
            )
            durations_ms.append((time.perf_counter() - started) * 1000.0)
            assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
            output = json.loads(result.stdout.decode("utf-8"))
            assert output.get("continue") is True

        thread.join(timeout=5)
        assert not failures
        if thread.is_alive() or observed.get("handled") != iterations + warmup_calls:
            pytest.xfail("wrapper did not exercise the daemon socket path")

        median_ms = statistics.median(durations_ms)
        p95_ms = _nearest_rank(durations_ms, 95)
        p99_ms = _nearest_rank(durations_ms, 99)
        print(
            "claude_code_hook native daemon-client path: "
            f"n={iterations} median={median_ms:.2f}ms "
            f"p95={p95_ms:.2f}ms p99={p99_ms:.2f}ms"
        )
        # Measured on Apple Silicon macOS: p95 ~15-17ms for the full
        # native client -> daemon round-trip.  Local gate at <20ms to catch
        # regressions while reflecting the real per-platform baseline.
        # CI shared runners widen to <60ms under CPU contention (see
        # _native_client_p95_gate_ms). The <10ms claim applies only to
        # in-process compute (test_claude_code_daemon_hot_path_latency_target).
        native_client_gate_ms = _native_client_p95_gate_ms()
        assert p95_ms < native_client_gate_ms
    finally:
        if socket_path.exists():
            socket_path.unlink()
        if socket_parent.exists():
            socket_parent.rmdir()


def test_claude_code_hook_wrapper_daemon_client_latency_telemetry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Measure shell-wrapper latency without using it as a p95 release gate.

    The wrapper still has to exercise the native daemon client and return valid
    hook output. Its latency is useful telemetry, but enforcing a strict p95
    gate here would rig the release claim against /bin/bash startup and
    workstation scheduler tails rather than the Ardur native hot path.  The
    native daemon-client gate (p95<20ms locally, measured ~15-17ms on Apple
    Silicon macOS) is the release signal; the shell path is reporting only.
    On CI the daemon socket timeout is relaxed (see _daemon_timeout_ms_env)
    so the wrapper can reach the daemon thread under CPU contention.
    """
    repo_root = Path(__file__).resolve().parents[2]
    wrapper = repo_root / "plugins" / "claude-code" / "hooks" / "pre_tool_use"
    if not wrapper.exists():
        pytest.xfail("Claude Code pre_tool_use wrapper is missing")

    from vibap import claude_code_daemon as daemon_module

    native_pre_tool_use_command = daemon_module.install_native_pre_tool_use_command(home=tmp_path, force=True)
    if native_pre_tool_use_command is None:
        pytest.xfail("native PreToolUse daemon client could not be built on this host")

    keys_dir = tmp_path / "keys"
    token = _issue_benchmark_passport(keys_dir)
    env = _benchmark_env(tmp_path, token)
    socket_parent = Path(f"/tmp/ardur-wrapper-daemon-bench-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    socket_parent.mkdir(mode=0o700)
    socket_path = socket_parent / "hook.sock"
    env.update(
        {
            "ARDUR_CC_HOOK_DAEMON": "1",
            "ARDUR_CC_HOOK_DAEMON_SOCKET": str(socket_path),
            "ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS": _daemon_timeout_ms_env(),
            "ARDUR_HOOK_PYTHON": sys.executable,
            "ARDUR_CC_HOOK_NATIVE_PRE_TOOL_USE": str(native_pre_tool_use_command),
            "ARDUR_CC_HOOK_STRICT_NATIVE": "1",
        }
    )
    for name in (
        "ARDUR_MISSION_PASSPORT",
        "VIBAP_HOME",
        "ARDUR_CC_HOOK_DIR",
        "ARDUR_CC_HOOK_DAEMON",
        "ARDUR_CC_HOOK_DAEMON_SOCKET",
        "ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS",
        "ARDUR_HOOK_PYTHON",
        "ARDUR_CC_HOOK_NATIVE_PRE_TOOL_USE",
        "ARDUR_CC_HOOK_STRICT_NATIVE",
    ):
        monkeypatch.setenv(name, env[name])

    env["ARDUR_HOOK_PYTHON"] = "/bin/false"

    iterations = _benchmark_iterations()
    warmup_calls = 5
    observed: dict[str, int] = {}
    failures: list[Exception] = []

    def _serve() -> None:
        try:
            observed["handled"] = daemon_module.serve_pre_tool_use_daemon(
                socket_path=socket_path,
                keys_dir=keys_dir,
                max_requests=iterations + warmup_calls,
            )
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            failures.append(exc)

    thread = threading.Thread(target=_serve, daemon=True)
    try:
        thread.start()
        for _ in range(100):
            if socket_path.exists():
                break
            time.sleep(0.01)
        assert socket_path.exists(), "daemon did not create Unix socket"

        for warmup_idx in range(warmup_calls):
            warmup = subprocess.run(
                [str(wrapper)],
                input=_hook_input(-(warmup_idx + 1)).encode("utf-8"),
                capture_output=True,
                text=False,
                env=env,
                check=False,
            )
            assert warmup.returncode == 0, warmup.stderr.decode("utf-8", errors="replace")
            assert json.loads(warmup.stdout.decode("utf-8")).get("continue") is True

        durations_ms: list[float] = []
        for i in range(iterations):
            started = time.perf_counter()
            result = subprocess.run(
                [str(wrapper)],
                input=_hook_input(i).encode("utf-8"),
                capture_output=True,
                text=False,
                env=env,
                check=False,
            )
            durations_ms.append((time.perf_counter() - started) * 1000.0)
            assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
            output = json.loads(result.stdout.decode("utf-8"))
            assert output.get("continue") is True

        thread.join(timeout=5)
        assert not failures
        if thread.is_alive() or observed.get("handled") != iterations + warmup_calls:
            pytest.xfail("wrapper did not exercise the daemon socket path")

        median_ms = statistics.median(durations_ms)
        p95_ms = _nearest_rank(durations_ms, 95)
        p99_ms = _nearest_rank(durations_ms, 99)
        print(
            "claude_code_hook wrapper daemon-client telemetry: "
            f"n={iterations} median={median_ms:.2f}ms "
            f"p95={p95_ms:.2f}ms p99={p99_ms:.2f}ms"
        )
    finally:
        if socket_path.exists():
            socket_path.unlink()
        if socket_parent.exists():
            socket_parent.rmdir()


def _coerce_duration_samples_ms(samples: object) -> list[float]:
    if isinstance(samples, dict):
        samples = samples.get("durations_ms", [])
    if not isinstance(samples, Iterable) or isinstance(samples, (str, bytes)):
        raise TypeError("daemon benchmark must return durations_ms or an iterable of ms samples")
    return [float(sample) for sample in samples]


def test_claude_code_daemon_hot_path_latency_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Gate the in-process compute path inside the daemon (p95<10ms locally).

    This measures pure in-process compute: passport validation, scope check,
    and receipt emission with no subprocess exec or Unix-socket IPC overhead.
    The <10ms claim is defensible for this path on Apple Silicon macOS, where
    the local baseline is ~2-3ms p95. The full client-to-daemon round-trip
    (native binary + socket) targets p95<20ms locally and is gated by
    ``test_claude_code_native_daemon_client_latency_target``.

    On CI shared runners (``CI=true`` / ``GITHUB_ACTIONS=true``) Ed25519
    signing under CPU contention runs materially slower (CI baseline ~33ms
    p95 vs ~2ms locally). CI runs widen the gate to p95<50ms so the
    informational benchmark job stops flapping; the p95<10ms local-evidence
    claim is unchanged on non-CI runs.
    """
    daemon_path = Path(__file__).resolve().parents[1] / "vibap" / "claude_code_daemon.py"
    if not daemon_path.exists():
        pytest.xfail("python/vibap/claude_code_daemon.py is not implemented yet")

    import importlib

    module = importlib.import_module("vibap.claude_code_daemon")
    benchmark = getattr(module, "benchmark_pre_tool_use_hot_path", None)
    if benchmark is None:
        pytest.xfail("daemon must expose benchmark_pre_tool_use_hot_path to enable this target")

    keys_dir = tmp_path / "keys"
    token = _issue_benchmark_passport(keys_dir)
    env = _benchmark_env(tmp_path, token)
    for name in ("ARDUR_MISSION_PASSPORT", "VIBAP_HOME", "ARDUR_CC_HOOK_DIR"):
        monkeypatch.setenv(name, env[name])

    iterations = _benchmark_iterations()
    samples_ms = _coerce_duration_samples_ms(
        benchmark(
            hook_input=json.loads(_hook_input(0)),
            keys_dir=keys_dir,
            iterations=iterations,
        )
    )
    assert len(samples_ms) >= iterations

    median_ms = statistics.median(samples_ms)
    p95_ms = _nearest_rank(samples_ms, 95)
    p99_ms = _nearest_rank(samples_ms, 99)
    print(
        "claude_code_daemon hot path: "
        f"n={len(samples_ms)} median={median_ms:.2f}ms "
        f"p95={p95_ms:.2f}ms p99={p99_ms:.2f}ms"
    )
    # Local gate: p95<10ms (Apple Silicon baseline ~2-3ms). CI shared runners
    # widen to p95<50ms (see _hot_path_p95_gate_ms) because Ed25519 signing
    # under CPU contention is materially slower there; the p95<10ms claim
    # remains a local-evidence threshold.
    hot_path_gate_ms = _hot_path_p95_gate_ms()
    assert p95_ms < hot_path_gate_ms
