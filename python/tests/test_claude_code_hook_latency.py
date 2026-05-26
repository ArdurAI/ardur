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
    native Unix-socket client -> daemon. It is the defensible p95<10ms release
    claim; the shell plugin wrapper below is telemetry only because shell
    startup and desktop scheduler tails are outside Ardur's native hot path.
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
    env.update(
        {
            "ARDUR_CC_HOOK_DAEMON": "1",
            "ARDUR_CC_HOOK_DAEMON_SOCKET": str(socket_path),
            "ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS": "100",
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
                [str(native_pre_tool_use_command), str(socket_path), "100"],
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
                [str(native_pre_tool_use_command), str(socket_path), "100"],
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
        assert p95_ms < 10
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
    hook output. Its latency is useful telemetry, but enforcing p95<10ms here
    would rig the release claim against shell startup and workstation scheduler
    tails rather than the Ardur native hot path.
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
            "ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS": "100",
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
    assert p95_ms < 10
