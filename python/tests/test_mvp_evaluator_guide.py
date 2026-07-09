from __future__ import annotations

import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
GUIDE = REPO_ROOT / "docs" / "mvp-evaluator-guide.md"
README = REPO_ROOT / "README.md"
MARKER = "<!-- evaluator-guide-live-block -->"
API_TOKEN = "evaluator-guide-contract-token"


def _walkthrough_block() -> str:
    guide = GUIDE.read_text(encoding="utf-8")
    marked = guide.split(MARKER, maxsplit=1)
    assert len(marked) == 2, "evaluator guide must contain one live-block marker"
    match = re.search(r"```bash\n(.*?)\n```", marked[1], flags=re.DOTALL)
    assert match is not None, "live-block marker must be followed by a Bash fence"
    return match.group(1)


def _wait_for_health(base_url: str, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(
                f"proxy exited before health check: {process.returncode}"
            )
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=0.5) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError):
            time.sleep(0.1)
    raise AssertionError("proxy did not become healthy")


def _stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def test_evaluator_guide_walkthrough_runs_against_authenticated_proxy(
    tmp_path: Path, unused_tcp_port: int
) -> None:
    ardur = Path(sys.executable).with_name("ardur")
    assert ardur.is_file(), "test environment must install the ardur CLI entrypoint"
    base_url = f"http://127.0.0.1:{unused_tcp_port}"
    child_env = os.environ.copy()
    child_env.pop("VIBAP_API_TOKEN", None)
    process = subprocess.Popen(
        [
            str(ardur),
            "start",
            "--host",
            "127.0.0.1",
            "--port",
            str(unused_tcp_port),
            "--keys-dir",
            str(tmp_path / "keys"),
            "--state-dir",
            str(tmp_path / "state"),
            "--log-path",
            str(tmp_path / "audit.jsonl"),
            "--api-token",
            API_TOKEN,
            "--no-tls",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        env=child_env,
    )
    result: subprocess.CompletedProcess[str] | None = None
    try:
        _wait_for_health(base_url, process)
        env = os.environ | {
            "ARDUR_API_TOKEN": API_TOKEN,
            "ARDUR_PROXY_URL": base_url,
            "TMPDIR": str(tmp_path),
        }
        result = subprocess.run(
            ["bash", "-c", _walkthrough_block()],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    finally:
        _stop_process(process)

    assert result is not None
    assert result.returncode == 0, result.stdout + result.stderr
    assert "health=ok" in result.stdout
    assert "read_file=PERMIT" in result.stdout
    assert "delete_file=DENY" in result.stdout
    assert "attest=signed-token-created" in result.stdout
    assert "session=ended" in result.stdout
    assert "metrics=prometheus-ok" in result.stdout
    assert API_TOKEN not in result.stdout + result.stderr
    assert list(tmp_path.glob("ardur-evaluator-*.??????")) == []


def test_evaluator_guide_has_no_stale_curl_contracts() -> None:
    guide = GUIDE.read_text(encoding="utf-8")
    curl_blocks = [
        block
        for block in re.findall(r"```bash\n(.*?)\n```", guide, flags=re.DOTALL)
        if re.search(r"\bcurl\b", block)
    ]

    assert curl_blocks == [_walkthrough_block()]
    assert '"tool":' not in guide
    assert '"resource":' not in guide
    assert '"action":' not in guide
    assert '"decision":"allow"' not in guide
    assert '"decision":"deny"' not in guide
    assert "printenv ARDUR_API_TOKEN" not in guide


def test_readme_routes_authenticated_evaluators_to_the_tested_guide() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "[MVP evaluator guide](docs/mvp-evaluator-guide.md)" in readme
    assert "evaluator guide is being refreshed" not in readme
