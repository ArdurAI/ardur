"""Organic CLI argument-loading coverage for proxy bearer-token normalization.

The lower-level HTTP characterization passes ``api_token`` directly to
``serve_proxy``. This module deliberately crosses the real module entrypoint,
argument parser, command dispatch, startup, and HTTP authentication boundary.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


_PYTHON_ROOT = Path(__file__).resolve().parents[1]


def _wait_for_health(process: subprocess.Popen[str], base_url: str) -> None:
    deadline = time.monotonic() + 8
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(
                f"ardur start exited before health check: rc={process.returncode}"
            )
        try:
            with urllib.request.urlopen(base_url + "/health", timeout=0.5) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError) as exc:
            last_error = exc
            time.sleep(0.05)
    raise AssertionError(f"ardur start did not become healthy: {last_error}")


def _post_issue_with_bearer(
    base_url: str,
    token: str | None,
) -> tuple[int, dict[str, object]]:
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        base_url + "/issue",
        data=b"{}",
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return int(response.status), json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return int(exc.code), json.loads(exc.read().decode("utf-8"))


def _stop_process(process: subprocess.Popen[str]) -> tuple[str, str]:
    # Drain the pipes as part of the wait. ``process.wait()`` on a PIPE-backed
    # child deadlocks once the child has filled a pipe buffer, which would turn
    # a chatty CLI into a spurious timeout/kill.
    if process.poll() is None:
        process.terminate()
        try:
            return process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
    return process.communicate(timeout=5)


def test_start_cli_trims_padded_api_token_through_real_argument_loading(
    tmp_path: Path,
    unused_tcp_port: int,
) -> None:
    canonical_token = "cli-test-token-32-bytes-DEFGHIJ"
    environment = dict(os.environ)
    environment.pop("VIBAP_API_TOKEN", None)
    environment["PYTHONPATH"] = str(_PYTHON_ROOT)
    base_url = f"http://127.0.0.1:{unused_tcp_port}"
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "vibap.cli",
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
            str(tmp_path / "audit.log"),
            "--api-token",
            f"   {canonical_token}   ",
            "--no-tls",
        ],
        cwd=tmp_path,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for_health(process, base_url)

        missing_status, missing_body = _post_issue_with_bearer(base_url, None)
        wrong_status, wrong_body = _post_issue_with_bearer(
            base_url,
            "synthetic-wrong-token",
        )
        canonical_status, canonical_body = _post_issue_with_bearer(
            base_url,
            canonical_token,
        )

        assert missing_status == 401
        assert missing_body["error"] == "missing or malformed Authorization header"
        assert wrong_status == 401
        assert wrong_body["error"] == "invalid bearer token"
        # The trimmed token must get PAST authentication. Asserting only
        # ``!= 401`` would also pass on a 500, so pin the specific post-auth
        # outcome instead: this request carries an empty ``{}`` body, so
        # reaching missing-field validation is itself the proof that the
        # bearer token was accepted.
        assert canonical_status == 400, canonical_body
        assert "agent_id" in canonical_body["error"], canonical_body
    finally:
        stdout, stderr = _stop_process(process)

    assert process.returncode is not None
    assert "source=argument" in stderr
    assert "token=redacted" in stderr
    assert canonical_token not in stdout
    assert canonical_token not in stderr
