"""Test that `ardur run` rejects empty/whitespace-only --output and --home."""

import json
import subprocess
import sys

import pytest

VENV_PYTHON = "/tmp/ardur-dx-probe-20260811T0808/python/.venv/bin/python"


def _run_ardur(*args: str) -> subprocess.CompletedProcess[str]:
    """Run `ardur run` with the given arguments and return the CompletedProcess."""
    cmd = [VENV_PYTHON, "-m", "vibap.cli", "run", *args]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _assert_path_arg_invalid(result: subprocess.CompletedProcess[str]) -> None:
    """Assert that the result is a path_arg_invalid JSON error with exit code 1."""
    assert result.returncode == 1, (
        f"Expected exit code 1, got {result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        pytest.fail(f"stdout is not valid JSON:\n{result.stdout}")
    assert data.get("error") == "path_arg_invalid", (
        f"Expected error='path_arg_invalid', got {data}"
    )


# ── --output tests ──────────────────────────────────────────────────────

def test_run_output_empty():
    """ardur run --output \"\" -- /bin/echo hello → path_arg_invalid"""
    result = _run_ardur("--output", "", "--", "/bin/echo", "hello")
    _assert_path_arg_invalid(result)


def test_run_output_whitespace():
    """ardur run --output \"   \" -- /bin/echo hello → path_arg_invalid"""
    result = _run_ardur("--output", "   ", "--", "/bin/echo", "hello")
    _assert_path_arg_invalid(result)


# ── --output + governance (--mission) tests ────────────────────────────

def test_run_governance_output_empty():
    """ardur run --mission test --output \"\" -- /bin/echo hello → path_arg_invalid"""
    result = _run_ardur("--mission", "test", "--output", "", "--", "/bin/echo", "hello")
    _assert_path_arg_invalid(result)


def test_run_governance_output_whitespace():
    """ardur run --mission test --output \"   \" -- /bin/echo hello → path_arg_invalid"""
    result = _run_ardur("--mission", "test", "--output", "   ", "--", "/bin/echo", "hello")
    _assert_path_arg_invalid(result)


# ── --home tests ───────────────────────────────────────────────────────
# --home is validated by argparse itself (exit code 2, stderr message),
# not by _path_arg_invalid_failure.  The guard is still in place — it just
# fires earlier in the argument-parsing layer.

def test_run_home_empty():
    """ardur run --home \"\" -- /bin/echo hello → argparse error, exit code 2"""
    result = _run_ardur("--home", "", "--", "/bin/echo", "hello")
    assert result.returncode == 2, (
        f"Expected exit code 2, got {result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "must be a non-empty path" in result.stderr


def test_run_home_whitespace():
    """ardur run --home \"   \" -- /bin/echo hello → argparse error, exit code 2"""
    result = _run_ardur("--home", "   ", "--", "/bin/echo", "hello")
    assert result.returncode == 2, (
        f"Expected exit code 2, got {result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "must be a non-empty path" in result.stderr
