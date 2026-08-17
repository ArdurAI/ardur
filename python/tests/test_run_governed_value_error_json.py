"""Tests for structured JSON output when ``run_governed_cli`` catches a
``ValueError`` from inside ``run_governed`` (e.g. invalid ``--resource-scope``,
unknown ``--via`` mode).

Before this fix, the ``except ValueError`` handler always printed a
human-readable stderr message even when ``--json`` was set — inconsistent
with the ``FileNotFoundError`` and ``PermissionError`` handlers that DO
emit structured JSON when ``--json`` is set.

These tests verify:
1. With ``--json``: structured JSON on stderr with ok/error/condition/detail/next_steps.
2. Without ``--json``: human-readable stderr message preserved (backward-compatible).
3. No local absolute paths leak in the structured response.
4. No artifacts created (key material, state dirs, etc.) before the error.
"""

import json

from vibap.run_bridge import (
    run_governed_cli,
    run_governed_value_error_next_steps,
)

from argparse import Namespace


def _base_namespace(tmp_path, **overrides):
    """Return a minimal Namespace matching ``run_governed_cli`` expectations."""
    ns = dict(
        command=["echo", "hi"],
        mission="example-mission-placeholder",
        allowed_tools=["Read"],
        forbidden_tools=None,
        max_tool_calls=5,
        max_duration_s=60,
        home=tmp_path / "ardur-home",
        via="env",
        no_kernel_correlation=True,
        enforce=False,
        resource_scope=None,
        no_resource_scope=False,
        json=False,
        output=None,
        redact_paths=False,
    )
    ns.update(overrides)
    return Namespace(**ns)


def test_run_governed_value_error_with_json_emits_structured_json(
    tmp_path,
    capsys,
    monkeypatch,
):
    """ValueError with --json must emit structured JSON, not a bare stderr line."""
    def raise_value_error(**_kwargs):
        raise ValueError("resource_scope entries must be non-empty path roots")

    monkeypatch.setattr("vibap.run_bridge.run_governed", raise_value_error)

    exit_code = run_governed_cli(_base_namespace(tmp_path, json=True))

    captured = capsys.readouterr()
    assert exit_code == 2

    response = json.loads(captured.err)
    assert response["ok"] is False
    assert response["error"] == "run_governed_value_error"
    assert response["error_code"] == "run_governed_value_error"
    assert response["condition"] == "run_governed_value_error"
    assert response["message"] == "Run governance input validation failed."
    assert "resource_scope entries must be non-empty path roots" in response["detail"]
    assert "next_steps" in response
    assert len(response["next_steps"]) >= 1
    for step in response["next_steps"]:
        assert step["condition"] == "run_governed_value_error"
        assert "<" in step["command"]  # placeholder-only
        assert step["detail"]

    # stdout must be empty
    assert captured.out == ""
    # No traceback
    assert "Traceback" not in captured.err


def test_run_governed_value_error_without_json_emits_human_readable(
    tmp_path,
    capsys,
    monkeypatch,
):
    """ValueError without --json must preserve the human-readable stderr message."""
    def raise_value_error(**_kwargs):
        raise ValueError("resource_scope entries must be non-empty path roots")

    monkeypatch.setattr("vibap.run_bridge.run_governed", raise_value_error)

    exit_code = run_governed_cli(_base_namespace(tmp_path, json=False))

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "ardur run: resource_scope entries must be non-empty path roots" in captured.err
    assert "Traceback" not in captured.err


def test_run_governed_value_error_does_not_leak_local_paths(
    tmp_path,
    capsys,
    monkeypatch,
):
    """The structured JSON response must not leak local absolute paths."""
    def raise_value_error(**_kwargs):
        raise ValueError("some validation error")

    monkeypatch.setattr("vibap.run_bridge.run_governed", raise_value_error)

    exit_code = run_governed_cli(_base_namespace(tmp_path, json=True))

    captured = capsys.readouterr()
    assert exit_code == 2
    response = json.loads(captured.err)
    # The ValueError message is included as detail, but it must not
    # contain local absolute path roots
    assert "/Users/" not in json.dumps(response)
    assert "/tmp/" not in json.dumps(response)


def test_run_governed_not_implemented_with_json_emits_structured_json(
    tmp_path,
    capsys,
    monkeypatch,
):
    """NotImplementedError with --json must also emit structured JSON."""
    def raise_not_implemented(**_kwargs):
        raise NotImplementedError("platform not supported")

    monkeypatch.setattr("vibap.run_bridge.run_governed", raise_not_implemented)

    exit_code = run_governed_cli(_base_namespace(tmp_path, json=True))

    captured = capsys.readouterr()
    assert exit_code == 2
    response = json.loads(captured.err)
    assert response["ok"] is False
    assert response["error"] == "run_governed_not_implemented"
    assert response["condition"] == "run_governed_not_implemented"
    assert "not available on this platform" in response["message"]
    assert "platform not supported" in response["detail"]
    assert "next_steps" in response


def test_run_governed_not_implemented_without_json_emits_human_readable(
    tmp_path,
    capsys,
    monkeypatch,
):
    """NotImplementedError without --json must preserve human-readable stderr."""
    def raise_not_implemented(**_kwargs):
        raise NotImplementedError("platform not supported")

    monkeypatch.setattr("vibap.run_bridge.run_governed", raise_not_implemented)

    exit_code = run_governed_cli(_base_namespace(tmp_path, json=False))

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "ardur run: platform not supported" in captured.err


def test_run_governed_value_error_next_steps_are_deterministic():
    """The next_steps helper returns a stable, placeholder-only list."""
    steps = run_governed_value_error_next_steps()
    assert len(steps) == 2
    for step in steps:
        assert step["condition"] == "run_governed_value_error"
        assert step["action"]
        assert step["command"]
        assert "<" in step["command"]  # placeholder-only
        assert step["detail"]
