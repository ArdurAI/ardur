"""Regression tests for port-in-use structured errors on ``ardur start`` and ``ardur hub``.

Both server-starting commands previously produced a raw Python traceback
(``OSError: [Errno 48] Address already in use``) when the configured port was
occupied. These tests verify that both now emit a structured JSON error with
``start_port_in_use`` / ``hub_port_in_use`` error codes.
"""

from __future__ import annotations

import errno
import json
import socket

import pytest


def _occupy_port() -> tuple[int, socket.socket]:
    """Bind a dummy socket on an ephemeral port and return (port, socket)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    return s.getsockname()[1], s


@pytest.fixture()
def occupied_port():
    port, sock = _occupy_port()
    yield port
    sock.close()


# ── cmd_start port-in-use ────────────────────────────────────────────────────


def test_start_port_in_use_emits_structured_json(occupied_port, tmp_path, capsys):
    """``ardur start`` on an occupied port emits ``start_port_in_use`` JSON."""
    from vibap.cli import cmd_start
    import argparse

    keys_dir = tmp_path / "keys"
    state_dir = tmp_path / "state"
    log_path = tmp_path / "audit.log"
    keys_dir.mkdir()
    state_dir.mkdir()

    args = argparse.Namespace(
        mission=None,
        keys_dir=str(keys_dir),
        state_dir=str(state_dir),
        log_path=str(log_path),
        host="127.0.0.1",
        port=occupied_port,
        require_auth=False,
        api_token=None,
        tls_cert=None,
        tls_key=None,
        no_tls=True,
    )

    rc = cmd_start(args)
    captured = capsys.readouterr()
    assert rc == 1
    data = json.loads(captured.out)
    assert data["ok"] is False
    assert data["error"] == "start_port_in_use"
    assert data["error_code"] == "start_port_in_use"
    assert data["condition"] == "start_port_in_use"
    assert "next_steps" in data
    assert len(data["next_steps"]) >= 1
    assert data["next_steps"][0]["action"] == "choose_available_start_port"
    # No traceback in stderr
    assert "Traceback" not in captured.err


# ── cmd_hub port-in-use ──────────────────────────────────────────────────────


def test_hub_port_in_use_emits_structured_json(occupied_port, tmp_path, capsys):
    """``ardur hub`` on an occupied port emits ``hub_port_in_use`` JSON."""
    from vibap.cli import cmd_hub
    import argparse

    home = tmp_path / "ardur-home"
    home.mkdir()

    args = argparse.Namespace(
        host="127.0.0.1",
        port=occupied_port,
        home=str(home),
        tls_cert=None,
        tls_key=None,
        no_tls=True,
    )

    rc = cmd_hub(args)
    captured = capsys.readouterr()
    assert rc == 1
    data = json.loads(captured.out)
    assert data["ok"] is False
    assert data["error"] == "hub_port_in_use"
    assert data["error_code"] == "hub_port_in_use"
    assert data["condition"] == "hub_port_in_use"
    assert "next_steps" in data
    assert len(data["next_steps"]) >= 1
    assert data["next_steps"][0]["action"] == "choose_available_hub_port"
    # No traceback in stderr
    assert "Traceback" not in captured.err


# ── response helper unit tests ───────────────────────────────────────────────


def test_start_port_in_use_response_shape():
    from vibap.cli import _start_port_in_use_response

    resp = _start_port_in_use_response()
    assert resp["ok"] is False
    assert resp["error"] == "start_port_in_use"
    assert resp["error_code"] == "start_port_in_use"
    assert resp["condition"] == "start_port_in_use"
    assert isinstance(resp["next_steps"], list)
    assert resp["next_steps"][0]["action"] == "choose_available_start_port"


def test_hub_port_in_use_response_shape():
    from vibap.cli import _hub_port_in_use_response

    resp = _hub_port_in_use_response()
    assert resp["ok"] is False
    assert resp["error"] == "hub_port_in_use"
    assert resp["error_code"] == "hub_port_in_use"
    assert resp["condition"] == "hub_port_in_use"
    assert isinstance(resp["next_steps"], list)
    assert resp["next_steps"][0]["action"] == "choose_available_hub_port"


# ── non-EADDRINUSE OSError re-raises (not swallowed) ────────────────────────


def test_start_non_addrinuse_oserror_reraises(tmp_path):
    """OSError without EADDRINUSE should re-raise, not be swallowed."""
    from vibap import cli as cli_module
    import argparse

    keys_dir = tmp_path / "keys"
    state_dir = tmp_path / "state"
    log_path = tmp_path / "audit.log"
    keys_dir.mkdir()
    state_dir.mkdir()

    args = argparse.Namespace(
        mission=None,
        keys_dir=str(keys_dir),
        state_dir=str(state_dir),
        log_path=str(log_path),
        host="127.0.0.1",
        port=0,  # port 0 = ephemeral, won't conflict
        require_auth=False,
        api_token=None,
        tls_cert=None,
        tls_key=None,
        no_tls=True,
    )

    original_serve_proxy = cli_module.serve_proxy

    def raise_permission_denied(**_kwargs):
        raise PermissionError(errno.EACCES, "Permission denied")

    cli_module.serve_proxy = raise_permission_denied
    try:
        with pytest.raises(PermissionError):
            cli_module.cmd_start(args)
    finally:
        cli_module.serve_proxy = original_serve_proxy
