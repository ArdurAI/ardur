"""Whitespace-only --api-token rejection on ``ardur kill-switch``.

Sibling to the existing ``start --api-token`` and
``status/doctor/desktop-observe --hub-token`` whitespace guards.

``cmd_kill_switch`` resolves the bearer token via
``args.api_token or os.environ.get("ARDUR_API_TOKEN", "")``. A whitespace-
only ``--api-token`` is truthy, so it shadows any ``ARDUR_API_TOKEN`` and
is sent verbatim as ``Bearer "  "`` to the loopback governance proxy admin
endpoint, producing a confusing 401/``Connection refused`` instead of a
clear CLI-layer rejection. The guard added alongside these tests rejects
whitespace-only tokens before any network call.

An unset ``--api-token`` (None) and an empty string ``""`` (falsy,
falls through to ``ARDUR_API_TOKEN``) remain valid: only whitespace-only
strings are rejected, matching the silent-empty-token bug class already
closed for ``start --api-token`` and ``kill-switch --proxy-url``.
"""

from __future__ import annotations

import argparse
import json
from urllib import request as urlrequest

import pytest

from vibap import cli as cli_module


def _namespace(**overrides) -> argparse.Namespace:
    base = dict(deactivate=False, proxy_url="https://127.0.0.1:8443", api_token=None)
    base.update(overrides)
    return argparse.Namespace(**base)


# ---------------------------------------------------------------------------
# Test 1: empty / unset / valid tokens are accepted (fall through to env).
#
# The guard must return ``None`` for everything except whitespace-only
# strings, so the existing ``args.api_token or os.environ.get(...)``
# fallthrough behavior is unchanged. Empty string ``""`` is intentionally
# NOT rejected (it is falsy and falls through to ``ARDUR_API_TOKEN``).
# ---------------------------------------------------------------------------

def test_kill_switch_api_token_empty_unset_and_valid_fall_through():
    """Only whitespace-only is rejected; everything else returns None."""
    ns_unset = _namespace(api_token=None)
    assert cli_module._kill_switch_api_token_invalid_failure(ns_unset) is None

    ns_empty = _namespace(api_token="")
    assert cli_module._kill_switch_api_token_invalid_failure(ns_empty) is None

    ns_valid = _namespace(api_token="real-token-value")
    assert cli_module._kill_switch_api_token_invalid_failure(ns_valid) is None


# ---------------------------------------------------------------------------
# Test 2: whitespace-only --api-token is rejected before the network call.
#
# Parametrized over the same whitespace shapes the ``start --api-token``
# guard covers. ``urlopen`` is monkeypatched to fail the test if reached,
# proving the guard fires pre-network.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("token_value", ["   ", "\t", "\n", " \t\n \t"])
def test_kill_switch_api_token_whitespace_returns_invalid_before_network(
    monkeypatch, capsys, token_value
):
    """Whitespace-only --api-token returns kill_switch_api_token_invalid (exit 1)."""

    def fail_if_urlopen_reached(*_args, **_kwargs):
        pytest.fail(
            "whitespace-only kill-switch --api-token must fail before urlopen"
        )

    monkeypatch.setattr(urlrequest, "urlopen", fail_if_urlopen_reached)

    rc = cli_module.cmd_kill_switch(_namespace(api_token=token_value))
    captured = capsys.readouterr()
    response = json.loads(captured.out)

    assert rc == 1
    assert captured.err == ""
    assert response["ok"] is False
    assert response["error"] == "kill_switch_api_token_invalid"
    assert response["error_code"] == "kill_switch_api_token_invalid"
    assert response["condition"] == "kill_switch_api_token_invalid"
    assert "api-token" in response["message"].lower().replace("-", "-")
    assert "whitespace" in response["message"].lower()
    assert response["next_steps"]

    rendered = json.dumps(response)
    # Placeholder-only remediation; no raw token or echo of the whitespace.
    assert "<api-token>" in rendered
    assert "<proxy-url>" in rendered
    assert token_value not in rendered
    # No traceback, no network-layer artifact leaks into the CLI response.
    assert "Traceback" not in rendered
    assert "urlopen error" not in rendered
    assert "Connection refused" not in rendered


# ---------------------------------------------------------------------------
# Test 3: a valid token still proceeds to the network call.
#
# The guard must not short-circuit real tokens. We assert the network layer
# is reached (and produces the documented proxy-unavailable failure), which
# is the pre-fix behavior.
# ---------------------------------------------------------------------------

def test_kill_switch_api_token_valid_proceeds_to_network(monkeypatch, capsys):
    """A real --api-token must NOT be rejected by the guard; it reaches urlopen."""

    called = {"count": 0}

    def fake_urlopen(*_args, **_kwargs):
        called["count"] += 1
        raise OSError("connection refused")

    monkeypatch.setattr(urlrequest, "urlopen", fake_urlopen)

    cli_module.cmd_kill_switch(_namespace(api_token="real-token-value"))
    captured = capsys.readouterr()
    response = json.loads(captured.out)

    # The guard did not fire (otherwise error/condition would be
    # kill_switch_api_token_invalid). The request reached urlopen and hit the
    # documented proxy-unavailable failure path instead.
    assert called["count"] == 1
    rendered = json.dumps(response)
    assert "kill_switch_api_token_invalid" not in rendered
    assert response["ok"] is False
    # The real token must not leak into the CLI JSON response.
    assert "real-token-value" not in rendered
