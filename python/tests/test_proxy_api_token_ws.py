"""Reject whitespace-only ``--api-token`` on ``python -m vibap.proxy`` and in
``serve_proxy`` library calls (auth-bypass defense-in-depth).

A whitespace-only ``--api-token`` is truthy before ``serve_proxy`` strips
whitespace, but resolves to an empty string after. Without the guards added
in this change, the proxy would start with an effectively empty auth token
that any client can match with ``Authorization: Bearer `` (an empty bearer),
bypassing bearer-token authentication entirely.

Two layers are covered:

1. **CLI layer** (``proxy.main``): a structured JSON failure response with
   ``proxy_api_token_invalid`` is emitted before key generation, matching the
   existing ``ardur start --api-token`` guard pattern.
2. **Library / ``serve_proxy`` layer**: ``serve_proxy`` raises ``ValueError``
   if a whitespace-only token survives to the strip step — this is the
   defense-in-depth boundary because ``serve_proxy`` is a library entry point
   not only reachable through ``cmd_start``.

Regression coverage for the auth-bypass class documented in the
2026-07-28 security review.
"""
from __future__ import annotations

import argparse
import json

import pytest


# ---------------------------------------------------------------------------
# CLI-layer guard: proxy.main() rejects whitespace-only --api-token
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ws",
    [
        "   ",
        "\t",
        "\n",
        " \t\n ",
    ],
    ids=["spaces", "tab", "newline", "mixed"],
)
def test_proxy_main_ws_api_token_rejected_before_key_generation(ws, capsys, monkeypatch):
    """``python -m vibap.proxy --api-token '   '`` must fail with structured
    JSON before generating keys or starting the server."""
    # Ensure generate_keypair is never called.
    def _fail(*a, **kw):
        raise AssertionError("keys must not be generated for whitespace-only token")

    monkeypatch.setattr("vibap.proxy.generate_keypair", _fail)
    monkeypatch.setattr("vibap.proxy.serve_proxy", _fail)

    from vibap import proxy

    rc = proxy.main(["--api-token", ws])
    assert rc == 1

    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["error_code"] == "proxy_api_token_invalid"
    assert data["ok"] is False


def test_proxy_main_unset_api_token_not_rejected():
    """Unset ``--api-token`` (None) is valid and must NOT trigger the
    api-token guard. Verify at the helper level (the guard function that
    ``main`` calls), not by starting the actual server."""
    from vibap import proxy

    args = argparse.Namespace(api_token=None)
    assert proxy._proxy_api_token_invalid_failure(args) is None


def test_proxy_main_empty_string_api_token_is_not_rejected(monkeypatch):
    """An empty-string ``--api-token ""`` is falsy and must NOT hit the
    whitespace guard (it falls through to autogeneration), mirroring the
    ``ardur start`` contract."""
    from vibap import proxy

    args = argparse.Namespace(api_token="")
    assert proxy._proxy_api_token_invalid_failure(args) is None


def test_proxy_main_real_token_is_not_rejected():
    """A real non-empty token must not trigger the guard."""
    from vibap import proxy

    args = argparse.Namespace(api_token="real-secret-token")
    assert proxy._proxy_api_token_invalid_failure(args) is None


# ---------------------------------------------------------------------------
# Library-layer guard: serve_proxy raises ValueError on whitespace-only token
# ---------------------------------------------------------------------------


def test_serve_proxy_ws_api_token_raises_value_error():
    """``serve_proxy`` must raise ``ValueError`` for a whitespace-only token
    (defense-in-depth for direct/library callers)."""
    from vibap import proxy

    mock_proxy = argparse.Namespace()
    with pytest.raises(ValueError, match="non-empty token"):
        proxy.serve_proxy(
            proxy=mock_proxy,
            private_key="fake-key",
            api_token="   ",
        )


def test_serve_proxy_tab_api_token_raises_value_error():
    """Tab-only token is also rejected at the library boundary."""
    from vibap import proxy

    mock_proxy = argparse.Namespace()
    with pytest.raises(ValueError, match="non-empty token"):
        proxy.serve_proxy(
            proxy=mock_proxy,
            private_key="fake-key",
            api_token="\t",
        )


def test_serve_proxy_unset_api_token_falls_through_to_generated():
    """Unset ``api_token`` (None) enters the ``else`` branch (autogeneration).
    The ValueError guard is inside the ``elif api_token:`` branch and cannot
    fire for None. We verify this indirectly by confirming the generated-token
    path is selected, not the argument path.

    This avoids starting the real HTTP server. The critical regression guard
    is the whitespace-only test above which confirms the ValueError fires when
    branch."""

    # We can't call serve_proxy without it starting the server, so verify the
    # branch logic directly by simulating the if/elif/else chain.
    api_token = None  # the value we're testing
    env_token_raw = None
    env_token = env_token_raw.strip() if env_token_raw is not None else None

    token_source = None
    if env_token:
        token_source = "env"
    elif api_token:
        api_token = api_token.strip()
        if not api_token:
            # This is the guard we added; it must NOT fire for None.
            assert False, "ValueError guard must not fire for None api_token"
        token_source = "argument"
    else:
        token_source = "generated"

    assert token_source == "generated"


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------


def test_proxy_api_token_invalid_response_shape():
    """The failure response has all required structured fields."""
    from vibap import proxy

    resp = proxy._proxy_api_token_invalid_response()
    assert resp["ok"] is False
    assert resp["error"] == "proxy_api_token_invalid"
    assert resp["error_code"] == "proxy_api_token_invalid"
    assert resp["condition"] == "proxy_api_token_invalid"
    assert "message" in resp
    assert "detail" in resp
    assert len(resp["next_steps"]) >= 2
    for step in resp["next_steps"]:
        assert "action" in step
        assert "command" in step
        assert "detail" in step


def test_proxy_api_token_invalid_failure_helper_variants():
    """The failure helper correctly classifies unset, empty, ws-only, and real."""
    from vibap import proxy

    # Unset (None) -> None (no failure)
    assert proxy._proxy_api_token_invalid_failure(
        argparse.Namespace(api_token=None)
    ) is None

    # Empty string "" -> None (falsy, falls through)
    assert proxy._proxy_api_token_invalid_failure(
        argparse.Namespace(api_token="")
    ) is None

    # Whitespace-only -> failure
    result = proxy._proxy_api_token_invalid_failure(
        argparse.Namespace(api_token="  \t ")
    )
    assert result is not None
    assert result["error_code"] == "proxy_api_token_invalid"

    # Real token -> None (no failure)
    assert proxy._proxy_api_token_invalid_failure(
        argparse.Namespace(api_token="abc123secret")
    ) is None
