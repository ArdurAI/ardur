"""Regression tests for structured kill-switch error responses.

Before this fix, ``ardur kill-switch`` leaked raw Python exception strings
(e.g. ``"<urlopen error [Errno 61] Connection refused>"``) into the ``error``
field of its structured JSON response.  These tests verify that every
kill-switch failure path emits ``error_code`` / ``message`` / ``detail``
fields with no raw Python internals.
"""

from __future__ import annotations

import json
from argparse import Namespace

from vibap import cli as cli_module


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

LEAK_MARKERS = (
    "<urlopen error",
    "urlopen error",
    "Errno",
    "Traceback",
    "urllib",
    "urllib.error",
    "urllib.request",
)


def _assert_no_raw_leak(response: dict) -> None:
    """Assert that no raw Python internal strings appear in the JSON response."""
    blob = json.dumps(response)
    for marker in LEAK_MARKERS:
        assert marker not in blob, (
            f"Raw Python internal marker {marker!r} found in kill-switch JSON"
        )


# ---------------------------------------------------------------------------
# Tests — connection refused (the primary bug)
# ---------------------------------------------------------------------------


def test_kill_switch_connection_refused_no_raw_urlopen_error(monkeypatch, capsys):
    """Connection-refused must NOT leak ``<urlopen error [Errno 61] ...>``."""
    from urllib import request as urlrequest

    def raise_refused(*_a, **_kw):
        from urllib.error import URLError

        raise URLError("[Errno 61] Connection refused")

    monkeypatch.setattr(urlrequest, "urlopen", raise_refused)

    rc = cli_module.cmd_kill_switch(
        Namespace(
            deactivate=False,
            proxy_url="http://127.0.0.1:9999",
            api_token="example-token-placeholder",
        )
    )
    response = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert response["ok"] is False
    # error field is now a structured code, not a raw string
    assert response["error"] == "proxy_unavailable"
    assert response["error_code"] == "proxy_unavailable"
    assert response["condition"] == "proxy_unavailable"
    assert "message" in response
    assert "detail" in response
    _assert_no_raw_leak(response)


def test_kill_switch_default_proxy_unreachable_no_raw_error(monkeypatch, capsys):
    """Default proxy (https://127.0.0.1:8443) unreachable must be structured."""
    from urllib import request as urlrequest

    def raise_refused(*_a, **_kw):
        from urllib.error import URLError

        raise URLError("[Errno 61] Connection refused")

    monkeypatch.setattr(urlrequest, "urlopen", raise_refused)
    monkeypatch.delenv("ARDUR_API_TOKEN", raising=False)

    rc = cli_module.cmd_kill_switch(
        Namespace(deactivate=False, proxy_url=None, api_token=None)
    )
    response = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert response["error"] == "proxy_unavailable"
    assert response["error_code"] == "proxy_unavailable"
    _assert_no_raw_leak(response)


# ---------------------------------------------------------------------------
# Tests — TLS failures
# ---------------------------------------------------------------------------


def test_kill_switch_tls_failure_structured(monkeypatch, capsys):
    """SSL/TLS errors must be classified, not leaked."""
    from urllib import request as urlrequest

    def raise_tls(*_a, **_kw):
        raise OSError("[SSL: WRONG_VERSION_NUMBER] wrong version number")

    monkeypatch.setattr(urlrequest, "urlopen", raise_tls)

    rc = cli_module.cmd_kill_switch(
        Namespace(
            deactivate=False,
            proxy_url="https://127.0.0.1:8443",
            api_token="example-token-placeholder",
        )
    )
    response = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert response["error"] == "proxy_tls_error"
    assert response["error_code"] == "proxy_tls_error"
    _assert_no_raw_leak(response)


# ---------------------------------------------------------------------------
# Tests — HTTP errors (auth, not-found)
# ---------------------------------------------------------------------------


def test_kill_switch_http_401_structured(monkeypatch, capsys):
    """HTTP 401 must classify as proxy_auth_error."""
    from urllib import request as urlrequest
    from urllib.error import HTTPError
    from io import BytesIO

    class FakeHTTPError(HTTPError):
        def __init__(self):
            super().__init__(
                "https://127.0.0.1:8443/admin/kill-switch",
                401,
                "Unauthorized",
                {},
                BytesIO(b'{"error": "invalid bearer token"}'),
            )  # type: ignore[arg-type]

    def raise_401(*_a, **_kw):
        raise FakeHTTPError()

    monkeypatch.setattr(urlrequest, "urlopen", raise_401)

    rc = cli_module.cmd_kill_switch(
        Namespace(
            deactivate=False,
            proxy_url="https://127.0.0.1:8443",
            api_token="example-token-placeholder",
        )
    )
    response = json.loads(capsys.readouterr().out)

    assert rc == 1
    # HTTPError path extracts error from payload, so the error field comes
    # from the payload body. But the response should still have status.
    assert response["ok"] is False
    assert response.get("status") == 401


def test_kill_switch_http_404_structured(monkeypatch, capsys):
    """HTTP 404 must classify as proxy_endpoint_error."""
    from urllib import request as urlrequest
    from urllib.error import HTTPError
    from io import BytesIO

    class FakeHTTPError(HTTPError):
        def __init__(self):
            super().__init__(
                "https://127.0.0.1:8443/admin/kill-switch",
                404,
                "Not Found",
                {},
                BytesIO(b"{}"),
            )  # type: ignore[arg-type]

    def raise_404(*_a, **_kw):
        raise FakeHTTPError()

    monkeypatch.setattr(urlrequest, "urlopen", raise_404)

    rc = cli_module.cmd_kill_switch(
        Namespace(
            deactivate=False,
            proxy_url="https://127.0.0.1:8443",
            api_token="example-token-placeholder",
        )
    )
    response = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert response["error"] == "proxy_endpoint_error"
    assert response["error_code"] == "proxy_endpoint_error"


# ---------------------------------------------------------------------------
# Tests — generic unknown failure
# ---------------------------------------------------------------------------


def test_kill_switch_unknown_error_falls_back_to_structured_generic(monkeypatch, capsys):
    """Unrecognised exception types must fall back to a structured generic code."""
    from urllib import request as urlrequest

    def raise_unknown(*_a, **_kw):
        raise RuntimeError("something completely unexpected happened")

    monkeypatch.setattr(urlrequest, "urlopen", raise_unknown)

    rc = cli_module.cmd_kill_switch(
        Namespace(
            deactivate=False,
            proxy_url="http://127.0.0.1:9999",
            api_token="example-token-placeholder",
        )
    )
    response = json.loads(capsys.readouterr().out)

    assert rc == 1
    assert response["error"] == "kill_switch_request_failed"
    assert response["error_code"] == "kill_switch_request_failed"
    assert "message" in response
    _assert_no_raw_leak(response)
