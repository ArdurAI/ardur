"""Regression tests for HTTP/CLI catch-all exception sanitization gaps.

These tests pin the contract that catch-all exception handlers in the
Personal Hub HTTP server, the VIBAP proxy GET handler, the native host
message handler, and several CLI command error paths never leak
``str(exc)`` from generic ``Exception`` subclasses to callers.

The invariant: a raw ``str(exc)`` from arbitrary exceptions
(``OSError``, ``KeyError``, ``AttributeError``, cryptography faults)
can carry filesystem paths, errno details, Python internals, and
stack-trace fragments. These must be replaced with generic safe
messages while the full exception is logged for operator triage.
"""

from __future__ import annotations

import inspect
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from unittest.mock import patch

import pytest


# ─── personal_hub.py: catch-all handler ────────────────────────────


class TestPersonalHubCatchAllSanitization:
    """The Personal Hub HTTP handler catch-all must not leak str(exc)."""

    def test_catch_all_no_str_exc_in_source(self) -> None:
        """Source inspection: the catch-all must use a generic message."""
        from vibap import personal_hub

        # Find _HubRequestHandler.do_POST source
        source = inspect.getsource(personal_hub)
        # The old pattern: "error": str(exc) in the internal_error catch-all
        # After the fix, the except clause binds no name and uses a literal.
        # Check the specific dangerous pattern is gone.
        do_post_section = source[source.index("def do_POST") : source.index("def do_POST") + 5000]
        assert '"error": str(exc), "error_code": "internal_error"' not in do_post_section, (
            "personal_hub do_POST catch-all still leaks str(exc) in internal_error response"
        )

    def test_hub_request_fallback_no_str_exc(self) -> None:
        """hub_request HTTPError fallback must not leak str(exc)."""
        from vibap import personal_hub

        source = inspect.getsource(personal_hub.hub_request)
        assert 'str(exc)' not in source, (
            "hub_request fallback still leaks str(exc) from HTTPError"
        )

    def test_hub_request_returns_safe_error_on_non_json_body(self) -> None:
        """When the Hub returns a non-JSON error body, the error must be generic."""
        from vibap.personal_hub import hub_request

        fake_response = urllib.error.HTTPError(
            url="https://127.0.0.1:8765/v1/test",
            code=500,
            msg="Internal Server Error",
            hdrs=None,  # type: ignore[arg-type]
            fp=None,
        )

        with patch("vibap.personal_hub.urlrequest.urlopen", side_effect=fake_response):
            result = hub_request("POST", "/v1/test", payload={})

        assert result["ok"] is False
        assert result["error"] == "hub_error"
        assert "Internal Server Error" not in json.dumps(result)


# ─── proxy.py: do_GET handler ──────────────────────────────────────


class TestProxyDoGetSanitization:
    """The proxy do_GET handler must have a catch-all exception handler."""

    def test_do_get_has_exception_handler(self) -> None:
        """Source inspection: do_GET must wrap its body in try/except."""
        from vibap.proxy import serve_proxy

        source = inspect.getsource(serve_proxy)
        # Find the do_GET method within serve_proxy
        do_get_start = source.index("def do_GET")
        do_post_start = source.index("def do_POST")
        do_get_source = source[do_get_start:do_post_start]

        assert "except Exception" in do_get_source, (
            "proxy do_GET has no catch-all exception handler"
        )
        assert '"error": "internal server error"' in do_get_source, (
            "proxy do_GET catch-all does not return a safe error message"
        )


# ─── ardur_personal_native_host.py: catch-all ──────────────────────


class TestNativeHostCatchAllSanitization:
    """The native host message handler catch-all must not leak str(exc)."""

    def test_catch_all_no_str_exc(self) -> None:
        """Source inspection: native host catch-all must not use str(exc)."""
        from vibap import ardur_personal_native_host

        source = inspect.getsource(ardur_personal_native_host)
        assert '"error": str(exc)' not in source, (
            "native host catch-all still leaks str(exc) in error response"
        )


# ─── cli.py: error path sanitization ──────────────────────────────


class TestCliVerifyFailureResponseSanitization:
    """_verify_failure_response must use _safe_exception_message."""

    def test_uses_safe_exception_message(self) -> None:
        """Source inspection: _verify_failure_response must not use str(exc)."""
        from vibap.cli import _verify_failure_response

        source = inspect.getsource(_verify_failure_response)
        assert "str(exc)" not in source, (
            "_verify_failure_response still uses raw str(exc) for detail"
        )
        assert "_safe_exception_message" in source, (
            "_verify_failure_response does not use _safe_exception_message"
        )

    def test_oserror_detail_is_class_name(self) -> None:
        """An OSError must not leak its path in the detail field."""
        from vibap.cli import _verify_failure_response

        exc = OSError("[Errno 2] No such file or directory: '/secret/path/keys.pem'")
        result = _verify_failure_response(exc)
        assert "/secret/path" not in result["detail"]
        assert "keys.pem" not in result["detail"]
        assert "OSError" in result["detail"]


class TestCliEvidenceCorrelateSanitization:
    """cmd_evidence_correlate must not leak str(exc) for TypeError/ValueError."""

    def test_type_value_error_split_from_domain(self) -> None:
        """Source inspection: TypeError/ValueError must use _safe_exception_message."""
        from vibap.cli import cmd_evidence_correlate

        source = inspect.getsource(cmd_evidence_correlate)
        # After the fix, TypeError/ValueError should be in a separate handler
        # that uses _safe_exception_message.
        assert "TypeError" in source, "TypeError not handled at all"
        assert "ValueError" in source, "ValueError not handled at all"
        # The combined handler must not use str(exc) for TypeError/ValueError
        # Check that the TypeError/ValueError path uses _safe_exception_message
        assert "_safe_exception_message" in source, (
            "cmd_evidence_correlate does not use _safe_exception_message for sanitization"
        )


class TestCliVerifyReceiverAttestationSanitization:
    """_cmd_verify_receiver_attestation must sanitize OSError/ValueError."""

    def test_oserror_value_error_use_safe_message(self) -> None:
        """Source inspection: OSError/ValueError must use _safe_exception_message."""
        from vibap.cli import _cmd_verify_receiver_attestation

        source = inspect.getsource(_cmd_verify_receiver_attestation)
        assert "_safe_exception_message" in source, (
            "_cmd_verify_receiver_attestation does not use _safe_exception_message"
        )


# ─── Integration: proxy GET exception returns safe 500 ─────────────


class TestProxyGetExceptionReturns500:
    """An exception during GET handling must return a safe 500, not a traceback."""

    def test_get_metrics_exception_returns_safe_500(
        self, tmp_path, proxy, private_key
    ) -> None:
        """If metrics.render() raises, the GET response must be a safe JSON 500."""
        import signal as _signal

        from vibap.proxy import serve_proxy

        original = _signal.signal
        _signal.signal = lambda *_a, **_kw: None  # type: ignore[assignment]

        port = _free_port()

        def run() -> None:
            try:
                serve_proxy(
                    proxy=proxy,
                    private_key=private_key,
                    host="127.0.0.1",
                    port=port,
                    require_auth=False,
                    no_tls=True,
                )
            except Exception:  # noqa: BLE001
                pass

        thread = threading.Thread(target=run, daemon=True)
        thread.start()

        base = f"http://127.0.0.1:{port}"
        deadline = time.time() + 5
        last_exc: Exception | None = None
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(base + "/health", timeout=0.5) as resp:
                    if resp.status == 200:
                        break
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                time.sleep(0.05)
        else:
            _signal.signal = original
            pytest.fail(f"proxy never became healthy: {last_exc}")

        try:
            # Patch metrics.render to raise during GET /metrics
            with patch("vibap.proxy.ardur_metrics") as mock_metrics:
                mock_metrics.render.side_effect = RuntimeError(
                    "secret internal path /Users/gnutakki/.ardur/keys"
                )
                mock_metrics.requests_total.inc.return_value = None
                req = urllib.request.Request(base + "/metrics")
                try:
                    urllib.request.urlopen(req, timeout=2)
                except urllib.error.HTTPError as exc:
                    body = exc.read().decode("utf-8")
                    assert exc.code == 500
                    parsed = json.loads(body)
                    assert parsed["error"] == "internal server error"
                    assert "secret internal path" not in body
                    assert "RuntimeError" not in body
                    assert "/Users/" not in body
                else:
                    pytest.fail("Expected HTTPError 500 but got success")
        finally:
            _signal.signal = original


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
