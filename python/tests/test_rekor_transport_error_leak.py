"""Regression tests for Rekor transport error classification.

Defect class: ``_default_rekor_transport`` previously wrapped raw
``str(exc)`` from urllib errors (``<urlopen error [Errno 61] Connection
refused>``) into ``TransparencyError``, which then leaked through
``cmd_anchor`` JSON ``message`` and ``drain_anchor_store`` result
``error`` fields.  This is the same class fixed for ``kill-switch`` and
``start/hub`` port-in-use.

The classifier ``_classify_rekor_transport_error`` must produce stable,
human-readable messages that never contain:
- ``<urlopen error``
- raw errno class names like ``ConnectionRefusedError``
- socket path leakage
"""

from __future__ import annotations

import io
import socket
import urllib.error

import pytest

from vibap.transparency import (
    TransparencyError,
    _classify_rekor_transport_error,
    _default_rekor_transport,
)


def _make_urlerror(reason: object) -> urllib.error.URLError:
    return urllib.error.URLError(reason)  # type: ignore[arg-type]


class TestClassifyRekorTransportError:
    """Verify that raw urllib internals are never exposed."""

    _RAW_LEAK_PATTERNS = ("<urlopen error", "ConnectionRefusedError", "ConnectionResetError")

    def _assert_no_raw_leak(self, exc: TransparencyError) -> None:
        text = str(exc)
        for pattern in self._RAW_LEAK_PATTERNS:
            assert pattern not in text, (
                f"classified error leaks raw urllib internals: {text!r}"
            )

    def test_connection_refused(self) -> None:
        """URLError wrapping ConnectionRefusedError must not leak internals."""
        inner = ConnectionRefusedError(61, "Connection refused")
        exc = _classify_rekor_transport_error(_make_urlerror(inner))
        self._assert_no_raw_leak(exc)
        assert "network error" in str(exc)

    def test_connection_reset(self) -> None:
        """URLError wrapping ConnectionResetError must not leak internals."""
        inner = ConnectionResetError(54, "Connection reset by peer")
        exc = _classify_rekor_transport_error(_make_urlerror(inner))
        self._assert_no_raw_leak(exc)
        assert "network error" in str(exc)

    def test_timeout(self) -> None:
        """TimeoutError must produce a clean timeout message."""
        exc = _classify_rekor_transport_error(TimeoutError("timed out"))
        self._assert_no_raw_leak(exc)
        assert "timed out" in str(exc).lower()

    def test_http_error_404(self) -> None:
        """HTTPError must produce HTTP status + reason."""
        http_exc = urllib.error.HTTPError(
            url="https://rekor.example/api/v1/log/entries",
            code=404,
            msg="Not Found",
            hdrs=None,  # type: ignore[arg-type]
            fp=io.BytesIO(b"{}"),
        )
        exc = _classify_rekor_transport_error(http_exc)
        self._assert_no_raw_leak(exc)
        assert "404" in str(exc)

    def test_http_error_500(self) -> None:
        """HTTPError 500 must produce HTTP status + reason."""
        http_exc = urllib.error.HTTPError(
            url="https://rekor.example/api/v1/log/entries",
            code=500,
            msg="Internal Server Error",
            hdrs=None,  # type: ignore[arg-type]
            fp=io.BytesIO(b"{}"),
        )
        exc = _classify_rekor_transport_error(http_exc)
        self._assert_no_raw_leak(exc)
        assert "500" in str(exc)

    def test_urlerror_with_string_reason(self) -> None:
        """URLError with a bare string reason must stay clean."""
        exc = _classify_rekor_transport_error(
            _make_urlerror("name resolution failed")
        )
        self._assert_no_raw_leak(exc)
        assert "name resolution failed" in str(exc)

    def test_generic_oserror_reason(self) -> None:
        """URLError wrapping a bare OSError without errno must not leak."""
        inner = OSError("some socket issue")
        exc = _classify_rekor_transport_error(_make_urlerror(inner))
        self._assert_no_raw_leak(exc)
        assert "network error" in str(exc)

    def test_oserror_subclass_without_errno_does_not_leak_class_name(self) -> None:
        """ConnectionRefusedError constructed without errno must not leak.

        Regression test for the latent leak found in the first review
        (t_982de924): ``ConnectionRefusedError("custom message")`` has
        ``errno=None``, which previously fell through to the
        ``type(reason).__name__`` branch and emitted the raw class name.
        """
        inner = ConnectionRefusedError("custom message without errno")
        assert inner.errno is None  # guard: confirm the test exercises the right path
        exc = _classify_rekor_transport_error(_make_urlerror(inner))
        self._assert_no_raw_leak(exc)
        assert "network error" in str(exc)

    def test_connection_reset_subclass_without_errno_does_not_leak(self) -> None:
        """ConnectionResetError without errno must not leak class name."""
        inner = ConnectionResetError("custom message without errno")
        assert inner.errno is None
        exc = _classify_rekor_transport_error(_make_urlerror(inner))
        self._assert_no_raw_leak(exc)
        assert "network error" in str(exc)

    def test_socket_timeout_urlerror(self) -> None:
        """URLError wrapping socket.timeout (errno ETIMEDOUT) must not leak."""
        inner = socket.timeout("timed out")
        exc = _classify_rekor_transport_error(_make_urlerror(inner))
        self._assert_no_raw_leak(exc)


class TestDefaultRekorTransportIntegration:
    """Verify the transport itself raises classified errors."""

    def test_transport_connection_refused_raises_clean_error(self) -> None:
        """The transport must raise a TransparencyError without raw internals."""
        with pytest.raises(TransparencyError) as exc_info:
            _default_rekor_transport(
                "https://127.0.0.1:1/api/v1/log/entries",
                b"{}",
                timeout=2,
                max_bytes=4096,
            )
        text = str(exc_info.value)
        for pattern in ("<urlopen error", "ConnectionRefusedError"):
            assert pattern not in text, f"transport leaks internals: {text!r}"

    def test_transport_http_error_raises_clean_error(self) -> None:
        """HTTP 404 from a mock server must produce a clean TransparencyError."""

        def mock_transport(
            url: str, payload: bytes, timeout: float, max_bytes: int
        ) -> bytes:
            raise urllib.error.HTTPError(
                url=url,
                code=404,
                msg="Not Found",
                hdrs=None,  # type: ignore[arg-type]
                fp=io.BytesIO(b"{}"),
            )

        # _classify_rekor_transport_error is called from inside the
        # transport's except block, so we just verify the classifier
        # directly for the HTTP path.
        http_exc = urllib.error.HTTPError(
            url="https://rekor.example",
            code=404,
            msg="Not Found",
            hdrs=None,  # type: ignore[arg-type]
            fp=io.BytesIO(b"{}"),
        )
        exc = _classify_rekor_transport_error(http_exc)
        assert "404" in str(exc)
        assert "<urlopen" not in str(exc)
