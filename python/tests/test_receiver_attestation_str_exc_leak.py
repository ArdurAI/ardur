"""Regression tests for receiver-attestation str(exc) path leak sanitization.

Defect: `load_receiver_envelope` and `load_json_document` interpolated raw
exception messages (`str(exc)`) into ReceiverAttestationError messages, which
leaked full filesystem paths (FileNotFoundError includes the path) and Python
internal JSON parse details into JSON output via cli.py's `str(exc)` consumer.

These tests assert the sanitized contract: error messages must name only the
exception class (e.g. FileNotFoundError, JSONDecodeError), never the path,
errno detail, or parser internals.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from vibap.receiver_attestation import (
    ReceiverAttestationError,
    load_json_document,
    load_receiver_envelope,
)


# --- leak indicators --------------------------------------------------------

_LEAK_MARKERS = ("/tmp/", "/private/", "/var/", "/Users/", "/home/", "Errno", "errno")


def _assert_no_leak(message: str, *, input_path: str) -> None:
    """Sanitized messages must not leak paths, errno, or parser internals."""
    assert isinstance(message, str)
    # No filesystem path segments from the input.
    base = os.path.basename(input_path)
    assert base not in message, f"filename leaked into message: {message!r}"
    # No path/errno markers.
    lowered = message.lower()
    for marker in _LEAK_MARKERS:
        assert marker.lower() not in lowered, f"{marker!r} leaked: {message!r}"
    # No double-quoted JSON parser internals (Expecting property name...).
    assert "expecting" not in lowered, f"parser detail leaked: {message!r}"
    # No raw colon-errno segments like "[Errno 2] No such file or directory".
    assert "no such file or directory" not in lowered, f"oserror detail leaked: {message!r}"


def _assert_class_named(message: str, *, expected_class: str) -> None:
    """Sanitized message names the exception class for debuggability."""
    assert expected_class in message, (
        f"expected class {expected_class!r} in message: {message!r}"
    )


# --- load_receiver_envelope --------------------------------------------------


def test_load_receiver_envelope_nonexistent_file_is_sanitized(tmp_path: Path) -> None:
    missing = tmp_path / "definitely_missing_envelope.json"
    with pytest.raises(ReceiverAttestationError) as exc_info:
        load_receiver_envelope(missing)
    message = str(exc_info.value)
    _assert_no_leak(message, input_path=str(missing))
    _assert_class_named(message, expected_class="FileNotFoundError")


def test_load_receiver_envelope_corrupt_json_is_sanitized(tmp_path: Path) -> None:
    corrupt = tmp_path / "corrupt_envelope.json"
    corrupt.write_text("{not valid json at all", encoding="utf-8")
    with pytest.raises(ReceiverAttestationError) as exc_info:
        load_receiver_envelope(corrupt)
    message = str(exc_info.value)
    _assert_no_leak(message, input_path=str(corrupt))
    _assert_class_named(message, expected_class="JSONDecodeError")


def test_load_receiver_envelope_unreadable_dir_as_file_is_sanitized(tmp_path: Path) -> None:
    # A directory cannot be read as a file → OSError subclass without a path leak.
    target = tmp_path / "not_a_file_dir"
    target.mkdir()
    with pytest.raises(ReceiverAttestationError) as exc_info:
        load_receiver_envelope(target)
    message = str(exc_info.value)
    _assert_no_leak(message, input_path=str(target))
    _assert_class_named(message, expected_class="IsADirectoryError")


# --- load_json_document ------------------------------------------------------


def test_load_json_document_nonexistent_mcp_request_is_sanitized(tmp_path: Path) -> None:
    missing = tmp_path / "nonexistent_mcp_request.json"
    with pytest.raises(ReceiverAttestationError) as exc_info:
        load_json_document(missing, label="MCP request")
    message = str(exc_info.value)
    assert "MCP request" in message
    _assert_no_leak(message, input_path=str(missing))
    _assert_class_named(message, expected_class="FileNotFoundError")


def test_load_json_document_nonexistent_mcp_response_is_sanitized(tmp_path: Path) -> None:
    missing = tmp_path / "nonexistent_mcp_response.json"
    with pytest.raises(ReceiverAttestationError) as exc_info:
        load_json_document(missing, label="MCP response")
    message = str(exc_info.value)
    assert "MCP response" in message
    _assert_no_leak(message, input_path=str(missing))
    _assert_class_named(message, expected_class="FileNotFoundError")


def test_load_json_document_corrupt_json_is_sanitized(tmp_path: Path) -> None:
    corrupt = tmp_path / "corrupt_mcp_request.json"
    corrupt.write_text("}{ totally not json", encoding="utf-8")
    with pytest.raises(ReceiverAttestationError) as exc_info:
        load_json_document(corrupt, label="MCP request")
    message = str(exc_info.value)
    _assert_no_leak(message, input_path=str(corrupt))
    _assert_class_named(message, expected_class="JSONDecodeError")


def test_load_json_document_unreadable_dir_as_file_is_sanitized(tmp_path: Path) -> None:
    target = tmp_path / "not_a_doc_dir"
    target.mkdir()
    with pytest.raises(ReceiverAttestationError) as exc_info:
        load_json_document(target, label="MCP request")
    message = str(exc_info.value)
    _assert_no_leak(message, input_path=str(target))
    _assert_class_named(message, expected_class="IsADirectoryError")
