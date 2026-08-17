"""Regression tests for fixture __main__ str(exc) path leak sanitization.

Defect: ``main()`` functions in fixture modules caught OSError/TypeError/ValueError
and emitted raw ``str(exc)`` in JSON error output, which could leak filesystem
paths (e.g. ``/var/folders/...``, ``/home/...``) and Python internals.

These tests assert the sanitized contract: JSON error output must contain only
safe, classified messages — never raw exception text with paths or errno details.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# --- helpers ----------------------------------------------------------------

_LEAK_MARKERS = ("/tmp/", "/private/", "/var/", "/Users/", "/home/", "Errno", "errno")


def _assert_no_path_leak(text: str) -> None:
    """Sanitized output must not leak filesystem paths or errno details."""
    lowered = text.lower()
    for marker in _LEAK_MARKERS:
        assert marker.lower() not in lowered, f"path/errno marker leaked: {marker!r} in {text!r}"


def _run_module(module: str, args: list[str]) -> subprocess.CompletedProcess[str]:
    """Run ``python -m vibap.<module>`` and capture stdout/stderr."""
    return subprocess.run(
        [sys.executable, "-m", f"vibap.{module}", *args],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parent.parent,
    )


# --- drp_conformance main() ------------------------------------------------

def test_drp_conformance_main_nonexistent_bundle_no_path_leak() -> None:
    """Passing a nonexistent bundle path must not leak the path in error output."""
    result = _run_module("drp_conformance", ["--bundle", "/nonexistent/bundle.json"])
    assert result.returncode != 0
    output = result.stderr.strip()
    assert output, "expected JSON error on stderr"
    parsed = json.loads(output)
    assert parsed["ok"] is False
    assert "error" in parsed
    assert "message" in parsed
    _assert_no_path_leak(output)
    # Nonexistent path triggers ValueError (path validation), not OSError.
    # The safe message must be present, not raw str(exc).
    assert parsed["message"] == "Invalid input type or value for conformance evaluation."


def test_drp_conformance_main_bundle_is_directory_no_path_leak(tmp_path: Path) -> None:
    """Passing a directory as --bundle must not leak the path in error output."""
    dir_path = tmp_path / "a_directory"
    dir_path.mkdir()
    result = _run_module("drp_conformance", ["--bundle", str(dir_path)])
    assert result.returncode != 0
    output = result.stderr.strip()
    assert output
    parsed = json.loads(output)
    assert parsed["ok"] is False
    _assert_no_path_leak(output)
    # Directory-as-file triggers ValueError (not valid JSON), not OSError.
    assert parsed["message"] == "Invalid input type or value for conformance evaluation."


# --- policy_conformance main() ----------------------------------------------

def test_policy_conformance_main_nonexistent_bundle_no_path_leak() -> None:
    """Passing a nonexistent bundle path must not leak the path in error output."""
    result = _run_module("policy_conformance", ["--bundle", "/nonexistent/bundle.json"])
    assert result.returncode != 0
    output = result.stderr.strip()
    assert output
    parsed = json.loads(output)
    assert parsed["ok"] is False
    _assert_no_path_leak(output)
    assert parsed["message"] == "Invalid input type or value for conformance evaluation."


def test_policy_conformance_main_bundle_is_directory_no_path_leak(tmp_path: Path) -> None:
    """Passing a directory as --bundle must not leak the path in error output."""
    dir_path = tmp_path / "a_directory"
    dir_path.mkdir()
    result = _run_module("policy_conformance", ["--bundle", str(dir_path)])
    assert result.returncode != 0
    output = result.stderr.strip()
    assert output
    parsed = json.loads(output)
    assert parsed["ok"] is False
    _assert_no_path_leak(output)
    assert parsed["message"] == "Invalid input type or value for conformance evaluation."


# --- drp_fixture main() ----------------------------------------------------

def test_drp_fixture_main_output_parent_is_file_triggers_oserror_no_path_leak(
    tmp_path: Path,
) -> None:
    """When --output has a parent that is a regular file, mkdir(parents=True)
    raises FileExistsError (OSError subclass).  The error JSON must not leak
    the path."""
    regular_file = tmp_path / "regular_file"
    regular_file.write_text("block")
    # --output points inside the regular file → mkdir fails with OSError
    bad_output = regular_file / "subdir"
    result = _run_module("drp_fixture", ["--output", str(bad_output)])
    assert result.returncode != 0
    output = result.stdout.strip()
    assert output
    parsed = json.loads(output)
    assert parsed["ok"] is False
    _assert_no_path_leak(output)
    assert parsed["message"] == "Filesystem error writing fixture output."


# --- offline_verification_fixture main() -----------------------------------

def test_offline_verification_fixture_main_output_parent_is_file_triggers_oserror_no_path_leak(
    tmp_path: Path,
) -> None:
    """When --output has a parent that is a regular file, mkdir(parents=True)
    raises FileExistsError (OSError subclass).  The error JSON must not leak
    the path."""
    regular_file = tmp_path / "regular_file"
    regular_file.write_text("block")
    bad_output = regular_file / "subdir"
    result = _run_module("offline_verification_fixture", ["--output", str(bad_output)])
    assert result.returncode != 0
    output = result.stdout.strip()
    assert output
    parsed = json.loads(output)
    assert parsed["ok"] is False
    _assert_no_path_leak(output)
    assert parsed["message"] == "Filesystem error writing fixture output."


# --- receiver_attestation_fixture main() -----------------------------------

def test_receiver_attestation_fixture_main_output_parent_is_file_triggers_oserror_no_path_leak(
    tmp_path: Path,
) -> None:
    """When --output has a parent that is a regular file, mkdir(parents=True)
    raises FileExistsError (OSError subclass).  The error JSON must not leak
    the path."""
    regular_file = tmp_path / "regular_file"
    regular_file.write_text("block")
    bad_output = regular_file / "subdir"
    result = _run_module("receiver_attestation_fixture", ["--output", str(bad_output)])
    assert result.returncode != 0
    output = result.stdout.strip()
    assert output
    parsed = json.loads(output)
    assert parsed["ok"] is False
    _assert_no_path_leak(output)
    assert parsed["message"] == "Filesystem error writing fixture output."


# --- policy_conformance delegation PermissionError (domain message is safe) ---

def test_policy_conformance_delegation_permission_error_has_safe_domain_message() -> None:
    """The PermissionError from derive_child_passport is a domain exception
    carrying an intentional, safe message (e.g. "scope escalation (tools): [...]")
    with no filesystem paths.  It is NOT an OS-level PermissionError and must
    NOT be replaced with a generic string — the message is part of the
    receipt evidence hash.

    This test documents that the message is safe and must be preserved verbatim.
    """
    from vibap.passport import MissionPassport, issue_passport, derive_child_passport
    from cryptography.hazmat.primitives.asymmetric import ec
    import uuid

    claims = {
        "sub": "test-agent",
        "mission": "test mission",
        "allowed_tools": ["read_file"],
        "forbidden_tools": [],
        "resource_scope": ["**"],
        "max_tool_calls": 5,
        "max_duration_s": 600,
        "delegation_allowed": True,
        "max_delegation_depth": 2,
        "jti": "test:authority-widening",
    }
    private_key = ec.generate_private_key(ec.SECP256R1())
    parent = MissionPassport(
        agent_id=claims["sub"],
        mission=claims["mission"],
        allowed_tools=list(claims["allowed_tools"]),
        forbidden_tools=list(claims["forbidden_tools"]),
        resource_scope=list(claims["resource_scope"]),
        max_tool_calls=claims["max_tool_calls"],
        max_duration_s=claims["max_duration_s"],
        delegation_allowed=claims["delegation_allowed"],
        max_delegation_depth=claims["max_delegation_depth"],
        cwd=None,
    )
    parent_token = issue_passport(
        parent,
        private_key,
        ttl_s=300,
        jti_override=str(uuid.uuid5(uuid.NAMESPACE_URL, claims["jti"])),
    )
    try:
        derive_child_passport(
            parent_token,
            private_key.public_key(),
            private_key,
            child_agent_id="child-agent",
            child_allowed_tools=["read_file", "write_file"],
            child_mission="widen",
            child_ttl_s=120,
            child_max_tool_calls=2,
            child_resource_scope=[],
            child_cwd=None,
        )
    except PermissionError as exc:
        msg = str(exc)
        _assert_no_path_leak(msg)
        assert "scope escalation" in msg, (
            f"Expected domain 'scope escalation' message, got: {msg!r}"
        )
    else:
        raise AssertionError("Expected PermissionError for authority widening")
