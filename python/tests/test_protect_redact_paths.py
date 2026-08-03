"""Tests for ``ardur protect claude-code --json --redact-paths``.

The ``protect claude-code`` success response contains 10+ path-bearing
fields across nested structures (``home``, ``active_passport``,
``plugin_dir``, ``run_command``, ``claims.resource_scope[]``,
``claims.cwd``, etc.).  Without ``--redact-paths`` these leak the local
filesystem layout when shared in CI artifacts or bug reports.  These
tests verify that ``--redact-paths`` replaces every local absolute path
with a stable placeholder and that the redacted output contains zero
``/private/``, ``/Users/``, or ``/tmp/`` prefixes.
"""

from __future__ import annotations

import json
import os
import tempfile
from unittest import mock

import pytest  # noqa: F401 — required by pytest collection

from vibap.cli import _redact_paths_deep, build_parser


# ---------------------------------------------------------------------------
# Unit tests for _redact_paths_deep
# ---------------------------------------------------------------------------

class TestRedactPathsDeep:
    """Unit tests for the recursive path redactor."""

    def test_redacts_flat_dict_string_fields(self):
        response = {
            "home": "/private/tmp/ardur-test/.vibap",
            "active_passport": "/private/tmp/ardur-test/.vibap/active_mission.jwt",
            "plugin_dir": "/private/tmp/ardur-test/plugins/claude-code",
        }
        redacted = _redact_paths_deep(response)
        assert redacted["home"] == "<tmp>/ardur-test/.vibap"
        assert redacted["active_passport"] == "<tmp>/ardur-test/.vibap/active_mission.jwt"
        assert redacted["plugin_dir"] == "<tmp>/ardur-test/plugins/claude-code"

    def test_redacts_nested_dict(self):
        response = {
            "claims": {
                "cwd": "/private/tmp/test-scope",
                "resource_scope": "/private/tmp/test-scope/*",
            }
        }
        redacted = _redact_paths_deep(response)
        assert redacted["claims"]["cwd"] == "<tmp>/test-scope"
        assert redacted["claims"]["resource_scope"] == "<tmp>/test-scope/*"

    def test_redacts_list_items(self):
        response = {
            "claims": {
                "resource_scope": [
                    "/private/tmp/test-scope",
                    "/private/tmp/test-scope/*",
                ]
            }
        }
        redacted = _redact_paths_deep(response)
        assert redacted["claims"]["resource_scope"] == [
            "<tmp>/test-scope",
            "<tmp>/test-scope/*",
        ]

    def test_redacts_path_inside_command_string(self):
        """``run_command`` embeds a path inside a longer string."""
        response = {
            "run_command": (
                "VIBAP_HOME=/private/tmp/ardur-test/.vibap "
                "claude --plugin-dir /private/tmp/ardur-test/plugins/claude-code"
            )
        }
        redacted = _redact_paths_deep(response)
        # _redact_local_path only replaces path-root prefixes; embedded
        # paths after the first token are still redacted because the
        # helper scans the whole string.
        assert "/private/tmp/" not in redacted["run_command"]

    def test_preserves_non_path_strings(self):
        response = {
            "mode": "safe-coding",
            "ok": True,
            "agent_id": "local-user:claude-code",
        }
        redacted = _redact_paths_deep(response)
        assert redacted == response

    def test_preserves_non_string_scalars(self):
        response = {
            "ok": True,
            "max_tool_calls": 250,
            "max_duration_s": 86400,
            "ttl_s": None,
        }
        redacted = _redact_paths_deep(response)
        assert redacted == response

    def test_handles_none(self):
        assert _redact_paths_deep(None) is None

    def test_handles_empty_structures(self):
        assert _redact_paths_deep({}) == {}
        assert _redact_paths_deep([]) == []

    def test_redacts_home_paths(self):
        home = os.path.expanduser("~")
        response = {"config": f"{home}/.config/ardur/config.json"}
        redacted = _redact_paths_deep(response)
        assert redacted["config"] == f"<home>/.config/ardur/config.json"

    def test_does_not_mutate_input(self):
        original = {"home": "/private/tmp/test"}
        _redact_paths_deep(original)
        assert original == {"home": "/private/tmp/test"}

    def test_deeply_nested_structure(self):
        response = {
            "level1": {
                "level2": {
                    "level3": {
                        "path": "/private/tmp/deeply/nested/path",
                    }
                }
            }
        }
        redacted = _redact_paths_deep(response)
        assert redacted["level1"]["level2"]["level3"]["path"] == "<tmp>/deeply/nested/path"


# ---------------------------------------------------------------------------
# Integration tests for the CLI flag
# ---------------------------------------------------------------------------

class TestProtectRedactPathsFlag:
    """Integration tests for ``--redact-paths`` on the protect subparser."""

    def test_flag_accepted_by_argparse(self):
        """The ``--redact-paths`` flag should be accepted without error."""
        parser = build_parser()
        args = parser.parse_args([
            "protect", "claude-code",
            "--scope", "/tmp/test-scope",
            "--json",
            "--redact-paths",
        ])
        assert args.redact_paths is True

    def test_flag_defaults_false(self):
        """Without ``--redact-paths``, the attribute should be False."""
        parser = build_parser()
        args = parser.parse_args([
            "protect", "claude-code",
            "--scope", "/tmp/test-scope",
            "--json",
        ])
        assert getattr(args, "redact_paths", False) is False

    def test_flag_available_without_json(self):
        """``--redact-paths`` can be passed even without ``--json`` (it
        just has no effect on human-readable output)."""
        parser = build_parser()
        args = parser.parse_args([
            "protect", "claude-code",
            "--scope", "/tmp/test-scope",
            "--redact-paths",
        ])
        assert args.redact_paths is True


# ---------------------------------------------------------------------------
# End-to-end path-leak verification
# ---------------------------------------------------------------------------

class TestProtectRedactPathsE2E:
    """End-to-end tests verifying no local paths leak with --redact-paths."""

    def _make_protect_response(self, tmp_home: str, scope: str) -> dict:
        """Build a realistic protect-claude-code success response."""
        return {
            "ok": True,
            "mode": "safe-coding",
            "scope": scope,
            "home": f"{tmp_home}/.vibap",
            "active_passport": f"{tmp_home}/.vibap/active_mission.jwt",
            "active_mission_path": f"{tmp_home}/.vibap/active_mission.jwt",
            "hook_python": f"{tmp_home}/.vibap/claude-code-hook-python",
            "native_pre_hook_command": f"{tmp_home}/.vibap/claude-code-pre_tool_use",
            "native_pre_hook_command_expected": f"{tmp_home}/.vibap/claude-code-pre_tool_use",
            "plugin_dir": f"{tmp_home}/plugins/claude-code",
            "run_command": (
                f"VIBAP_HOME={tmp_home}/.vibap "
                f"claude --plugin-dir {tmp_home}/plugins/claude-code"
            ),
            "claims": {
                "resource_scope": [scope, f"{scope}/*"],
                "cwd": scope,
            },
        }

    def test_no_local_paths_after_redaction(self):
        """After ``_redact_paths_deep``, no field should contain local
        path prefixes like ``/private/``, ``/Users/``, or ``/tmp/``."""
        with tempfile.TemporaryDirectory() as tmpdir:
            response = self._make_protect_response(
                tmp_home=f"/private{tmpdir}",
                scope=f"/private{tmpdir}/test-scope",
            )
            redacted = _redact_paths_deep(response)
            blob = json.dumps(redacted)

        # No raw local path prefixes should survive redaction.
        assert "/private/" not in blob
        assert "/Users/" not in blob
        # ``/tmp/`` inside the redacted placeholders like ``<tmp>/`` is fine,
        # but a bare ``/tmp/`` prefix would indicate a leak.  Check that no
        # string value starts with it.
        def _check_no_leak(obj):
            if isinstance(obj, str):
                assert not obj.startswith("/tmp/"), f"Path leak: {obj}"
                assert not obj.startswith("/private/"), f"Path leak: {obj}"
                assert not obj.startswith("/Users/"), f"Path leak: {obj}"
            elif isinstance(obj, dict):
                for v in obj.values():
                    _check_no_leak(v)
            elif isinstance(obj, list):
                for item in obj:
                    _check_no_leak(item)

        _check_no_leak(redacted)

    def test_placeholders_are_stable(self):
        """Redacted paths should use the same stable placeholders."""
        with tempfile.TemporaryDirectory() as tmpdir:
            response = self._make_protect_response(
                tmp_home=tmpdir,
                scope=f"{tmpdir}/test-scope",
            )
            redacted = _redact_paths_deep(response)

        temp_root = tempfile.gettempdir()
        assert redacted["home"] == f"<tmp>{tmpdir[len(temp_root)]}/.vibap" or \
               redacted["home"].startswith("<tmp>")
        assert redacted["active_passport"].startswith("<tmp>")

    def test_count_path_fields_redacted(self):
        """Verify that all 11+ path-bearing fields in a realistic response
        are redacted, matching the probe's finding of 11 leaks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            response = self._make_protect_response(
                tmp_home=f"/private{tmpdir}",
                scope=f"/private{tmpdir}/test-scope",
            )

            def _count_leaks(obj) -> int:
                count = 0
                if isinstance(obj, str):
                    if obj.startswith("/private/") or obj.startswith("/Users/") or \
                       obj.startswith("/tmp/") or "/var/folders/" in obj:
                        count += 1
                elif isinstance(obj, dict):
                    for v in obj.values():
                        count += _count_leaks(v)
                elif isinstance(obj, list):
                    for item in obj:
                        count += _count_leaks(item)
                return count

            before = _count_leaks(response)
            after_redaction = _count_leaks(_redact_paths_deep(response))

        assert before >= 10, f"Expected 10+ path leaks in test fixture, got {before}"
        assert after_redaction == 0, f"Expected 0 leaks after redaction, got {after_redaction}"
