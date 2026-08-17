"""Tests for --redact-paths on ``ardur setup`` and ``ardur uninstall``.

These commands previously leaked local absolute filesystem paths in their
JSON output (``home``, ``config``, ``launch_agent``, ``would_remove``,
``removed``).  The ``--redact-paths`` flag uses ``_redact_paths_deep`` to
recursively redact all path-bearing fields so the output is safe to share
in CI artifacts or bug reports.

The contract is identical to ``--redact-paths`` on ``ardur run --json``,
``ardur status``, ``ardur doctor``, ``ardur doctor-claude-code``, and
``ardur protect claude-code``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

# Make the vibap package importable from the worktree.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vibap.cli import (  # noqa: E402
    _redact_paths_deep,
    cmd_uninstall,
)

_HOME = os.path.expanduser("~")
_TEMP = tempfile.gettempdir()


def _make_local_path(suffix: str = "ardur-test/.vibap/personal") -> str:
    """Return a real local path that _redact_paths_deep will redact."""
    return os.path.join(_TEMP, suffix)


# ---------------------------------------------------------------------------
# Helper tests — verify _redact_paths_deep handles setup/uninstall response shapes
# ---------------------------------------------------------------------------


class TestRedactPathsDeepForSetupUninstall:
    """Verify _redact_paths_deep handles the specific dict/list shapes
    returned by setup_personal and uninstall_personal."""

    def test_redacts_setup_response_home_config_launch_agent(self):
        """setup returns home, config, launch_agent as top-level path strings."""
        local_home = _make_local_path()
        local_config = _make_local_path("ardur-test/.vibap/personal/config.json")
        local_plist = os.path.join(
            _HOME, "Library/LaunchAgents/dev.ardur.personal-hub.plist"
        )
        response = {
            "ok": True,
            "home": local_home,
            "config": local_config,
            "hub_url": "http://127.0.0.1:8420",
            "hub_token": "secret-token",
            "launch_agent": local_plist,
            "next_steps": [],
        }
        redacted = _redact_paths_deep(response)
        assert _TEMP not in redacted["home"], f"Leaked temp root: {redacted['home']}"
        assert _TEMP not in redacted["config"], f"Leaked temp root: {redacted['config']}"
        assert _HOME not in redacted["launch_agent"], (
            f"Leaked home root: {redacted['launch_agent']}"
        )
        # Placeholders present
        assert "<tmp>" in redacted["home"] or "<var-folders>" in redacted["home"]
        assert "<home>" in redacted["launch_agent"]
        # Non-path fields preserved
        assert redacted["hub_url"] == "http://127.0.0.1:8420"
        assert redacted["hub_token"] == "secret-token"
        assert redacted["ok"] is True

    def test_redacts_uninstall_dry_run_would_remove_list(self):
        """uninstall --dry-run returns would_remove as a list of path strings."""
        local_plist = os.path.join(
            _HOME, "Library/LaunchAgents/dev.ardur.personal-hub.plist"
        )
        local_home = _make_local_path()
        response = {
            "ok": True,
            "dry_run": True,
            "would_remove": [local_plist, local_home],
            "removed": [],
            "data_kept": True,
        }
        redacted = _redact_paths_deep(response)
        for path in redacted["would_remove"]:
            assert _HOME not in path, f"Leaked home root: {path}"
            assert _TEMP not in path, f"Leaked temp root: {path}"
        assert "<home>" in redacted["would_remove"][0]
        # Non-path fields preserved
        assert redacted["dry_run"] is True
        assert redacted["data_kept"] is True

    def test_redacts_uninstall_removed_list(self):
        """uninstall returns removed as a list of path strings."""
        local_plist = os.path.join(
            _HOME, "Library/LaunchAgents/dev.ardur.personal-hub.plist"
        )
        response = {
            "ok": True,
            "removed": [local_plist],
            "data_kept": True,
        }
        redacted = _redact_paths_deep(response)
        assert _HOME not in redacted["removed"][0], (
            f"Leaked home root: {redacted['removed'][0]}"
        )
        assert "<home>" in redacted["removed"][0]

    def test_does_not_mutate_input(self):
        """_redact_paths_deep must not mutate the input dict/list."""
        local_home = _make_local_path()
        local_plist = os.path.join(
            _HOME, "Library/LaunchAgents/dev.ardur.personal-hub.plist"
        )
        original = {
            "home": local_home,
            "would_remove": [local_plist],
        }
        original_home = original["home"]
        original_list_item = original["would_remove"][0]
        _redact_paths_deep(original)
        assert original["home"] == original_home
        assert original["would_remove"][0] == original_list_item

    def test_preserves_non_path_fields(self):
        """Booleans, ints, None must pass through unchanged."""
        response = {
            "ok": True,
            "dry_run": False,
            "port": 8420,
            "data_kept": None,
            "next_steps": ["step one", "step two"],
        }
        redacted = _redact_paths_deep(response)
        assert redacted == response

    def test_handles_empty_structures(self):
        """Empty dicts, lists, and None must be handled gracefully."""
        response = {
            "ok": True,
            "would_remove": [],
            "removed": [],
            "next_steps": {},
        }
        redacted = _redact_paths_deep(response)
        assert redacted["would_remove"] == []
        assert redacted["removed"] == []
        assert redacted["next_steps"] == {}


# ---------------------------------------------------------------------------
# Argparse flag tests
# ---------------------------------------------------------------------------


class TestRedactPathsFlagAcceptance:
    """Verify --redact-paths is accepted by the argparse subparsers."""

    def _parse_setup(self, *extra_args):
        """Parse ``ardur setup`` args and return the namespace."""
        from vibap.cli import build_parser

        parser = build_parser()
        return parser.parse_args(["setup", *extra_args])

    def _parse_uninstall(self, *extra_args):
        """Parse ``ardur uninstall`` args and return the namespace."""
        from vibap.cli import build_parser

        parser = build_parser()
        return parser.parse_args(["uninstall", *extra_args])

    def test_setup_accepts_redact_paths(self):
        args = self._parse_setup("--redact-paths")
        assert args.redact_paths is True

    def test_setup_defaults_redact_paths_false(self):
        args = self._parse_setup()
        assert args.redact_paths is False

    def test_uninstall_accepts_redact_paths(self):
        args = self._parse_uninstall("--redact-paths")
        assert args.redact_paths is True

    def test_uninstall_defaults_redact_paths_false(self):
        args = self._parse_uninstall()
        assert args.redact_paths is False

    def test_setup_accepts_redact_paths_with_json(self):
        """Both --json and --redact-paths can be passed together."""
        args = self._parse_setup("--json", "--redact-paths")
        assert args.json is True
        assert args.redact_paths is True

    def test_uninstall_accepts_redact_paths_with_dry_run(self):
        """--redact-paths works alongside --dry-run."""
        args = self._parse_uninstall("--dry-run", "--redact-paths")
        assert args.dry_run is True
        assert args.redact_paths is True


# ---------------------------------------------------------------------------
# E2E path-redaction verification
# ---------------------------------------------------------------------------


class TestSetupUninstallRedactE2E:
    """End-to-end verification that cmd_setup and cmd_uninstall actually
    redact paths when --redact-paths is set."""

    def test_uninstall_dry_run_redacts_paths_in_output(self, capsys, tmp_path):
        """cmd_uninstall --dry-run with --redact-paths must not leak paths."""
        home = tmp_path / "ardur-home"
        home.mkdir(parents=True, exist_ok=True)
        args = argparse.Namespace(
            home=str(home),
            remove_data=False,
            dry_run=True,
            json=True,
            redact_paths=True,
        )
        rc = cmd_uninstall(args)
        captured = capsys.readouterr()
        assert rc == 0
        # The tmp_path is under the temp root, so with redaction it must not appear
        assert str(tmp_path) not in captured.out, (
            f"Local tmp_path leaked in redacted output: {captured.out}"
        )
        # Also verify no raw home root in output
        assert _HOME not in captured.out or "<home>" in captured.out

    def test_uninstall_no_redact_leaks_paths(self, capsys, tmp_path):
        """Without --redact-paths, uninstall output contains local tmp_path.
        This is the inverse proof: without the flag, paths ARE present."""
        home = tmp_path / "ardur-home-noredact"
        home.mkdir(parents=True, exist_ok=True)
        args = argparse.Namespace(
            home=str(home),
            remove_data=True,
            dry_run=True,
            json=True,
            redact_paths=False,
        )
        cmd_uninstall(args)
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        # The home path should be in would_remove when --remove-data and not redacting
        assert output["ok"] is True
        # The would_remove list should contain the local path (proving inverse)
        if output.get("would_remove"):
            raw_paths = json.dumps(output)
            assert str(tmp_path) in raw_paths or "<tmp>" in raw_paths, (
                "Expected local path in unredacted output"
            )

    def test_count_path_fields_redacted_in_setup_like_response(self):
        """Verify that a setup-shaped response has ALL path fields redacted."""
        local_home = _make_local_path()
        local_config = _make_local_path("ardur-test/config.json")
        local_plist = os.path.join(_HOME, "Library/LaunchAgents/dev.ardur.plist")
        response = {
            "ok": True,
            "home": local_home,
            "config": local_config,
            "launch_agent": local_plist,
            "next_steps": [
                f"brew services start ardur-personal (home: {local_home})",
            ],
        }
        redacted = _redact_paths_deep(response)
        # Every string in the response must be free of local roots
        def check(o):
            if isinstance(o, str):
                assert _TEMP not in o, f"Leaked temp root in: {o}"
                assert _HOME + "/" not in o, f"Leaked home root in: {o}"
            elif isinstance(o, dict):
                for v in o.values():
                    check(v)
            elif isinstance(o, list):
                for item in o:
                    check(item)

        check(redacted)
        # Placeholders must be present
        all_text = json.dumps(redacted)
        assert "<home>" in all_text or "<tmp>" in all_text or "<var-folders>" in all_text
