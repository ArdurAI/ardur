"""Regression tests for ``ardur issue --keys-dir`` OSError handling.

When the parent of ``--keys-dir`` is on a read-only filesystem or otherwise
unreachable, ``resolve_keys_dir`` calls ``target.mkdir(parents=True,
exist_ok=True)`` which can raise ``OSError`` (e.g. PermissionError,
read-only filesystem). Before the fix, this escaped as a raw traceback.
After the fix, it returns a structured JSON error with condition
``keys_dir_unreachable``.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from vibap.passport import KeyDirectoryError, resolve_keys_dir


class TestResolveKeysDirOSError:
    """``resolve_keys_dir`` must raise ``KeyDirectoryError`` for OSError."""

    def test_permission_denied_on_mkdir(self, tmp_path: Path) -> None:
        """PermissionError during mkdir becomes KeyDirectoryError."""
        target = tmp_path / "blocked"

        original_mkdir = Path.mkdir

        def fake_mkdir(self: Path, *args: object, **kwargs: object) -> None:
            if self == target:
                raise PermissionError(
                    "[Errno 13] Permission denied: '%s'" % str(target)
                )
            return original_mkdir(self, *args, **kwargs)

        with patch.object(Path, "mkdir", fake_mkdir):
            with pytest.raises(KeyDirectoryError) as exc_info:
                resolve_keys_dir(str(target))

        assert exc_info.value.condition == "keys_dir_unreachable"

    def test_read_only_filesystem_on_mkdir(self, tmp_path: Path) -> None:
        """OSError (read-only filesystem) during mkdir becomes KeyDirectoryError."""
        target = tmp_path / "ronly"

        original_mkdir = Path.mkdir

        def fake_mkdir(self: Path, *args: object, **kwargs: object) -> None:
            if self == target:
                raise OSError(
                    30, "Read-only file system", str(target)
                )
            return original_mkdir(self, *args, **kwargs)

        with patch.object(Path, "mkdir", fake_mkdir):
            with pytest.raises(KeyDirectoryError) as exc_info:
                resolve_keys_dir(str(target))

        assert exc_info.value.condition == "keys_dir_unreachable"
        assert "Read-only file system" in exc_info.value.detail

    def test_oserror_detail_does_not_leak_path(self, tmp_path: Path) -> None:
        """The KeyDirectoryError detail must not include the filesystem path."""
        target = tmp_path / "secret_leak_check"

        original_mkdir = Path.mkdir

        def fake_mkdir(self: Path, *args: object, **kwargs: object) -> None:
            if self == target:
                raise OSError(30, "Read-only file system", str(target))
            return original_mkdir(self, *args, **kwargs)

        with patch.object(Path, "mkdir", fake_mkdir):
            with pytest.raises(KeyDirectoryError) as exc_info:
                resolve_keys_dir(str(target))

        assert str(target) not in exc_info.value.detail

    def test_file_exists_error_still_uses_keys_dir_not_directory(
        self, tmp_path: Path
    ) -> None:
        """FileExistsError must still produce condition=keys_dir_not_directory."""
        # Create a file at the target so mkdir with exist_ok=False would fail
        # (but mkdir(parents=True, exist_ok=True) won't raise for existing dirs).
        # Instead test NotADirectoryError by creating a file in a parent path.
        blocking_file = tmp_path / "blocker"
        blocking_file.write_text("blocking")
        target = blocking_file / "subdir"

        with pytest.raises(KeyDirectoryError) as exc_info:
            resolve_keys_dir(str(target))

        assert exc_info.value.condition == "keys_dir_not_directory"

    def test_normal_keys_dir_still_works(self, tmp_path: Path) -> None:
        """A valid writable keys-dir must resolve normally."""
        target = tmp_path / "valid_keys"
        result = resolve_keys_dir(str(target))
        assert result == target
        assert result.is_dir()


class TestIssueKeysDirOSErrorCLI:
    """CLI-level tests for structured error on unreachable --keys-dir."""

    def test_issue_keys_dir_unreachable_returns_structured_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """``ardur issue --keys-dir /nonexistent`` must emit JSON, not traceback."""

        from vibap.cli import main

        target = tmp_path / "unreachable"

        original_mkdir = Path.mkdir

        def fake_mkdir(self: Path, *args: object, **kwargs: object) -> None:
            if self == target:
                raise OSError(30, "Read-only file system", str(target))
            return original_mkdir(self, *args, **kwargs)

        with patch.object(Path, "mkdir", fake_mkdir):
            exit_code = main(
                [
                    "issue",
                    "--agent-id",
                    "test-agent",
                    "--mission",
                    "test",
                    "--keys-dir",
                    str(target),
                ]
            )

        assert exit_code == 1
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["ok"] is False
        assert payload["error"] == "keys_dir_unreachable"
        assert "detail" in payload
        assert str(target) not in payload["detail"]
