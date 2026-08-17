"""Test that sync_source_docs.py excludes local git worktree checkouts.

Contributors who use ``git worktree`` inside their Ardur checkout will have a
``worktrees/`` (or ``.worktrees/``) directory containing full repo clones.
The Hugo source-mirror sync script must exclude these so they never appear as
stale generated mirror files or pollute the public source tree.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

REPO_ROOT = Path(__file__).resolve().parents[2]
SYNC_SCRIPT = REPO_ROOT / "site" / "scripts" / "sync_source_docs.py"


def load_sync_module():
    spec = importlib.util.spec_from_file_location(
        "sync_source_docs", SYNC_SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class WorktreeExclusionTests(unittest.TestCase):
    """Files under worktrees/ and .worktrees/ must never appear in public
    markdown discovery."""

    def setUp(self) -> None:
        self.temporary_directory = TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

        # Mimic a git-worktree layout inside the repo root.
        wt = self.root / "worktrees" / "dev-checkout"
        wt.mkdir(parents=True)
        (wt / "README.md").write_text("# Worktree README\n")
        (wt / "docs").mkdir()
        (wt / "docs" / "guide.md").write_text("# Guide\n")

        # Hidden-variant layout used by some worktree managers.
        hwt = self.root / ".worktrees" / "feature"
        hwt.mkdir(parents=True)
        (hwt / "CLAUDE.md").write_text("# Claude\n")

        # A real source file that SHOULD be discovered.
        (self.root / "REAL.md").write_text("# Real Source\n")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_worktrees_dir_excluded(self) -> None:
        """Files under worktrees/ and .worktrees/ must not appear in
        :func:`discover_markdown` output."""
        sync = load_sync_module()
        original_root = sync.REPO_ROOT
        try:
            sync.REPO_ROOT = self.root
            paths = sync.discover_markdown()
            path_strs = [str(p) for p in paths]

            # The legitimate source file must be present.
            self.assertIn("REAL.md", path_strs)

            # No worktree file may leak through.
            for p in path_strs:
                self.assertFalse(
                    p.startswith("worktrees/"),
                    f"worktrees/ file leaked into public markdown: {p}",
                )
                self.assertFalse(
                    p.startswith(".worktrees/"),
                    f".worktrees/ file leaked into public markdown: {p}",
                )
        finally:
            sync.REPO_ROOT = original_root

    def test_worktrees_in_excluded_dir_names(self) -> None:
        """``worktrees`` must be in :data:`PUBLIC_MARKDOWN_EXCLUDED_DIR_NAMES`."""
        sync = load_sync_module()
        self.assertIn("worktrees", sync.PUBLIC_MARKDOWN_EXCLUDED_DIR_NAMES)

    def test_worktrees_prefix_excluded(self) -> None:
        """Both ``worktrees/`` and ``.worktrees/`` must be in
        :data:`PUBLIC_MARKDOWN_EXCLUDED_PREFIXES`."""
        sync = load_sync_module()
        self.assertIn("worktrees/", sync.PUBLIC_MARKDOWN_EXCLUDED_PREFIXES)
        self.assertIn(".worktrees/", sync.PUBLIC_MARKDOWN_EXCLUDED_PREFIXES)


if __name__ == "__main__":
    unittest.main()
