"""Resolve immutable assets shipped with the Python distribution."""

from __future__ import annotations

from pathlib import Path


def claude_code_plugin_dir(cwd: Path | None = None) -> Path:
    """Return the first available canonical or packaged plugin directory."""

    working_directory = cwd if cwd is not None else Path.cwd()
    packaged = Path(__file__).resolve().parent / "_plugins" / "claude-code"
    candidates = (
        working_directory / "plugins" / "claude-code",
        packaged,
        Path(__file__).resolve().parents[2] / "plugins" / "claude-code",
    )
    return next((candidate for candidate in candidates if candidate.is_dir()), packaged)
