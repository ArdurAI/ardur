"""Tests for empty/whitespace path validation in ``claude_code_daemon``.

These pin the behaviour added when ``--socket-path`` and ``--keys-dir`` were
changed from ``type=Path`` to ``type=str`` with explicit pre-validation.

``argparse``'s built-in ``Path`` type converts ``""`` to ``Path(".")`` (the
current working directory) and ``"   "`` to ``Path("   ")``.  Both are
incorrect for a daemon that must bind to a specific Unix socket and load keys
from a specific directory.  The validation rejects empty or whitespace-only
strings *before* any ``Path()`` conversion, emitting a clean argparse error
(exit code 2) instead of a raw traceback.
"""

from __future__ import annotations

import subprocess
import sys

import pytest


_DAEMON_MOD = "vibap.claude_code_daemon"


def _run_daemon_cli(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """Invoke ``python -m vibap.claude_code_daemon`` as a subprocess."""
    return subprocess.run(
        [sys.executable, "-m", _DAEMON_MOD, *argv],
        capture_output=True,
        text=True,
        timeout=10,
    )


@pytest.mark.parametrize("raw", ["", "   "])
def test_daemon_rejects_empty_or_whitespace_socket_path(raw: str) -> None:
    """Empty / whitespace-only ``--socket-path`` must error with exit 2."""
    result = _run_daemon_cli(["--socket-path", raw])
    assert result.returncode == 2, (result.returncode, result.stderr)
    assert "usage:" in result.stderr.lower()
    assert "non-empty" in result.stderr.lower()
    # Must NOT produce a Python traceback.
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("raw", ["", "   "])
def test_daemon_rejects_empty_or_whitespace_keys_dir(raw: str) -> None:
    """Empty / whitespace-only ``--keys-dir`` must error with exit 2."""
    result = _run_daemon_cli(["--keys-dir", raw])
    assert result.returncode == 2, (result.returncode, result.stderr)
    assert "usage:" in result.stderr.lower()
    assert "non-empty" in result.stderr.lower()
    assert "Traceback" not in result.stderr


def test_daemon_main_rejects_empty_socket_path_in_process() -> None:
    """``main()`` raises SystemExit(2) for empty ``--socket-path``."""
    from vibap.claude_code_daemon import main

    with pytest.raises(SystemExit) as exc_info:
        main(["--socket-path", ""])
    assert exc_info.value.code == 2


def test_daemon_main_rejects_whitespace_keys_dir_in_process() -> None:
    """``main()`` raises SystemExit(2) for whitespace-only ``--keys-dir``."""
    from vibap.claude_code_daemon import main

    with pytest.raises(SystemExit) as exc_info:
        main(["--keys-dir", "   "])
    assert exc_info.value.code == 2


@pytest.mark.parametrize("bad", [-1, 0])
def test_daemon_rejects_non_positive_max_requests(bad: int) -> None:
    """``--max-requests`` <= 0 must error with exit 2, not start the daemon."""
    result = _run_daemon_cli(["--max-requests", str(bad)])
    assert result.returncode == 2, (result.returncode, result.stderr)
    assert "usage:" in result.stderr.lower()
    assert "positive integer" in result.stderr.lower()
    # Must NOT produce a Python traceback.
    assert "Traceback" not in result.stderr


def test_daemon_main_rejects_negative_max_requests_in_process() -> None:
    """``main()`` raises SystemExit(2) for ``--max-requests=-1``."""
    from vibap.claude_code_daemon import main

    with pytest.raises(SystemExit) as exc_info:
        main(["--max-requests", "-1"])
    assert exc_info.value.code == 2


def test_daemon_main_rejects_zero_max_requests_in_process() -> None:
    """``main()`` raises SystemExit(2) for ``--max-requests=0``."""
    from vibap.claude_code_daemon import main

    with pytest.raises(SystemExit) as exc_info:
        main(["--max-requests", "0"])
    assert exc_info.value.code == 2
