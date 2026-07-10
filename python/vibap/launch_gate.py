"""PID-preserving pre-exec gate for ``ardur run`` kernel registration."""

from __future__ import annotations

import argparse
import os
import sys


RELEASE_BYTE = b"\x01"
PARENT_NOT_READY_EXIT = 125


def _parse_args(argv: list[str]) -> tuple[int, list[str]]:
    parser = argparse.ArgumentParser(description="wait for Ardur registration, then exec a command")
    parser.add_argument("--ready-fd", type=int, required=True, help=argparse.SUPPRESS)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("a command is required after --")
    return args.ready_fd, command


def main(argv: list[str] | None = None) -> int:
    ready_fd, command = _parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        release = os.read(ready_fd, 1)
    except OSError as exc:
        print(f"ardur launch gate: parent readiness channel failed: {exc}", file=sys.stderr)
        return PARENT_NOT_READY_EXIT
    finally:
        try:
            os.close(ready_fd)
        except OSError:
            # The fd may already be closed by the OS or inherited by the
            # target process; nothing actionable for the gate.
            pass

    if release != RELEASE_BYTE:
        print("ardur launch gate: parent exited before releasing target", file=sys.stderr)
        return PARENT_NOT_READY_EXIT

    try:
        os.execvpe(command[0], command, os.environ)
    except OSError as exc:
        print(f"ardur launch gate: exec {command[0]!r} failed: {exc}", file=sys.stderr)
        return 126
    # os.execvpe replaces the process image on success, so this line is
    # unreachable in normal operation.  It exists to make the control-flow
    # explicit for static analysis (no implicit ``return None``).
    return 127  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
