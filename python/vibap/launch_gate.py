"""PID-preserving pre-exec gate for ``ardur run`` kernel registration."""

from __future__ import annotations

import argparse
import ctypes
import os
import signal
import sys
import time


RELEASE_BYTE = b"\x01"
PARENT_NOT_READY_EXIT = 125
PTRACE_TRACEME = 0
PTRACE_CONT = 7
PTRACE_DETACH = 17
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_TRACEEXEC = 1 << 4
PTRACE_O_EXITKILL = 1 << 20
PTRACE_EVENT_EXEC = 4
TRACE_STOP_TIMEOUT_S = 10.0


def _ptrace(request: int, pid: int, data: int = 0) -> None:
    """Issue one Linux ptrace request and preserve errno on failure."""
    libc = ctypes.CDLL(None, use_errno=True)
    ptrace = libc.ptrace
    ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
    ptrace.restype = ctypes.c_long
    ctypes.set_errno(0)
    result = ptrace(request, pid, None, ctypes.c_void_p(data))
    if result == -1:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def _wait_for_stop(pid: int, *, timeout_s: float) -> int:
    deadline = time.monotonic() + timeout_s
    while True:
        waited_pid, status = os.waitpid(pid, os.WNOHANG)
        if waited_pid == pid:
            return status
        if time.monotonic() >= deadline:
            raise TimeoutError(f"process {pid} did not reach ptrace stop within {timeout_s}s")
        time.sleep(0.01)


def wait_for_exec_stop(pid: int, *, timeout_s: float = TRACE_STOP_TIMEOUT_S) -> None:
    """Hold ``pid`` at its post-exec kernel stop until policy is installed."""
    status = _wait_for_stop(pid, timeout_s=timeout_s)
    if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGSTOP:
        raise RuntimeError(f"launch gate {pid} did not report its initial SIGSTOP (status={status:#x})")

    _ptrace(PTRACE_SETOPTIONS, pid, PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL)
    _ptrace(PTRACE_CONT, pid)

    status = _wait_for_stop(pid, timeout_s=timeout_s)
    event = status >> 16
    if not os.WIFSTOPPED(status) or os.WSTOPSIG(status) != signal.SIGTRAP or event != PTRACE_EVENT_EXEC:
        raise RuntimeError(f"launch gate {pid} did not reach PTRACE_EVENT_EXEC (status={status:#x})")


def release_exec_stop(pid: int) -> None:
    """Detach from a tracee stopped at PTRACE_EVENT_EXEC and let it run."""
    _ptrace(PTRACE_DETACH, pid)


def _parse_args(argv: list[str]) -> tuple[int | None, bool, list[str]]:
    parser = argparse.ArgumentParser(description="wait for Ardur registration, then exec a command")
    gate = parser.add_mutually_exclusive_group(required=True)
    gate.add_argument("--ready-fd", type=int, help=argparse.SUPPRESS)
    gate.add_argument("--trace-exec", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("a command is required after --")
    return args.ready_fd, args.trace_exec, command


def main(argv: list[str] | None = None) -> int:
    ready_fd, trace_exec, command = _parse_args(list(sys.argv[1:] if argv is None else argv))
    if trace_exec:
        try:
            _ptrace(PTRACE_TRACEME, 0)
            os.kill(os.getpid(), signal.SIGSTOP)
        except OSError as exc:
            print(f"ardur launch gate: ptrace bootstrap failed: {exc}", file=sys.stderr)
            return PARENT_NOT_READY_EXIT
    else:
        assert ready_fd is not None
        try:
            release = os.read(ready_fd, 1)
        except OSError as exc:
            print(f"ardur launch gate: parent readiness channel failed: {exc}", file=sys.stderr)
            return PARENT_NOT_READY_EXIT
        finally:
            try:
                os.close(ready_fd)
            except OSError:
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
