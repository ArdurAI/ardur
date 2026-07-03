#!/usr/bin/env python3
"""Benign demo agent for the `ardur run --enforce` seccomp-tier end-to-end demo.

The seccomp counterpart to agent.py's exec-blocking demo: instead of a
forbidden execve, this attempts a forbidden connect(2) — the one syscall the
seccomp user-notify fallback tier can enforce (plan E4). Same timeline
contract as agent.py: sleep first so ardur-exec-shim's handoff to the daemon
has landed before the probe runs (register_session/apply_policy/handoff all
race the agent's own startup, same as the BPF-LSM path's apply_policy race).

Under --enforce (OP_NET_CONNECT deny, seccomp tier active) the kernel refuses
the connect with EPERM; under permissive the same op is logged but allowed.
"""
import errno
import os
import socket
import time

DELAY = float(os.environ.get("AGENT_DELAY", "4"))
TARGET_HOST = os.environ.get("AGENT_CONNECT_HOST", "127.0.0.3")
TARGET_PORT = int(os.environ.get("AGENT_CONNECT_PORT", "19999"))

try:
    with open("/proc/self/cgroup", encoding="ascii") as fh:
        cgline = fh.read().strip()
except OSError as exc:
    cgline = f"<unreadable: {exc}>"
print(f"AGENT: pid={os.getpid()} cgroup={cgline}", flush=True)

print(f"AGENT: sleeping {DELAY}s for the seccomp handoff to land...", flush=True)
time.sleep(DELAY)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.connect((TARGET_HOST, TARGET_PORT))
    print(f"AGENT: connect({TARGET_HOST}:{TARGET_PORT}) SUCCEEDED — not blocked", flush=True)
    print("AGENT: RESULT=ALLOWED", flush=True)
except OSError as exc:
    ev = exc.errno
    name = errno.errorcode.get(ev, "?")
    print(f"AGENT: connect({TARGET_HOST}:{TARGET_PORT}) BLOCKED — errno={ev} ({name})", flush=True)
    print(f"AGENT: RESULT={'DENIED_EPERM' if ev == errno.EPERM else f'DENIED_{name}'}", flush=True)
finally:
    sock.close()
