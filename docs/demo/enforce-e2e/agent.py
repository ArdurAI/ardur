#!/usr/bin/env python3
"""Benign demo agent for the `ardur run --enforce` BPF-LSM end-to-end demo.

Timeline (matches run_bridge: Popen -> adopt into cgroup -> apply_policy):
  1. Record our own cgroup (read BEFORE any deny policy could block a file open).
  2. Sleep, so run_bridge's apply_policy lands before we probe.
  3. Attempt the forbidden exec (/bin/echo) in a forked child and report the
     child's errno. Under --enforce (OP_EXEC deny + STRICT) the kernel refuses
     it with EPERM; under permissive the same op is logged but allowed.

The parent only does pipe/fork/wait/write-to-stdout after the policy lands —
none of which are hooked operations — so STRICT fail-closed does not brick it.
"""
import errno
import os
import time

DELAY = float(os.environ.get("AGENT_DELAY", "4"))

try:
    with open("/proc/self/cgroup", encoding="ascii") as fh:
        cgline = fh.read().strip()
except OSError as exc:
    cgline = f"<unreadable: {exc}>"
print(f"AGENT: pid={os.getpid()} cgroup={cgline}", flush=True)

print(f"AGENT: sleeping {DELAY}s for apply_policy to land...", flush=True)
time.sleep(DELAY)

target = os.environ.get("AGENT_EXEC_TARGET", "/bin/echo")
r, w = os.pipe()  # CLOEXEC by default (PEP 446): auto-closed on a successful execve
pid = os.fork()
if pid == 0:
    os.close(r)
    try:
        os.execv(target, [target, "AGENT-EXEC-RAN"])
    except OSError as exc:
        os.write(w, str(exc.errno).encode())
        os._exit(99)
    os._exit(0)  # unreachable on success (process is replaced)

os.close(w)
payload = os.read(r, 16).decode().strip()
os.waitpid(pid, 0)

if payload == "":
    print(f"AGENT: exec({target}) SUCCEEDED — not blocked", flush=True)
    print("AGENT: RESULT=ALLOWED", flush=True)
else:
    ev = int(payload)
    name = errno.errorcode.get(ev, "?")
    print(f"AGENT: exec({target}) BLOCKED — errno={ev} ({name})", flush=True)
    print(f"AGENT: RESULT={'DENIED_EPERM' if ev == errno.EPERM else f'DENIED_{name}'}", flush=True)
