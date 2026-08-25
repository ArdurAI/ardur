#!/usr/bin/env python3
"""Benign demo agent for the `ardur run --enforce` seccomp-tier end-to-end demo.

The seccomp counterpart to agent.py's exec-blocking demo: instead of a
forbidden execve, this attempts a forbidden connect(2) — the one syscall the
seccomp user-notify fallback tier can enforce (plan E4). Same timeline
contract as agent.py: sleep first so ardur-exec-shim's handoff to the daemon
has landed before the probe runs (register_session/apply_policy/handoff all
race the agent's own startup, same as the BPF-LSM path's apply_policy race).

The agent first performs a real authenticated /evaluate request against the
embedded governance bridge. Under --enforce (OP_NET_CONNECT deny, seccomp tier
active) that exact daemon-owned control-plane tuple remains reachable, while
the later unrelated loopback connect is refused with EPERM. Under permissive
the same data-plane op is logged but allowed.
"""
import errno
import json
import os
import socket
import time
import urllib.request

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

request = urllib.request.Request(
    os.environ["ARDUR_PROXY_URL"] + "/evaluate",
    data=json.dumps(
        {
            "session_id": os.environ["ARDUR_SESSION_ID"],
            "tool_name": "fetch",
            "arguments": {"url": f"http://{TARGET_HOST}:{TARGET_PORT}/probe"},
        }
    ).encode(),
    method="POST",
    headers={
        "Authorization": "Bearer " + os.environ["ARDUR_API_TOKEN"],
        "Content-Type": "application/json",
    },
)
with urllib.request.urlopen(request, timeout=5) as response:
    governance = json.loads(response.read())
print(f"AGENT: governance decision={governance['decision']} before connect", flush=True)

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
