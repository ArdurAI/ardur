#!/usr/bin/env bash
# In-container orchestration for the `ardur run --enforce` seccomp-tier e2e
# demo (plan E4 / issue #104) — the seccomp counterpart to run.sh's BPF-LSM
# demo. Runs inside the same privileged demo image (see
# docs/demo/enforce-e2e.md), forcing the daemon onto the seccomp fallback
# tier with -disable-bpf-lsm so this proves the fallback path specifically,
# even on a host (like this image's kernel) where BPF-LSM would otherwise win
# tier selection.
#   Usage: run-seccomp.sh <enforce|permissive>
set -euo pipefail
MODE="${1:-enforce}"
OUT="/out/seccomp-${MODE}"; mkdir -p "$OUT"
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
DPID=""

cleanup() {
  if [ -n "$DPID" ]; then
    kill "$DPID" 2>/dev/null || true
    wait "$DPID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

case "$MODE" in
  enforce|permissive) ;;
  *) echo "usage: $0 <enforce|permissive>" >&2; exit 2 ;;
esac

echo "============ ardur run seccomp-tier demo — mode=${MODE} ============"

# 0. kernel-facing filesystems (idempotent; require --privileged)
mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true
mount -t bpf        bpf        /sys/fs/bpf          2>/dev/null || true
mount -t tracefs    tracefs    /sys/kernel/tracing  2>/dev/null || true
mkdir -p /run/ardur /var/lib/ardur
echo "cgroup=$(stat -fc %T /sys/fs/cgroup)"

# 1. start the daemon *forced onto the seccomp tier*; wait for its handoff
#    socket to come up (the seccomp-tier equivalent of run.sh's
#    "process_guard loaded" wait).
rm -rf /var/lib/ardur/kernelcapture/evidence/* 2>/dev/null || true
ardur-kernelcaptured -debug -disable-bpf-lsm > "$OUT/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 40); do
  grep -q "seccomp handoff socket listening" "$OUT/daemon.log" && break
  kill -0 $DPID 2>/dev/null || { echo "daemon died:"; cat "$OUT/daemon.log"; exit 1; }
  sleep 0.25
done
if grep -q "seccomp handoff socket listening" "$OUT/daemon.log"; then
  echo "daemon: seccomp tier active, handoff socket listening ✓"
else
  echo "daemon: seccomp handoff socket never came up"
  tail -5 "$OUT/daemon.log"
  exit 1
fi
if grep -q "\"tier\":\"seccomp\"" "$OUT/daemon.log"; then
  echo "daemon: enforcement_tier=seccomp confirmed (BPF-LSM was disabled, not just unavailable) ✓"
else
  echo "daemon: expected seccomp tier was not selected"
  tail -10 "$OUT/daemon.log"
  exit 1
fi

# 2. ardur run a benign agent under a mission that forbids network access.
#    --no-resource-scope: skip the default cwd file allowlist, which the
#    seccomp tier can never satisfy (it only enforces OP_NET_CONNECT) — see
#    run_governed()'s no_resource_scope docstring. Without this the mission
#    would never reach applied_seccomp_tier at all, regardless of the shim
#    wiring this demo exists to prove (issue #104).
ENF=""; [ "$MODE" = "enforce" ] && ENF="--enforce"
ardur run \
  --home "/out/home-seccomp-${MODE}" \
  --mission "Kernel demo: network access is forbidden (seccomp tier)." \
  --forbidden-tools fetch \
  --no-resource-scope \
  --max-tool-calls 50 \
  --via env \
  $ENF \
  -- python3 "$DEMO_DIR/agent_seccomp.py" 2>&1 | tee "$OUT/ardur-run.log" | grep -E "AGENT:|kernel policy|kernel link|attestation|agent exit|ardur-exec-shim|ardur run:"

grep -q "AGENT: governance decision=DENY before connect" "$OUT/ardur-run.log"
grep -Eq "tool calls[[:space:]]+[1-9][0-9]* evaluated" "$OUT/ardur-run.log"
grep -Eq "receipts[[:space:]]+[1-9][0-9]* signed" "$OUT/ardur-run.log"
grep -Eq "agent exit[[:space:]]+0$" "$OUT/ardur-run.log"
if [ "$MODE" = "enforce" ]; then
  grep -q "AGENT: RESULT=DENIED_EPERM" "$OUT/ardur-run.log"
else
  grep -q "AGENT: RESULT=DENIED_ECONNREFUSED" "$OUT/ardur-run.log"
fi

# 3. offline evidence verification: hash-chain integrity + attestation linkage.
#    Same enforce_events.jsonl format and same enforce-verify tool as the
#    BPF-LSM demo — the E3 evidence pipeline is shared across both tiers.
EVID=$(find /var/lib/ardur/kernelcapture/evidence -name enforce_events.jsonl -print -quit 2>/dev/null)
if [ -n "$EVID" ]; then
  cp "$EVID" "$OUT/enforce_events.jsonl"
  python3 - "$OUT/enforce_events.jsonl" "$MODE" <<'PY'
import json
import sys

path, mode = sys.argv[1:]
entries = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
targets = [(entry.get("event") or {}).get("Path", "") for entry in entries]
if "127.0.0.3:19999" not in targets:
    raise SystemExit(f"FAIL: exact data-plane target missing from evidence: {targets}")
if any(target.startswith("127.0.0.1:") for target in targets):
    raise SystemExit(f"FAIL: control-plane exemption emitted as mission evidence: {targets}")
denied = sum(entry.get("verdict") == "denied" for entry in entries)
if mode == "enforce" and denied < 1:
    raise SystemExit("FAIL: enforce mode produced no denied data-plane verdict")
print(f"seccomp evidence exact data-plane target = 127.0.0.3:19999; denied verdicts = {denied}")
PY
  DIGEST=$(python3 - "/out/home-seccomp-${MODE}" <<'PY'
import base64, glob, json, os, sys
home = sys.argv[1]
for p in glob.glob(f"{home}/**/*", recursive=True):
    if not os.path.isfile(p): continue
    try: txt = open(p, encoding="utf-8", errors="ignore").read()
    except OSError: continue
    for tok in txt.replace('"', " ").split():
        if tok.startswith("ey") and tok.count(".") == 2 and len(tok) > 80:
            try:
                pad = tok.split(".")[1]; pad += "=" * (-len(pad) % 4)
                c = json.loads(base64.urlsafe_b64decode(pad))
            except Exception: continue
            if "scope_compliance" in c:
                print((c.get("kernel_enforcement") or {}).get("chain_digest", "")); sys.exit()
PY
)
  echo "------ offline verification (no kernel, no daemon, no root) ------"
  echo "attestation kernel_enforcement.chain_digest = ${DIGEST:-<none>}"
  [ -n "$DIGEST" ] || { echo "FAIL: attestation has no kernel-enforcement chain digest"; exit 1; }
  enforce-verify "$OUT/enforce_events.jsonl" "$DIGEST"
  echo "enforce-verify exit: 0"
else
  echo "FAIL: no enforce_events.jsonl produced for the data-plane probe"
  exit 1
fi

cleanup
DPID=""
echo "== seccomp demo (${MODE}) done =="
