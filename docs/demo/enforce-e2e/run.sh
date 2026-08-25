#!/usr/bin/env bash
# In-container orchestration for the `ardur run` BPF-LSM e2e demo.
# Runs inside the privileged demo image (see docs/demo/enforce-e2e.md).
#   Usage: run.sh <enforce|permissive>
set -euo pipefail
MODE="${1:-enforce}"
# OUT_BASE defaults to /out (the Docker demo image mounts a writable /out).
# virtme-ng boots the host rootfs read-only, so the vng wrapper
# (ci-vng-observability-gap.sh) points this at a writable tmpfs instead.
OUT_BASE="${OUT_BASE:-/out}"
OUT="${OUT_BASE}/${MODE}"; mkdir -p "$OUT"
RUN_HOME="${OUT_BASE}/home-${MODE}"
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
DPID=""

cleanup() {
  if [ -n "$DPID" ]; then
    kill "$DPID" 2>/dev/null || true
    wait "$DPID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "================ ardur run BPF-LSM demo — mode=${MODE} ================"

# 0. kernel-facing filesystems (idempotent; require --privileged)
mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true
mount -t bpf        bpf        /sys/fs/bpf          2>/dev/null || true
mount -t tracefs    tracefs    /sys/kernel/tracing  2>/dev/null || true
mkdir -p /run/ardur /var/lib/ardur
echo "lsm=$(cat /sys/kernel/security/lsm 2>/dev/null)  btf=$(test -f /sys/kernel/btf/vmlinux && echo yes || echo no)  cgroup=$(stat -fc %T /sys/fs/cgroup)"

# 1. start the daemon; wait for the BPF-LSM guard to attach
rm -rf /var/lib/ardur/kernelcapture/evidence/* 2>/dev/null || true
ardur-kernelcaptured -debug > "$OUT/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 40); do
  grep -q "process_guard loaded" "$OUT/daemon.log" && break
  kill -0 $DPID 2>/dev/null || { echo "daemon died:"; cat "$OUT/daemon.log"; exit 1; }
  sleep 0.25
done
if grep -q "process_guard loaded" "$OUT/daemon.log"; then
  echo "daemon: BPF-LSM guard loaded ✓"
else
  echo "daemon: guard NOT loaded"
  tail -5 "$OUT/daemon.log"
  kill "$DPID"
  exit 1
fi

# 2. ardur run a benign agent under a mission that forbids executing programs.
#    --max-tool-calls is passed explicitly to support dev before fix #111.
ENF=""; [ "$MODE" = "enforce" ] && ENF="--enforce"
if ! ardur run \
  --home "$RUN_HOME" \
  --mission "Kernel demo: executing external programs is forbidden." \
  --forbidden-tools Bash \
  --max-tool-calls 50 \
  --via env \
  $ENF \
  -- python3 "$DEMO_DIR/agent.py" 2>&1 | tee "$OUT/ardur-run.log" | grep -E "AGENT:|kernel policy|kernel link|attestation|agent exit"; then
  echo "ardur run pipeline failed; full captured output follows:"
  cat "$OUT/ardur-run.log"
  exit 1
fi

grep -q "AGENT: governance decision=DENY before exec" "$OUT/ardur-run.log"
grep -Eq "tool calls[[:space:]]+1 evaluated" "$OUT/ardur-run.log"
grep -Eq "receipts[[:space:]]+1 signed" "$OUT/ardur-run.log"
grep -Eq "agent exit[[:space:]]+0" "$OUT/ardur-run.log"
if [ "$MODE" = "enforce" ]; then
  grep -q "AGENT: RESULT=DENIED_EPERM" "$OUT/ardur-run.log"
else
  grep -q "AGENT: RESULT=ALLOWED" "$OUT/ardur-run.log"
fi

python3 "$DEMO_DIR/verify-observability-gap.py" "$RUN_HOME"

# 3. offline evidence verification: hash-chain integrity + attestation linkage
EVID=$(find /var/lib/ardur/kernelcapture/evidence -name enforce_events.jsonl -print -quit 2>/dev/null)
if [ -n "$EVID" ]; then
  cp "$EVID" "$OUT/enforce_events.jsonl"
  # Pull kernel_enforcement.chain_digest from the session attestation (the JWT
  # whose claims carry scope_compliance — distinct from the mission passport).
  DIGEST=$(python3 - "$RUN_HOME" <<'PY'
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
            if "scope_compliance" in c:  # attestation, not passport
                print((c.get("kernel_enforcement") or {}).get("chain_digest", "")); sys.exit()
PY
)
  echo "------ offline verification (no kernel, no daemon, no root) ------"
  echo "attestation kernel_enforcement.chain_digest = ${DIGEST:-<none>}"
  enforce-verify "$OUT/enforce_events.jsonl" ${DIGEST:+$DIGEST}
  echo "enforce-verify exit: $?"
fi
test -n "$EVID"

kill "$DPID" 2>/dev/null || true
wait "$DPID" 2>/dev/null || true
DPID=""
echo "== demo (${MODE}) done =="
