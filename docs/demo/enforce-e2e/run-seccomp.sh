#!/usr/bin/env bash
# In-container orchestration for the `ardur run --enforce` seccomp-tier e2e
# demo (plan E4 / issue #104) — the seccomp counterpart to run.sh's BPF-LSM
# demo. Runs inside the same privileged demo image (see
# docs/demo/enforce-e2e.md), forcing the daemon onto the seccomp fallback
# tier with -disable-bpf-lsm so this proves the fallback path specifically,
# even on a host (like this image's kernel) where BPF-LSM would otherwise win
# tier selection.
#   Usage: run-seccomp.sh <enforce|permissive>
set -u
MODE="${1:-enforce}"
OUT="/out/seccomp-${MODE}"; mkdir -p "$OUT"
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"

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
grep -q "seccomp handoff socket listening" "$OUT/daemon.log" \
  && echo "daemon: seccomp tier active, handoff socket listening ✓" \
  || { echo "daemon: seccomp handoff socket never came up"; tail -5 "$OUT/daemon.log"; kill $DPID; exit 1; }
grep -q "\"tier\":\"seccomp\"" "$OUT/daemon.log" \
  && echo "daemon: enforcement_tier=seccomp confirmed (BPF-LSM was disabled, not just unavailable) ✓"

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

# 3. offline evidence verification: hash-chain integrity + attestation linkage.
#    Same enforce_events.jsonl format and same enforce-verify tool as the
#    BPF-LSM demo — the E3 evidence pipeline is shared across both tiers.
EVID=$(find /var/lib/ardur/kernelcapture/evidence -name enforce_events.jsonl 2>/dev/null | head -1)
if [ -n "$EVID" ]; then
  cp "$EVID" "$OUT/enforce_events.jsonl"
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
  enforce-verify "$OUT/enforce_events.jsonl" ${DIGEST:+$DIGEST}
  echo "enforce-verify exit: $?"
else
  echo "no enforce_events.jsonl produced — nothing to verify"
  [ "$MODE" = "enforce" ] && { echo "FAIL: enforce mode must produce evidence of the denial"; kill $DPID 2>/dev/null; exit 1; }
fi

kill $DPID 2>/dev/null; wait $DPID 2>/dev/null
echo "== seccomp demo (${MODE}) done =="
