# `ardur run --enforce` — kernel enforcement end-to-end demo

This demo drives the **whole Epic A enforcement stack together** on a real
BPF-LSM kernel and proves the cycle end to end — not just per component:

| Stage | Component | PR |
| --- | --- | --- |
| **detect** | eBPF exec/exit + BPF-LSM `enforce_events` → `ardur-kernelcaptured` | #82 / #92 / #101 |
| **enforce** | `process_guard.bpf.c` LSM hooks return `-EPERM` | #92 / #101 |
| **apply** | `ardur run` lowers the mission and pushes it to the kernel maps (`apply_policy`) | #96 |
| **attest** | hash-chained receipts + `kernel_enforcement` folded into the session attestation | #100 |

What it demonstrates, concretely:

1. **(a) detect + attest** — the daemon registers the run's cgroup and issues a signed attestation.
2. **(b) apply reaches the kernel** — the lowered `BpfPolicyPlan` is written to the BPF maps (`kernel policy installed`).
3. **(c) the forbidden syscall actually fails `EPERM`** — a benign agent's `execve` is refused by the kernel.
4. **(d) tamper-evident evidence** — the `enforce_events.jsonl` hash chain records the denial, the attestation commits to the chain head, and both **verify offline** with no kernel, daemon, or root.

A **permissive control run** (same mission, no `--enforce`) shows the same op
*logged but allowed* — isolating the kernel as the thing that enforces.

---

## Prerequisites

The one hard requirement is a Linux kernel with **`bpf` in the active LSM list**
plus **BTF** and **cgroup v2**. Loading a `BPF_PROG_TYPE_LSM` program needs the
`bpf` LSM to be enabled at boot (`lsm=...,bpf`).

On macOS, **Docker Desktop**'s LinuxKit kernel ships this by default; **Colima**
(stock Ubuntu cloud kernel) does **not**. Check whichever runtime you use:

```console
$ docker run --rm --privileged alpine sh -c \
    'mount -t securityfs securityfs /sys/kernel/security 2>/dev/null; \
     echo "lsm=$(cat /sys/kernel/security/lsm)"; \
     test -f /sys/kernel/btf/vmlinux && echo "btf=yes"'
lsm=capability,bpf,landlock      # <-- must contain "bpf"
btf=yes
```

If `lsm=` does not contain `bpf`, this kernel cannot enforce — pick another
runtime (Docker Desktop works) or boot the VM kernel with `lsm=...,bpf`.

The container runs `--privileged --pid=host` (CAP_BPF/CAP_SYS_ADMIN to load LSM
programs; `--pid=host` so the daemon's exec/exit correlation sees host PIDs).

---

## Build

From the **repository root**:

```console
$ docker build -f docs/demo/enforce-e2e/Dockerfile -t ardur-enforce-demo .
```

The image builds `ardur-kernelcaptured` and the `enforce-verify` tool from
source (the committed `processguard_bpfel.o` is used as-is — no clang needed)
and installs the `ardur` CLI.

---

## Run — enforce

```console
$ mkdir -p /tmp/ardur-demo-out
$ docker run --rm --privileged --pid=host \
    -v /tmp/ardur-demo-out:/out \
    ardur-enforce-demo \
    bash /opt/ardur/demo/run.sh enforce
```

Expected output (session ids and hashes vary per run):

```text
================ ardur run BPF-LSM demo — mode=enforce ================
lsm=capability,bpf,landlock  btf=yes  cgroup=cgroup2fs
daemon: BPF-LSM guard loaded ✓
AGENT: pid=2923 cgroup=0::/
AGENT: sleeping 4.0s for apply_policy to land...
AGENT: exec(/bin/echo) BLOCKED — errno=1 (EPERM)          # <-- (c) kernel refused the exec
AGENT: RESULT=DENIED_EPERM
  attestation   sha-256:c7406a51...                        # <-- (a) signed attestation
  kernel link   cgroup registered with eBPF daemon; detect→session link active
  kernel policy kernel BPF policy installed                # <-- (b) apply_policy reached the kernel
  agent exit    0
------ offline verification (no kernel, no daemon, no root) ------
attestation kernel_enforcement.chain_digest = caca42ff...
entries         = 2
denied verdicts = 2
chain intact    = true                                     # <-- (d) hash chain verifies
chain head hash = caca42ff...
attestation digest match = true                            # <-- (d) attestation commits to the log
enforce-verify exit: 0
== demo (enforce) done ==
```

The kernel evidence log (`/tmp/ardur-demo-out/enforce/enforce_events.jsonl`),
one hash-chained record per line:

```jsonc
// seq 1 — the interpreter's own /proc/self/stat read, denied under STRICT
{"seq":1,"prev_hash":"","hash":"7429a1ff…","event":{"PID":2923,"Op":2,"ActionTaken":1,"EnforceMode":1,"Comm":"python3","Path":"/proc/2923/stat"},"verdict":"denied",…}
// seq 2 — the denied open of the /bin/echo binary during execve (the exec attempt)
{"seq":2,"prev_hash":"7429a1ff…","hash":"caca42ff…","event":{"PID":2924,"Op":2,"ActionTaken":1,"EnforceMode":1,"Comm":"python3","Path":"/usr/bin/echo"},"verdict":"denied",…}
```

The attestation carries the rollup (Op codes: `1`=EXEC, `2`=FILE_READ,
`4`=NET_CONNECT; Action `1`=DENY; Mode `1`=ENFORCE):

```json
"kernel_enforcement": {
  "total_events": 2, "verdict_counts": {"denied": 2},
  "tier_coverage": {"bpf_lsm:enforce": 2}, "last_seq": 2,
  "chain_digest": "caca42ff…",
  "tamper_chain_start_seq": 1,
  "kill_switch_change_count": 0,
  "kill_switch_engaged_during_session": false,
  "kill_switch_evidence_gap": false
}
```

If the global kernel kill switch changes while a session is active, the daemon
first appends an attributed transition to `_tamper/tamper_audit.jsonl`. The
session snapshot then also carries `tamper_chain_last_seq` and
`tamper_chain_digest`; the signed attestation therefore commits to that global
tamper-chain head. `tamper_chain_start_seq` delimits the first chain entry that
could overlap the session, `kill_switch_change_count` counts committed
transitions in that window, and `kill_switch_engaged_during_session` stays true
after a later disengage so a suspension interval cannot disappear from the
final state. `kill_switch_evidence_gap` is conservative: it becomes true if a
receipt cannot be persisted, even when the daemon successfully rolls the kernel
map back. A caller receives `OK:false` for that operation rather than success
without evidence.

## Run — permissive (control)

Same mission, **no** `--enforce`:

```console
$ docker run --rm --privileged --pid=host \
    -v /tmp/ardur-demo-out:/out \
    ardur-enforce-demo \
    bash /opt/ardur/demo/run.sh permissive
```

```text
AGENT: exec(/bin/echo) SUCCEEDED — not blocked            # <-- same op, now allowed
AGENT: RESULT=ALLOWED
...
entries         = 14
denied verdicts = 0                                        # events logged as "blocked", not denied
chain intact    = true
```

`/bin/echo` runs to completion (hence 14 logged file-reads as it loads
`libc`/`ld.so`/locale), every event `verdict=blocked` (logged, not enforced).
The **only** difference between the runs is `--enforce`, so the kernel is
demonstrably the thing that turned the log into a block.

---

## What actually happened (mechanism)

`--enforce` does two things to the run's cgroup:

1. Lowers `--forbidden-tools Bash` → **`OP_EXEC = DENY` (enforce)**.
2. Sets the cgroup's **`STRICT`** flag → any op with *no explicit rule*
   fails **closed** (`-EPERM`). `OP_FILE_READ` has no rule, so it fail-closes.

When the agent's child calls `execv("/bin/echo")`, the kernel's `open_exec()`
opens the binary first — that fires the `lsm.s/file_open` hook with
`OP_FILE_READ` on `/usr/bin/echo`, which STRICT denies with `-EPERM`. So the
`execve` is refused *at the binary-open step*, before `bprm_check_security` is
even reached; the explicit `OP_EXEC` deny is the belt-and-suspenders second
line. Net guarantee: **a governed agent under `--enforce` cannot execute
external programs** — proven by the `EPERM`.

In **permissive** mode there is no STRICT flag and `OP_EXEC`'s mode is
PERMISSIVE, so the binary open passes and `bprm_check_security` fires with
`OP_EXEC` — logged as `blocked` but returning `0` (allow). (In that run you can
see the actual `Op=1` exec event on `/bin/echo` followed by echo's own file
reads.)

---

## Offline verification

`enforce-verify` (built into the image, also `go run ./cmd/enforce-verify` from
the repo) re-derives the SHA-256 chain with the same
`kernelcapture.VerifyEnforceReceiptChain` the daemon ships — **no kernel, no
daemon, no root**:

```console
$ enforce-verify enforce_events.jsonl <attestation-chain_digest>
entries         = 2
denied verdicts = 2
chain intact    = true
attestation digest match = true      # the signed attestation commits to this exact log
```

Tampering is detected (edit any event and re-run → `chain intact = false`,
exit 1). This is covered by `go/cmd/enforce-verify/verify_test.go` and by the
producer's own `enforce_receipt_chain_test.go`.

---

## Notes & caveats

- **`correlation = ambiguous/ambiguous`** in the log is expected: the kernel's
  action (DENY) is authoritative on its own; correlation only *grades* how
  confidently an event maps to a specific tool-call receipt, and the burst of
  events at exec time leaves that grading ambiguous. Attribution to the session
  (via cgroup id) is exact.
- **`--max-tool-calls 50`** is passed explicitly in `run.sh`. Plain `ardur run`
  without it crashes on current `dev` (`int(None)` `TypeError`); fixed in #111.
- **Colima / stock cloud kernels won't work** — they don't boot with `bpf` in
  the LSM list. Use Docker Desktop (LinuxKit) or a kernel booted `lsm=...,bpf`.
- This is a **single-host dev demo**. Production packaging (systemd unit,
  privileged installer) is Slice 2 (#91).

## Cleanup

```console
$ rm -rf /tmp/ardur-demo-out
$ docker image rm ardur-enforce-demo
```
