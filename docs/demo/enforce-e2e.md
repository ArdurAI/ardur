# `ardur run` — BPF-LSM enforcement and observability demo

This demo exercises the BPF-LSM enforcement and process-observability stack on
a real kernel. The current verified proof is deliberately split:

- `ardur-guard-smoke` proves that an installed BPF-LSM deny policy returns
  `EPERM` and emits enforcement evidence.
- `run.sh permissive` proves the real `ardur run` bridge, signed receipt
  registration, process exec/exit capture, correlation, and attestation metric.
- Full `ardur run --enforce` launch bootstrap is not currently a verified
  end-to-end proof: the initial governed agent exec can be denied by its own
  policy. That defect is tracked in [#241](https://github.com/ArdurAI/ardur/issues/241).

Do not combine the first two results into a claim that the current full
enforce-mode launch succeeds. They prove distinct boundaries without weakening
the kernel policy or reopening the target-policy race.

| Stage | Component | PR |
| --- | --- | --- |
| **detect** | eBPF exec/exit + BPF-LSM `enforce_events` → `ardur-kernelcaptured` | #82 / #92 / #101 |
| **enforce** | `process_guard.bpf.c` LSM hooks return `-EPERM` | #92 / #101 |
| **apply** | `ardur run` lowers the mission and pushes it to the kernel maps (`apply_policy`) | #96 |
| **attest** | hash-chained receipts + `kernel_enforcement` folded into the session attestation | #100 |
| **measure** | receipt-to-process-lifecycle observability gap in the signed attestation | #39 |

What the two verified paths demonstrate, concretely:

1. **(a) detect + attest** — the daemon registers the run's cgroup and issues a signed attestation.
2. **(b) apply reaches the kernel** — the lowered `BpfPolicyPlan` is written to the BPF maps (`kernel policy installed`).
3. **(c) a forbidden syscall actually fails `EPERM`** — the direct guard smoke proves the kernel refusal.
4. **(d) tamper-evident session evidence** — the permissive run's `enforce_events.jsonl` hash chain is committed into its attestation and verifies offline with no kernel, daemon, or root. The separate guard smoke verifies the denied raw event.
5. **(e) measured process-lifecycle gap** — the agent obtains a signed governance receipt before its attempted effect, and the attestation reports a non-empty daemon-captured sample with at least one correlated effect.

A **permissive metric run** (same mission, no `--enforce`) shows the operation
logged but allowed while exercising receipt-to-lifecycle correlation. It is
not a control paired with a successful full enforce-mode launch until #241 is
resolved.

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

## Run — seccomp fallback control-plane proof

The seccomp path is an independent full `ardur run` E2E and does not require
`bpf` in the active LSM list. The demo forces `-disable-bpf-lsm`, then runs a
network-deny mission through the seccomp listener:

```console
$ docker run --rm --privileged --pid=host \
    -v /tmp/ardur-demo-out:/out \
    ardur-enforce-demo \
    bash /opt/ardur/demo/run-seccomp.sh enforce
```

The agent first completes an authenticated `/evaluate` call and produces a
signed governance receipt. It then deliberately attempts a separate
`127.0.0.3:19999` connection so the kernel tier is tested independently of the
proxy decision. The script requires the governance decision, a non-zero
evaluated-call and receipt count, `DENIED_EPERM`, an exact denied data-plane
event, no control-plane event, an intact evidence chain, and an attestation
digest match. Every assertion is fail-fast.

The governance exception is one daemon-stored IP-and-port tuple, not loopback
or CIDR allowlisting. The supervisor connects a `pidfd_getfd(2)` duplicate of
the target socket using trusted tuple bytes and returns success without
`SECCOMP_USER_NOTIF_FLAG_CONTINUE`; see
[Kernel Capture Daemon Operations](../reference/kernel-capture-daemon.md#seccomp-governance-endpoint)
for the Linux 5.6 and ptrace-permission requirements and the remaining tier
boundary.

The paired permissive control uses the same governance call and data-plane
target but expects `ECONNREFUSED` and zero denied verdicts:

```console
$ docker run --rm --privileged --pid=host \
    -v /tmp/ardur-demo-out:/out \
    ardur-enforce-demo \
    bash /opt/ardur/demo/run-seccomp.sh permissive
```

---

## Run — enforce (known bootstrap failure)

This command is retained as a fail-fast reproducer for #241. On the current
tree it is expected to stop when the launch gate cannot exec the initial agent;
it must not be treated as a passing end-to-end demonstration.

```console
$ mkdir -p /tmp/ardur-demo-out
$ docker run --rm --privileged --pid=host \
    -v /tmp/ardur-demo-out:/out \
    ardur-enforce-demo \
    bash /opt/ardur/demo/run.sh enforce
```

Current fail-fast output (session ids and hashes vary per run):

```text
================ ardur run BPF-LSM demo — mode=enforce ================
lsm=capability,bpf,landlock  btf=yes  cgroup=cgroup2fs
daemon: BPF-LSM guard loaded ✓
  attestation   sha-256:58951f5a...
  kernel link   cgroup registered with eBPF daemon; detect→session link active
  kernel policy kernel BPF policy installed
  agent exit    126
```

The script exits 126 at this point and does not print `done`; that nonzero exit
is the expected #241 reproducer. The initial agent never starts, so this mode
does not produce a governed call or a #39 receipt-to-effect measurement.

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

## Run — permissive (current observability proof)

Same mission, **no** `--enforce`. This is the mode used by KVM CI to verify the
#39 metric against a real BPF process-lifecycle stream:

```console
$ docker run --rm --privileged --pid=host \
    -v /tmp/ardur-demo-out:/out \
    ardur-enforce-demo \
    bash /opt/ardur/demo/run.sh permissive
```

```text
AGENT: governance decision=DENY before exec
AGENT: exec(/bin/echo) SUCCEEDED — not blocked            # <-- same op, now allowed
AGENT: RESULT=ALLOWED
observability gap status = measured
observability gap captured effects = 4
observability gap correlated effects = 2
observability gap ratio = 0.5
entries         = 104
denied verdicts = 0
chain intact    = true
attestation digest match = true
```

`/bin/echo` runs to completion (hence 14 logged file-reads as it loads
`libc`/`ld.so`/locale), every event `verdict=blocked` (logged, not enforced).
The permissive run does not prove denial. The separate `ardur-guard-smoke`
test proves BPF-LSM denial directly; combining those results is intentionally
deferred until #241 provides a kernel-verifiable bootstrap boundary.

Counts vary with the kernel and process startup sequence. The verifier requires
a non-empty captured sample and at least one correlated effect, but the ratio
describes only captured `process_exec` / `process_exit` events. It is not a
file, network, provider-hidden, or universal host-effect coverage claim. A
capture-loss window reports `degraded` instead of `measured`.

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
line. The direct guard smoke proves that this installed policy denies external
exec with `EPERM`; the current full `ardur run --enforce` path fails earlier at
its own bootstrap exec, as documented above.

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

- Enforcement receipts can still report **`correlation = ambiguous/ambiguous`**
  when a burst cannot be tied to one tool-call receipt. The #39 verifier instead
  requires at least one process-lifecycle event correlated to the registered
  governance receipt; cgroup attribution to the session remains exact.
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
