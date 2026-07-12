# Kernel Capture Daemon Operations

`ardur-kernelcaptured` is the Linux daemon that owns Ardur's local Unix-socket
control plane and kernel event consumers. This reference describes
control-plane-only mode, process-lifecycle cgroup filtering, and capture-loss
evidence.

## Control-plane-only mode

Start the daemon with `--no-ringbuf` only when intentionally testing or
diagnosing the socket control plane:

```bash
ardur-kernelcaptured --no-ringbuf
```

The flag keeps the daemon's health and session-control socket available, but it
does not start the process exec/exit consumer, the BPF-LSM enforcement
consumer, or the seccomp handoff server. The daemon therefore provides neither
kernel capture nor a kernel enforcement tier in this mode. Startup emits:

```text
eBPF ringbuf consumers disabled (--no-ringbuf); enforcement tiers unavailable
```

Do not use `--no-ringbuf` as a production fallback for a failing event
consumer. A healthy socket in this mode proves control-plane liveness only; it
does not prove that a governed process is observed or constrained below the
tool-call boundary.

## Seccomp governance endpoint

On a seccomp-tier `ardur run`, the network policy also traps the agent's TCP
connection to the run's embedded governance proxy. The authenticated,
session-owning parent includes that proxy's exact literal loopback IP and port
in `apply_policy`. The daemon validates the tuple and stores it separately from
the mission's `net_allow`; hostnames, non-loopback addresses, port zero, an
endpoint without `OP_NET_CONNECT`, and broad `127/8` or `::1` CIDR exceptions
are not accepted.

For that exact tuple only, the daemon does not resume the tracee's original
`connect(2)` with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. Another target thread
could rewrite a pointer argument after inspection. Instead, the supervisor
uses `pidfd_open(2)` and `pidfd_getfd(2)` to duplicate the target socket,
connects the shared socket using the daemon-stored tuple, revalidates the
notification, and returns synthetic success with no continue flag. Any lookup,
permission, duplication, connect, or notification-validity failure returns
`EPERM`. The control connection is transport plumbing and does not emit a
mission enforcement event; unrelated loopback connections still follow the
mission policy and remain visible in evidence.

This emulation requires Linux 5.6 or newer and permission for the daemon to
perform the kernel's `PTRACE_MODE_ATTACH_REALCREDS` check for the target. A
production daemon normally satisfies that through its privileged service
identity; restrictive capability, Yama, LSM, or container settings can still
deny it, in which case the connection fails closed. See the Linux kernel
[seccomp user-notification documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html),
[`seccomp_unotify(2)`](https://www.man7.org/linux/man-pages/man2/seccomp_unotify.2.html),
and [`pidfd_getfd(2)`](https://www.man7.org/linux/man-pages/man2/pidfd_getfd.2.html).
The shipped systemd unit includes `CAP_SYS_PTRACE` in both its ambient and
bounding sets and explicitly permits `pidfd_open` and `pidfd_getfd`; custom
units must preserve those three requirements for the seccomp endpoint path.

Ordinary seccomp mission-policy allows still use `CONTINUE` and retain the
documented weaker-than-BPF-LSM race boundary. The BPF-LSM tier does not use
seccomp emulation: its root process receives an exact generation-bound
loopback IP-and-port exception in BPF, and a `PTRACE_EVENT_EXEC` stop keeps the
target from running until cgroup registration and policy application finish.

## BPF-LSM stopped-exec bootstrap

Strict BPF-LSM launch stops the new root image at `PTRACE_EVENT_EXEC`, before
target user space runs. The daemon reads `/proc/<pid>/exe`, cwd, and cmdline,
resolves symlinks, and records the executable plus at most four regular-file
arguments. It then arms a one-shot observation keyed by its own TGID and the
observed inode and opens each file synchronously. The LSM writes the
kernel-native superblock device plus inode into the target cgroup's allow map
and returns that device through an acknowledgement record. This avoids trusting
namespace-translated path, `st_dev`, or mount-ID values from userspace.
Fixed root-only runtime reads cover `/usr`, distro library roots `/lib` and
`/lib64`, the loader cache, CA certificates, entropy, and the root's `/proc`
subtree. The governed request cannot add another category.

The file-open hook additionally requires the current TGID to equal the
daemon-stamped session root and the allow-map generation to equal the active
policy generation. A child, another generation, or a replaced file object
cannot reuse the exception. Observation request setup, trigger open,
acknowledgement, and cleanup are serialized with policy application; any
failure aborts launch while the target remains stopped.

The observation map is pinned only so its ABI participates in all-or-nothing
guard-state reuse. Its requests are transient capabilities, not policy: every
daemon start clears all stale requests before exposing the policy maps or
reporting the BPF-LSM guard ready. Applied enforcement and exact-file allow
entries remain pinned across restart.

These file identities and the fixed runtime-category bitmask are daemon-private
fields added after wire validation; a governed client cannot submit or widen
them. They apply only to reads. Pinned-map reuse also validates map type, key
size, value size, capacity, and flags against the embedded BPF specification,
so an old complete pin generation cannot be paired with a new userspace ABI.
Any observation, map update, cgroup migration, policy application, or ptrace
transition failure kills the still-stopped target instead of releasing an
ungoverned process.

## Process lifecycle cgroup filter

The production lifecycle consumer pins `filter_control` and `allowed_cgroups`
with its exec/exit tracepoint links, ringbuf, and producer-drop counter as one
restart generation. An older generation without either filter-map pin is
removed before a fresh attach; partial old and new generations are not reused
together.

At startup the daemon temporarily makes the filter permissive, clears stale
allowlist entries inherited from any prior daemon lifetime, restores every
currently admitted session, and then enables filtering. An enabled filter with
an empty allowlist is the normal idle state: no unrelated host exec/exit events
enter Ardur's lifecycle ringbuf when no governed session exists.

For each `register_session`, the daemon adds the verified nonzero cgroup before
the registry can return success and before the launch gate is released. A map
update failure rejects that registration so the enabled producer cannot omit
the new session. Session end and TTL expiry first retire the userspace route and
wait for already-matched evidence work, then remove the cgroup. Multiple active
sessions retain independent entries. The BPF allowlist capacity is 4,096,
matching the daemon session registry's active-session limit.

If startup reconciliation itself fails, the daemon leaves filtering disabled
and continues the prior permissive capture behavior rather than enabling a
partial allowlist that could hide governed events. It logs the degradation; the
resource-isolation benefit is unavailable for that daemon lifetime. If the
control map cannot be switched to that known-permissive state, new session
registration fails instead of risking an enabled stale allowlist that omits the
session. When the consumer detaches cleanly, it leaves pinned filtering enabled
with an empty allowlist so pinned tracepoints do not fill the ringbuf while no
reader exists.

This is producer-side resource and completeness isolation. The userspace router
still validates session ownership before writing evidence. It does not claim
universal process capture, observe provider-hidden actions, or write unrelated
host events into session evidence.

## Opt-in agent recognition preview

Start the Linux daemon with recognition explicitly enabled:

```bash
ardur-kernelcaptured --agent-recognition
```

The embedded registry currently contains four release-bound exact Linux
`comm` values: `claude` (`claude_code`), `codex` (`codex_cli`), `gemini`
(`gemini_cli`), and `kimi` (`kimi_cli`). The BPF producer checks those names in
a 64-entry hash map and emits matching exec events alongside the unchanged
cgroup-scoped lifecycle feed. Nonmatching host execs and all host-wide exit
events are dropped before ringbuf reservation. The registry is versioned and
SHA-256-digested; the digest is integrity metadata for the embedded rules, not
a signature or software-provenance assertion.

Operator class overrides are applied before the map is populated:

```bash
ardur-kernelcaptured --agent-recognition \
  --agent-recognition-allow claude_code,codex_cli \
  --agent-recognition-deny codex_cli
```

Deny takes precedence over allow. Unknown class names fail startup, override
flags require `--agent-recognition`, and recognition cannot be combined with
`--no-ringbuf`. Every daemon start disables and clears any inherited
recognition map before installing the selected names. If optional recognition
configuration fails, the classifier is disabled while normal cgroup-scoped
lifecycle capture remains active. Clean detach disables and clears recognition
so pinned tracepoints do not keep emitting candidates without a consumer.

The daemon classifies only bounded process metadata already present in the
lifecycle event and logs a recognized candidate before session routing. An
unrouted candidate is not appended to a session evidence log. Exact-name-only
evidence has `confidence=low`,
`identity_assurance=heuristic_process_metadata`, and
`governance_action=observe_only`. No argv, executable path, binary hash, uid,
environment, or file content is collected by this preview. It does not issue a
passport, adopt a process, select policy, or enforce an action. A process can
reuse one of these names, while interpreter-backed installs can appear as
`node` or another generic runtime; both false positives and false negatives
therefore remain possible. Issue #67 remains open for the multi-signal corpus
and precision/recall gate.

## Lifecycle capture loss

Lifecycle capture has two observable loss sources. If the eBPF producer cannot
reserve ringbuf space, it increments a pinned monotonic counter. The daemon
baselines inherited totals at startup and samples new deltas after delivered
events and before session registration, status, or end:

```text
lifecycle ringbuf producer drops observed drop_count=<n> kernel_dropped_total=<n> loss_epoch=<n>
```

Separately, the userspace consumer decodes a fixed binary record emitted by the
matching eBPF program. A record that is too short for that ABI, or otherwise
cannot be decoded, produces:

```text
malformed ringbuf record loss_epoch=<n>
```

The daemon drops a malformed record and continues reading. For either source,
`loss_epoch` is a monotonic daemon-lifetime identifier for a host-wide lifecycle
capture gap. Missing or malformed records have no trustworthy session owner, so
every session active when the gap is observed records the same increment. An
uncorrelated valid event cannot clear the summary, and a session registered
after the prior counter delta was sampled does not inherit it.

Successful `session_status` and `end_session` responses expose the summary with
`coverage_status`, total `ringbuf_dropped`, source-specific
`producer_ringbuf_dropped` / `malformed_records`, sticky
`producer_counter_evidence_gap`, `daemon_queue_dropped`, and the
first and last affected loss epochs. The evidence-gap flag becomes true if the
counter cannot be read, moves backwards, or a previously installed live source
disappears. Sessions registered while that unavailable state persists inherit
the flag. In that case the missing count is unknown, even if the numeric
counters are zero. The run bridge fetches this summary before ending a normal
governed session and folds it into the signed attestation as
`kernel_enforcement.lifecycle_capture`. The daemon retains the summary for the
session lifetime and returns it on every status request; individual lifecycle
receipts do not misrepresent the host-global gap as event-local capture loss.

A producer drop points to ringbuf pressure. A malformed record instead points
to a producer/consumer ABI mismatch, truncated sample, or corruption after
reservation. Neither is the expected symptom of a BPF verifier rejection:
verifier or attach failures occur during startup and are reported by the loader
before records can be emitted.

## Process-lifecycle observability gap

The `ardur run` proxy registers each signed receipt identifier with the daemon
after writing the receipt and before returning the evaluation response that
releases the action. `register_receipt` accepts only a bounded opaque identifier
from the Unix-socket peer that owns the active session. PID, cgroup, peer
identity, and observation time come from daemon-owned state. Registrations are
deduplicated and capped at 4,096 per session.

Successful `session_status` and `end_session` responses include
`observability_gap` with:

- registered, corroborated, and unobserved receipt counts;
- captured, correlated, and uncorrelated process lifecycle effect counts;
- `observed_effect_gap_ratio = uncorrelated_effects / captured_effects` for a
  non-empty captured sample;
- `effect_scope = process_lifecycle` and explicit `process_exec` /
  `process_exit` event classes; and
- `receipt_source_assurance = authenticated_session_owner`.

An empty captured sample is `not_measured` and omits the ratio. A non-empty,
loss-free sample is `measured`. Any lifecycle capture loss or producer-counter
evidence gap makes it `degraded`; the ratio still describes only the events
that reached the daemon and must not be promoted to a complete-session rate.
The metric does not claim daemon-side receipt signature verification, universal
host capture, or file/network/provider-hidden effect coverage. The run bridge
folds it into the signed attestation at
`kernel_enforcement.observability_gap`.

## Operator response

1. Confirm that the daemon binary and eBPF objects came from the same reviewed
   build or release digest.
2. Inspect startup logs for load, verifier, attach, or pinned-state reuse
   failures, and for lifecycle cgroup-filter reconciliation warnings, before
   the first malformed-record warning.
3. Treat every producer-drop or malformed-record warning, or any
   `lifecycle_capture` summary whose
   `coverage_status` is `degraded` as an evidence gap; do not use affected
   sessions to claim complete kernel observation for that interval.
4. Interpret `observability_gap.observed_effect_gap_ratio` only within its
   `process_lifecycle` event classes. Investigate uncorrelated effects, but do
   not treat a zero observed-sample ratio as proof of universal coverage.
5. Restart with a matched daemon and eBPF artifact set. If warnings continue,
   preserve the daemon logs, kernel version, artifact digests, and the first
   affected receipt for diagnosis.
6. Use `--no-ringbuf` only to isolate the socket control plane. Record that
   capture and enforcement were intentionally unavailable during the test.

The summary is evidence-integrity metadata for a session's active time window,
not a claim that the malformed record belonged to that session or a promise
that any missing kernel event can be reconstructed.
