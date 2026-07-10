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
