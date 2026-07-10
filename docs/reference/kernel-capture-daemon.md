# Kernel Capture Daemon Operations

`ardur-kernelcaptured` is the Linux daemon that owns Ardur's local Unix-socket
control plane and kernel event consumers. This reference describes two
operator-visible conditions: control-plane-only mode and malformed process
lifecycle records.

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

## Malformed lifecycle records

The process lifecycle consumer decodes a fixed binary record emitted by the
matching eBPF program. A record that is too short for that ABI, or otherwise
cannot be decoded, produces a structured warning:

```text
malformed ringbuf record drop_count=<n>
```

The daemon drops that record and continues reading. `drop_count` is the number
of malformed records seen since the previous valid lifecycle event. If the next
valid event correlates to a session, its kernel receipt carries that count as
`capture_loss.ringbuf_dropped`; correlation then treats the evidence as
degraded or insufficient rather than claiming a complete event stream. If the
next valid event is not correlated, the current implementation resets the
counter without writing it to a session receipt, so daemon logs remain the
source of truth for the host-wide gap.

A malformed record points to a producer/consumer ABI mismatch, truncated
sample, or corruption in the lifecycle event path. It is not the expected
symptom of a BPF verifier rejection: verifier or attach failures occur during
startup and are reported by the loader before records can be emitted.

## Operator response

1. Confirm that the daemon binary and eBPF objects came from the same reviewed
   build or release digest.
2. Inspect startup logs for load, verifier, attach, or pinned-state reuse
   failures before the first malformed-record warning.
3. Treat every malformed-record warning or nonzero
   `capture_loss.ringbuf_dropped` value as an evidence gap; do not use affected
   sessions to claim complete kernel observation for that interval.
4. Restart with a matched daemon and eBPF artifact set. If warnings continue,
   preserve the daemon logs, kernel version, artifact digests, and the first
   affected receipt for diagnosis.
5. Use `--no-ringbuf` only to isolate the socket control plane. Record that
   capture and enforcement were intentionally unavailable during the test.

The receipt counter is evidence-integrity metadata attached to the next
correlated event, not a per-session packet-loss metric or a promise that every
missing kernel event can be reconstructed.
