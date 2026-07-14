# Linux Agent-Recognition Overhead And Loss Harness

Ardur ships a real-Linux paired benchmark for the opt-in
`ardur-kernelcaptured --agent-recognition` path. It measures the same
deterministic native exec corpus with recognition disabled and enabled, records
raw AB/BA observations, and fails closed when lifecycle or fingerprint work is
not completely accounted.

This is host-specific engineering evidence. It is not a universal overhead
number, an accuracy study, identity attestation, or proof that the observed
process is governed.

## Measurement contract

Each run uses one copied native workload whose basename is `codex`, one
generated owner-only fingerprint registry, and the production daemon's fixed
non-blocking fingerprint queue and worker count. The harness performs one or
more discarded warm-up pairs followed by at least 20 measured pairs. Pair order
alternates deterministically between baseline-first and enabled-first.

Every pair records:

- the baseline and enabled workload elapsed time, including the signed
  overhead numerator, baseline denominator, and percentage;
- daemon CPU runtime summed across `/proc/<pid>/task/*/schedstat` and daemon
  peak RSS from procfs;
- workload completions and authenticated daemon health responsiveness;
- lifecycle delivered, producer-ringbuf-dropped, malformed, and unexplained
  counts;
- recognition candidate, recognized, rejected, and unexplained counts; and
- fingerprint success, mismatch, saturation, resolution-denied,
  process-exited, unsupported, size-exceeded, deadline-exceeded, in-flight,
  and unexplained counts.

The report recomputes p50, p95, minimum, maximum, and mean from the raw pairs.
It carries the exact source SHA, kernel/architecture/Go metadata, workload and
registry digests, sample counts, profile settings, gate result, and a SHA-256
artifact digest. Validation recomputes every ledger, summary, overhead value,
and artifact digest before the file is published.

## Bounded profiles

| Profile set | Low | Sustained | Storm | Intended use |
|---|---:|---:|---:|---|
| `ci` | 4 events, concurrency 1 | 20 events, concurrency 4 | 80 events, concurrency 16 | Required pull-request and `dev` evidence |
| `release` | 20 events, concurrency 1 | 200 events, concurrency 16 | 800 events, concurrency 64 | Manual, longer release evidence |

Each process remains alive for 300 ms so the production asynchronous resolver
can open and hash the executable before exit. The required CI profile uses one
warm-up and 20 measured pairs. The release profile is only available through
explicit workflow dispatch or `--profile release`; it is not scheduled.

## Budget lifecycle

The first exact-head hosted-runner run is baseline evidence and reports
`gate_status: not_evaluated`. Reviewers inspect its raw pairs, environment,
loss ledgers, and artifact digest before committing:

- the reviewed baseline report as an explicit public evidence fixture; and
- `go/pkg/kernelcapture/testdata/agent-recognition-benchmark-budget-v0.1.json`.

The budget records the evidence artifact digest and per-profile evidence p50,
p95 daemon CPU, peak RSS, and explicit tolerances. Once the file exists, the CI
workflow automatically loads it for the `ci` profile. The command exits 1 when
a budget is exceeded and exits 2 for invalid input, unavailable measurement,
schema drift, digest mismatch, or report-publication failure.

Budget evaluation always fails on a missing profile, too few samples, producer
drops, malformed records, unexplained capture, rejection, fingerprint queue
saturation, unavailable fingerprint work, in-flight work, or unexplained
fingerprint outcomes. Tolerances cover runner variance; they never convert
loss into a pass.

## Local real-Linux run

Build all three exact artifacts from the same checkout:

```bash
cd go
go build -trimpath -o /tmp/ardur-kernelcaptured ./cmd/ardur-kernelcaptured
go build -trimpath -o /tmp/ardur-agent-recognition-benchmark ./cmd/ardur-agent-recognition-benchmark
go build -trimpath -o /tmp/ardur-agent-recognition-workload ./cmd/ardur-agent-recognition-workload
```

Run only on an isolated disposable Linux host with BTF, bpffs, tracefs, root,
and no production Ardur daemon. The daemon uses a host-global bpffs namespace,
so a shared production host would make the evidence invalid and create a pin
collision risk.

```bash
sudo /tmp/ardur-agent-recognition-benchmark \
  --daemon-bin /tmp/ardur-kernelcaptured \
  --workload-bin /tmp/ardur-agent-recognition-workload \
  --source-sha "$(git rev-parse HEAD)" \
  --output-dir /tmp/ardur-agent-recognition-report \
  --profile ci \
  --warmup-pairs 1 \
  --measured-pairs 20
```

The output directory is `0700`; the JSON report is written atomically as
`0600`. The report contains no full host path, argv, environment, process
identifier, computed host-executable digest, or payload. It does include the
digest of the copied deterministic workload and the canonical registry digest.

## CI, privilege, and cost boundary

The dedicated workflow uses a fresh `ubuntu-24.04` GitHub-hosted VM, read-only
repository permission, commit-pinned actions, and no secrets. It mounts bpffs
or tracefs only when absent, runs the exact PR-head artifacts with `sudo`, then
uploads the owner-readable JSON report for 14 days. GitHub documents standard
hosted runners as fresh VMs and Linux runners as providing passwordless sudo:
[GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

The required profile consumes several CI minutes and performs 4,160 measured
workload execs plus warm-up across both arms. The longer profile increases CPU
and runner time substantially and is manual. Public-repository hosted-runner
minutes are currently not billed, but self-hosted/private execution still has
real compute, queueing, energy, and possible per-minute cost. Do not schedule
the release profile without a longitudinal experiment design.

## Primary-source basis

- Linux documents that a BPF ring-buffer reservation fails without blocking
  when no space remains. A separate monotonic producer-drop counter is therefore
  required to distinguish shedding from delivery:
  [BPF ring buffer](https://docs.kernel.org/bpf/ringbuf.html).
- Linux documents the first schedstat field as CPU runtime in nanoseconds. The
  harness sums it over the daemon's thread group because Go work is not confined
  to the process leader:
  [Scheduler statistics](https://docs.kernel.org/scheduler/sched-stats.html#proc-pid-schedstat).

## Targeted verification

```bash
cd go
go test -race -count=1 \
  ./pkg/kernelcapture \
  ./cmd/ardur-kernelcaptured \
  ./cmd/ardur-agent-recognition-benchmark \
  ./cmd/ardur-agent-recognition-workload
```
