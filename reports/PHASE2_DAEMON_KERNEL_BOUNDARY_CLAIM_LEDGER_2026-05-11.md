# Phase 2 Daemon/Kernel Boundary Claim Ledger

Date: 2026-07-29
Branch baseline: `origin/dev` at `4550b3f90e7e9a90e21cf3c9a47346b7a0cafb8d`
Scope: public-site claim ledger source for the current Phase 2 development boundary.
Prior baseline: `a82d6ed6cd6cc0d3eed2cd22c44428cc8db938a6` (2026-07-01).

## Claim supported

The current `dev` branch supports a bounded development claim:

> Ardur has a gated local Linux eBPF process-lifecycle proof harness that can load and attach exec/exit tracepoints in a privileged Linux test environment, plus bounded Linux Slice 2 daemon installer/systemd/link-pinning development surfaces: `ardur-sensor` preflight/install/status/uninstall commands, fd-anchored root custody path/config creation, a systemd unit with `sd_notify`/watchdog/capability/path boundaries, and BPF tracepoint-link/ringbuf-map pinning for restart survival. The boundary also includes no-mutation daemon custody/preflight seams, peer-authorization and protocol/peer handshake contracts, Linux `SO_PEERCRED` retrieval plus daemon-observed process-start identity binding, accepted-connection protocol seam, dry-run accept-loop invariant seams, a bounded local Unix-domain socket server proof seam for authorized daemon protocol requests, a capped in-memory daemon session registry for register/status/end requests with safe active-session lookup and PID-reuse mismatch rejection when same UID/GID/PID presents different process-start ticks, no-mutation handoff-plan builder ergonomics, daemon-internal status snapshots, in-memory snapshot retention handler/sink proof, a narrow local `session_status` client proof that rejects response expansion, a no-write status evidence-log planning seam with schema/digest/rotation bounds, an in-memory JSONL evidence-log entry builder that revalidates digest/session/size before any future write path, an injected in-memory append/rotation planner that computes accept/rotate/reject decisions against a fake sink only, an injected filesystem append/rotation adapter that executes validated logical-path writes through caller-provided filesystem implementations with temp-dir test coverage, daemon-side `session_status` evidence-log wiring that appends successful status snapshots through that injected filesystem before retaining them without expanding the client protocol, a no-mutation daemon session handoff plan for hashed state/runtime paths plus cgroup allowlist preconditions, and a no-privilege/no-execution launch-wrapper session-proof seam with deterministic argv/cwd digest evidence.

This is an experimental development boundary, not release or production readiness.

Since the prior Jul 1 baseline, the following bounded development capabilities have
been added to the tree:

- **Agent recognition pipeline**: exec-basename matching beside the existing `comm`
  field, bounded native agent fingerprints with SHA-256 proc-exe hashing and
  pidfd-based resolution, a maintained accuracy corpus with Wilson-score evaluation
  and a CI gate, an overhead benchmark with paired-reference evidence and CPU
  gating, and a BPF-LSM observer that binds script launchers to kernel objects.
  These are bounded CI-gated proof and measurement surfaces, not production
  classification accuracy claims.

- **Seccomp user-notify enforcement tier (E4)**: a `SECCOMP_RET_USER_NOTIF`
  connect(2)-scoped filter with fd handoff via `SCM_RIGHTS`, TOCTOU-safe
  re-validation, and fail-closed-on-ambiguity semantics. The daemon selects BPF-LSM
  at startup and degrades to seccomp when BPF-LSM is unavailable.

- **Enforce events hash chain**: monotonic sequencing with a SHA-256 per-scope hash
  chain, orphan-event tracking, tamper-chain integration, kill-switch evidence, and
  a `VerifyEnforceReceiptChain` verifier for gap/tampering/reordering detection.

- **Observability gap measurement**: a lifecycle-loss accumulator with ringbuf drops,
  producer drops, malformed records, daemon queue drops, and gap-ratio computation.

- **Daemon security hardening**: `O_NOFOLLOW` on evidence-log writes, a restrictive
  `0o077` umask on Unix, validated trimmed socket paths, non-positive-duration
  guards, seccomp listener fd-reuse prevention, stale-allowlist revocation before
  gate, serialized policy-map handle lifecycle, fail-closed unverifiable-peer-PID
  rejection, daemon-work drain before teardown, and seccomp session-root handoff
  binding with authentication against the daemon-observed delegated root process.

- **Sensor lifecycle**: version stamping in config with downgrade refusal and an
  uninstall `--purge` option preserving state/evidence.

- **Tamper self-audit**: `RunTamperAudit` re-verifies BPF-LSM link attachments via
  `BPF_OBJ_GET_INFO_BY_FD`, checks kill-switch map integrity, and emits a JSONL
  tamper-evidence log.

## Evidence in the tree

- `go/pkg/kernelcapture/README.md` states the current MVP claim boundary and non-claims.
- `go/pkg/kernelcapture/linux_ebpf_smoke_linux.go` contains the gated Linux eBPF lifecycle smoke path.
- `go/pkg/kernelcapture/daemon_custody.go` and `go/pkg/kernelcapture/daemon_preflight.go` define dry-run custody and read-only preflight checks.
- `go/cmd/ardur-sensor/main.go` defines the Linux host-sensor management CLI surface: preflight, install, uninstall, and status. The install path checks kernel capabilities, calls the custody installer, installs the systemd unit, and can run `systemctl daemon-reload` plus `systemctl enable --now` unless `--no-enable` is supplied.
- `go/pkg/kernelcapture/daemon_installer_linux.go` implements fd-anchored root custody path/config creation with post-install preflight assertion and explicit boundaries for socket bind, bpffs map pinning, runtime directory creation, and systemd service lifecycle.
- `packaging/systemd/ardur-kernelcaptured.service` defines the bounded root systemd service unit with `Type=notify`, `WatchdogSec=30s`, runtime/state/log directory declarations, BPF-related capability bounds, and explicit daemon-owned write paths.
- `go/pkg/kernelcapture/linux_ebpf_daemon_linux.go` adds restart-survival BPF link and ringbuf-map pinning under daemon-owned bpffs paths, with fallback behavior when pinning is unavailable.
- `go/pkg/kernelcapture/daemon_protocol.go` defines the deterministic JSON-line protocol contract, rejects daemon-owned fields from clients, and decodes client-visible responses with unknown-field rejection so internal daemon status snapshot fields cannot be accepted as wire protocol expansion.
- `go/pkg/kernelcapture/daemon_peer_authorization.go` requires daemon-observed peer identity, including non-zero process-start ticks, and explicit UID/GID policy.
- `go/pkg/kernelcapture/daemon_peer_credentials_linux.go` implements the Linux `SO_PEERCRED` retrieval seam for already-open Unix connections and reads bounded `/proc/<pid>/stat` start-time ticks for the observed peer PID.
- `go/pkg/kernelcapture/daemon_socket_peer_contract.go` joins decoded protocol requests, daemon-observed peer credentials, process-start identity, and validated custody context for accepted Unix connections.
- `go/pkg/kernelcapture/daemon_socket_server.go` implements the bounded local Unix-domain socket proof seam: bind validated local socket path, cap request bytes/read timeout/concurrency, observe peer credentials, authorize request+peer, and dispatch only authorized requests to an injected handler.
- `go/pkg/kernelcapture/daemon_session_registry.go` implements the capped in-memory authorized handler seam for `register_session`, `session_status`, and `end_session`, including TTL expiry, duplicate-active-session rejection, active-session capacity exhaustion, inactive-session pruning, fail-closed unknown/ended/expired status behavior, daemon-observed process-start-bound ownership checks that reject PID-reuse mismatches for status/end, and safe active-session lookup plus no-mutation handoff-plan builder ergonomics for internal daemon status/handoff code.
- `go/pkg/kernelcapture/daemon_session_status_snapshot.go` implements the daemon-internal status snapshot wrapper for authorized `session_status` requests: it combines active registry metadata with the no-mutation handoff plan while keeping client-visible protocol responses narrow.
- `go/pkg/kernelcapture/daemon_session_status_snapshot_handler.go` and `go/pkg/kernelcapture/daemon_session_status_snapshot_sink.go` implement the in-memory daemon-side retention handler/sink for successful authorized `session_status` snapshots; the sink stores detached copies only and performs no persistence or mutation outside memory.
- `go/pkg/kernelcapture/daemon_session_status_client.go` implements the narrow local Unix-socket `session_status` client proof that sends a validated request and decodes only `DaemonProtocolResponse`, rejecting protocol response expansion.
- `go/pkg/kernelcapture/daemon_session_status_evidence_log_plan.go` implements the no-write status evidence-log planning seam for retained daemon-internal snapshots: schema version, entry kind, session-id-hashed daemon-owned evidence-log path, snapshot entry digest, retention/rotation bounds, and fail-closed validation before any file creation/write/rotation path exists.
- `go/pkg/kernelcapture/daemon_session_status_evidence_log_entry.go` implements the in-memory JSONL evidence-log entry builder: it validates the reviewed plan, revalidates snapshot integrity, recomputes the digest, fails closed on digest/session/size mismatch, and returns newline-terminated bytes without creating, appending, rotating, or persisting evidence-log files.
- `go/pkg/kernelcapture/daemon_session_status_evidence_log_append_plan.go` implements the injected in-memory append/rotation planner: it validates canonical JSONL entries, computes accept/rotate/reject decisions against a fake sink with overflow-guarded byte accounting, derives simulated rotation paths under the evidence-log directory, and retains accepted entries only as copied memory without opening, creating, appending, rotating, or persisting files.
- `go/pkg/kernelcapture/daemon_session_status_evidence_log_filesystem_append.go` implements the injected filesystem append/rotation adapter: it reuses the in-memory planner, executes minimal mkdir/append or mkdir/rename/append operations through a caller-provided filesystem surface, commits state only after filesystem success, and is covered by temp-dir path-mapping tests.
- `go/pkg/kernelcapture/daemon_session_status_evidence_log_handler.go` implements daemon-side `session_status` evidence-log wiring: successful authorized status snapshots are planned, encoded, appended through the injected filesystem adapter, then retained in memory while the client receives only `DaemonProtocolResponse`.
   - It also automatically removes in-memory evidence-log append state on successful `end_session` and on failed/expired `session_status`.
- `go/pkg/kernelcapture/daemon_session_handoff_plan.go` implements the no-mutation daemon session handoff plan seam for active registry records, including hashed daemon-owned state/runtime paths and a non-zero cgroup allowlist precondition sequence without filesystem writes, cgroup assignment, BPF map mutation, or live enforcement.
- `go/pkg/kernelcapture/daemon_accept_loop_plan.go` validates a dry-run accept-loop plan with custody validation, explicit UID/GID allowlists, bounded request bytes, read timeout, bounded concurrency, and non-executed preflight/bind/accept/peer-observation/decode/authorization/dispatch steps.
- `go/pkg/kernelcapture/launch_wrapper_session.go` defines the launch-wrapper no-execution contract seam and deterministic evidence envelope.
- `go/pkg/kernelcapture/launch_wrapper_session_test.go` verifies launch-wrapper digest integrity and boundary behavior.
- `reports/PHASE2_EBPF_MVP_VERIFICATION_2026-05-10.md` recorded the Linux eBPF MVP verification context and environment limits (that companion report was removed during the open-source-release cleanup and is no longer present in this tree).
- `go/pkg/kernelcapture/agent_fingerprint.go` and `go/pkg/kernelcapture/agent_fingerprint_linux.go` implement bounded native agent fingerprints with SHA-256 proc-exe hashing, pidfd-based resolution, and a worker pool with panic isolation.
- `go/pkg/kernelcapture/agent_recognition.go` and `go/pkg/kernelcapture/agent_recognition_evaluation.go` implement exec-basename and `comm` matching plus a maintained accuracy corpus with Wilson-score evaluation.
- `go/pkg/kernelcapture/agent_recognition_benchmark.go` and `go/pkg/kernelcapture/agent_recognition_benchmark_linux.go` implement the overhead benchmark with paired-reference evidence and CPU gating.
- `go/pkg/kernelcapture/launcher_identity_linux.go` implements the BPF-LSM observer that binds script launchers to kernel objects.
- `go/pkg/kernelcapture/process_exec_filter_linux.go` implements exec-basename recognition in the BPF filter.
- `go/pkg/kernelcapture/seccomp_notify_linux.go` and `go/pkg/kernelcapture/daemon_seccomp_linux.go` implement the `SECCOMP_RET_USER_NOTIF` enforcement tier (E4) with fd handoff and TOCTOU re-validation.
- `go/pkg/kernelcapture/enforce_receipt_chain.go` and `go/pkg/kernelcapture/enforce_event_summary.go` implement the monotonic SHA-256 hash chain for enforce events.
- `go/pkg/kernelcapture/observability_gap.go` and `go/pkg/kernelcapture/lifecycle_capture_summary.go` implement lifecycle-loss accounting and gap-ratio measurement.
- `go/pkg/kernelcapture/tamper_audit.go` implements the BPF-LSM link re-verification and kill-switch integrity self-audit.
- `go/pkg/kernelcapture/sensor_version.go` implements version stamping, downgrade refusal, and purge lifecycle.
- `go/pkg/kernelcapture/daemon_cgroup_verify_linux.go` implements fail-closed rejection of unverifiable peer PIDs.
- `go/cmd/ardur-kernelcaptured/main.go` wires seccomp listener lifecycle, stale-allowlist revocation, policy-map serialization, daemon-work drain, and seccomp session-root handoff binding.

## Not claimed

This evidence does **not** support claims of:

- production daemon readiness beyond the bounded Linux/systemd Slice 2 installer proof surface
- release package, cross-platform installer, unattended upgrade, rollback, or production service-management support
- production live enforcement or persistent session-state management
- production persistent status snapshot/evidence-log storage, fsync/crash recovery, or restart-safe evidence retention
- daemon-owned evidence-log service wiring, ownership changes, or production append/rotation lifecycle
- client-visible protocol expansion from daemon-internal status snapshots
- daemon-created/assigned per-session cgroups
- filesystem writes, cgroup writes, or BPF map mutation from the handoff plan seam
- file/network side-effect capture
- universal CLI capture across Codex, Gemini, Kimi, or future CLIs
- cross-platform kernel capture (macOS Endpoint Security or Windows ETW) — an `es_client_darwin.go` scaffold and `packaging/macos/systemextension/` bundle skeleton exist behind an Apple entitlement gate; `NewESClient` always fails without the entitlement and no events are captured
- unprivileged/no-install eBPF support
- production readiness

## Verification run for this 2026-07-29 claim-ledger docs refresh

This refresh is a docs/source-mirror alignment pass over the current
`origin/dev` claim boundary, not a new runtime/kernel validation run. It
incorporates evidence from 77 Go commits that landed between the prior Jul 1
baseline (`a82d6ed`) and the current `4550b3f`. A currency delta report at
`ardur-private/knowledge/runs/CONTINUOUS_DEV_PROBE_20260729T0030CDT_CLAIM_LEDGER_CURRENCY_4550B3F/`
catalogued 28 features and classified each as understated-code or understated-docs.
Local evidence for this docs refresh included:

```bash
./scripts/conductor-bootstrap.sh
git diff --check origin/dev
git diff --check
python3 site/scripts/sync_source_docs.py --check
python3 site/scripts/validate_claims.py
/opt/homebrew/bin/hugo --source site
python3 site/scripts/validate_rendered_docs_links.py site/public
```

A focused scan over the source ledger and generated mirror confirmed that the
Slice 2 installer/systemd/link-pinning markers, the new agent recognition / E4 /
hardening evidence references, and the non-claims above remain present, and that
stale local-Hugo-unavailable current-refresh wording is absent.
The broader Go tests, check-local quick gate, and gitleaks scan belong to prior
Phase 2/final-gates evidence and must be rerun by any future
final-gates/pre-release task that uses this ledger as landing evidence. This
docs/source-mirror refresh does not claim to have rerun them.
