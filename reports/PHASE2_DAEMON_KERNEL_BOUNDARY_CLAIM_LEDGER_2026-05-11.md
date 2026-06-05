# Phase 2 Daemon/Kernel Boundary Claim Ledger

Date: 2026-05-12
Branch baseline: `origin/dev` at `825baab0910a7a602d23d13b2021b2573be40a6e`
Scope: public-site claim ledger source for the current Phase 2 development boundary.

## Claim supported

The current `dev` branch supports a bounded development claim:

> Ardur has a gated local Linux eBPF process-lifecycle proof harness that can load and attach exec/exit tracepoints in a privileged Linux test environment, plus no-mutation daemon custody, preflight, peer-authorization, protocol/peer handshake, Linux `SO_PEERCRED` retrieval seam, accepted-connection protocol seam, dry-run accept-loop invariant seams, a bounded local Unix-domain socket server proof seam for authorized daemon protocol requests, a capped in-memory daemon session registry for register/status/end requests with safe active-session lookup, no-mutation handoff-plan builder ergonomics, daemon-internal status snapshots, in-memory snapshot retention handler/sink proof, a narrow local `session_status` client proof that rejects response expansion, a no-write status evidence-log planning seam with schema/digest/rotation bounds, an in-memory JSONL evidence-log entry builder that revalidates digest/session/size before any future write path, an injected in-memory append/rotation planner that computes accept/rotate/reject decisions against a fake sink only, a no-mutation daemon session handoff plan for hashed state/runtime paths plus cgroup allowlist preconditions, and a no-privilege/no-execution launch-wrapper session-proof seam with deterministic argv/cwd digest evidence.

This is an experimental development boundary, not release or production readiness.

## Evidence in the tree

- `go/pkg/kernelcapture/README.md` states the current MVP claim boundary and non-claims.
- `go/pkg/kernelcapture/linux_ebpf_smoke_linux.go` contains the gated Linux eBPF lifecycle smoke path.
- `go/pkg/kernelcapture/daemon_custody.go` and `go/pkg/kernelcapture/daemon_preflight.go` define dry-run custody and read-only preflight checks.
- `go/pkg/kernelcapture/daemon_protocol.go` defines the deterministic JSON-line protocol contract, rejects daemon-owned fields from clients, and decodes client-visible responses with unknown-field rejection so internal daemon status snapshot fields cannot be accepted as wire protocol expansion.
- `go/pkg/kernelcapture/daemon_peer_authorization.go` requires daemon-observed peer identity and explicit UID/GID policy.
- `go/pkg/kernelcapture/daemon_peer_credentials_linux.go` implements the Linux `SO_PEERCRED` retrieval seam for already-open Unix connections.
- `go/pkg/kernelcapture/daemon_socket_peer_contract.go` joins decoded protocol requests, daemon-observed peer credentials, and validated custody context for accepted Unix connections.
- `go/pkg/kernelcapture/daemon_socket_server.go` implements the bounded local Unix-domain socket proof seam: bind validated local socket path, cap request bytes/read timeout/concurrency, observe peer credentials, authorize request+peer, and dispatch only authorized requests to an injected handler.
- `go/pkg/kernelcapture/daemon_session_registry.go` implements the capped in-memory authorized handler seam for `register_session`, `session_status`, and `end_session`, including TTL expiry, duplicate-active-session rejection, active-session capacity exhaustion, inactive-session pruning, fail-closed unknown/ended/expired status behavior, and safe active-session lookup plus no-mutation handoff-plan builder ergonomics for internal daemon status/handoff code.
- `go/pkg/kernelcapture/daemon_session_status_snapshot.go` implements the daemon-internal status snapshot wrapper for authorized `session_status` requests: it combines active registry metadata with the no-mutation handoff plan while keeping client-visible protocol responses narrow.
- `go/pkg/kernelcapture/daemon_session_status_snapshot_handler.go` and `go/pkg/kernelcapture/daemon_session_status_snapshot_sink.go` implement the in-memory daemon-side retention handler/sink for successful authorized `session_status` snapshots; the sink stores detached copies only and performs no persistence or mutation outside memory.
- `go/pkg/kernelcapture/daemon_session_status_client.go` implements the narrow local Unix-socket `session_status` client proof that sends a validated request and decodes only `DaemonProtocolResponse`, rejecting protocol response expansion.
- `go/pkg/kernelcapture/daemon_session_status_evidence_log_plan.go` implements the no-write status evidence-log planning seam for retained daemon-internal snapshots: schema version, entry kind, session-id-hashed daemon-owned evidence-log path, snapshot entry digest, retention/rotation bounds, and fail-closed validation before any file creation/write/rotation path exists.
- `go/pkg/kernelcapture/daemon_session_status_evidence_log_entry.go` implements the in-memory JSONL evidence-log entry builder: it validates the reviewed plan, revalidates snapshot integrity, recomputes the digest, fails closed on digest/session/size mismatch, and returns newline-terminated bytes without creating, appending, rotating, or persisting evidence-log files.
- `go/pkg/kernelcapture/daemon_session_status_evidence_log_append_plan.go` implements the injected in-memory append/rotation planner: it validates canonical JSONL entries, computes accept/rotate/reject decisions against a fake sink with overflow-guarded byte accounting, derives simulated rotation paths under the evidence-log directory, and retains accepted entries only as copied memory without opening, creating, appending, rotating, or persisting files.
- `go/pkg/kernelcapture/daemon_session_handoff_plan.go` implements the no-mutation daemon session handoff plan seam for active registry records, including hashed daemon-owned state/runtime paths and a non-zero cgroup allowlist precondition sequence without filesystem writes, cgroup assignment, BPF map mutation, or live enforcement.
- `go/pkg/kernelcapture/daemon_accept_loop_plan.go` validates a dry-run accept-loop plan with custody validation, explicit UID/GID allowlists, bounded request bytes, read timeout, bounded concurrency, and non-executed preflight/bind/accept/peer-observation/decode/authorization/dispatch steps.
- `go/pkg/kernelcapture/launch_wrapper_session.go` defines the launch-wrapper no-execution contract seam and deterministic evidence envelope.
- `go/pkg/kernelcapture/launch_wrapper_session_test.go` verifies launch-wrapper digest integrity and boundary behavior.
- `reports/PHASE2_EBPF_MVP_VERIFICATION_2026-05-10.md` records the Linux eBPF MVP verification context and environment limits.

## Not claimed

This evidence does **not** support claims of:

- production daemon install/start/service-management readiness
- production live enforcement or persistent session-state management
- persistent status snapshot/evidence-log storage
- evidence-log file creation, real append/write path, rotation execution, or persistence
- client-visible protocol expansion from daemon-internal status snapshots
- daemon-created/assigned per-session cgroups
- filesystem writes, cgroup writes, or BPF map mutation from the handoff plan seam
- file/network side-effect capture
- universal CLI capture across Codex, Gemini, Kimi, or future CLIs
- cross-platform kernel capture (macOS Endpoint Security or Windows ETW)
- production readiness

## Verification run for this claim-ledger refresh

```bash
python3 site/scripts/validate_claims.py
python3 site/scripts/sync_source_docs.py --check
cd go && go test ./pkg/kernelcapture -count=1
./scripts/check-local.sh --quick --python <path-to-project-python>
git diff --check
gitleaks detect --source . --no-git --redact
```

Local Hugo rendering was unavailable in this environment (`hugo unavailable`), so rendered-site validation remains delegated to the `hugo-site` GitHub workflow for the pushed commit.
