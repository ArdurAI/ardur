# Phase 2 Daemon/Kernel Boundary Claim Ledger

Date: 2026-05-12
Branch baseline: `origin/dev` at `825baab0910a7a602d23d13b2021b2573be40a6e`
Scope: public-site claim ledger source for the current Phase 2 development boundary.

## Claim supported

The current `dev` branch supports a bounded development claim:

> Ardur has a local Linux eBPF process-lifecycle proof harness plus no-mutation daemon custody, preflight, peer-authorization, protocol/peer handshake, Linux `SO_PEERCRED` retrieval seam, accepted-connection protocol seam, dry-run accept-loop invariant seams, and a no-privilege/no-execution launch-wrapper session-proof seam with deterministic argv/cwd digest evidence.

This is an experimental development boundary, not release or production readiness.

## Evidence in the tree

- `go/pkg/kernelcapture/README.md` states the current MVP claim boundary and non-claims.
- `go/pkg/kernelcapture/linux_ebpf_smoke_linux.go` contains the gated Linux eBPF lifecycle smoke path.
- `go/pkg/kernelcapture/daemon_custody.go` and `go/pkg/kernelcapture/daemon_preflight.go` define dry-run custody and read-only preflight checks.
- `go/pkg/kernelcapture/daemon_protocol.go` defines the deterministic JSON-line protocol contract and rejects daemon-owned fields from clients.
- `go/pkg/kernelcapture/daemon_peer_authorization.go` requires daemon-observed peer identity and explicit UID/GID policy.
- `go/pkg/kernelcapture/daemon_peer_credentials_linux.go` implements the Linux `SO_PEERCRED` retrieval seam for already-open Unix connections.
- `go/pkg/kernelcapture/daemon_socket_peer_contract.go` joins decoded protocol requests, daemon-observed peer credentials, and validated custody context for accepted Unix connections.
- `go/pkg/kernelcapture/daemon_accept_loop_plan.go` validates a dry-run accept-loop plan with custody validation, explicit UID/GID allowlists, bounded request bytes, read timeout, bounded concurrency, and non-executed preflight/bind/accept/peer-observation/decode/authorization/dispatch steps.
- `go/pkg/kernelcapture/launch_wrapper_session.go` defines the launch-wrapper no-execution contract seam and deterministic evidence envelope.
- `go/pkg/kernelcapture/launch_wrapper_session_test.go` verifies launch-wrapper digest integrity and boundary behavior.
- `reports/PHASE2_EBPF_MVP_VERIFICATION_2026-05-10.md` records the Linux eBPF MVP verification context and environment limits.

## Not claimed

This evidence does **not** support claims of:

- production daemon install/start readiness
- socket listener/server/accept-loop/live enforcement
- live `SO_PEERCRED` enforcement
- eBPF load/attach in this launch-wrapper seam update
- daemon-owned per-session cgroups
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
