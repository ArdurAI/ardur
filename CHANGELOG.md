# Changelog

All notable changes to Ardur will be documented in this file.

## [Unreleased]

### Security

### Added

### Changed

### Fixed

## [0.2.0] — 2026-07-19

### Security
- Scope Biscuit authority-baseline queries explicitly to the issuer-signed
  authority block and reject duplicate required or optional scalar facts
  instead of selecting a row by dependency-defined ordering; verified by
  `test_verify_preserves_special_authority_values_with_explicit_scope` and
  `test_verify_rejects_duplicate_authority_scalar`
- Reject holder-authored Biscuit blocks that widen tool, deny-list, resource,
  side-effect, budget, time, delegation, lineage-parent, or working-directory
  authority while preserving valid transitive attenuation
- Label exported actor/verifier identity as signed receipt claims while
  explicitly reporting that the detached exporter did not verify SPIFFE
  workload identity
- Add an opt-in verifier-clock maximum-age policy for offline evidence bundles,
  bound future-dated receipts by explicit skew, and report that age checks do
  not provide one-time replay protection
- Revoke path and network allowlist entries dropped by a BPF-LSM policy update
  before publishing its managed-generation gate, and abort the update if a
  stale entry cannot be removed
- Scan inline tool `inputSchema` and legacy `parameters` description annotations
  for instruction injection without treating instance defaults/examples as
  schemas or exposing unsafe schema-member names
- Bind each seccomp listener handoff to the registered root process's
  daemon-observed PID/start-time identity instead of accepting any peer on the
  daemon-wide UID/GID allowlist
- Serialize the Linux daemon's BPF policy-map handle lifetime so startup,
  health, in-flight mutations, tier withdrawal, and close cannot race
- Make the Linux cgroup-ownership verifier independently fail closed when a
  non-root handshake has no resolvable peer PID, preserving the upstream
  `SO_PEERCRED` identity gate as defense in depth
- Pin Biscuit holder verification to a server-owned issuer key, JWT-SVID trust
  bundle, and audience; require configured binding on every presentation; and
  reject caller-supplied roots plus non-`jwt-svid` bundle keys
- Require RFC 8785 canonical payload bytes for versioned Execution Receipt v0.2 JWTs while preserving explicit legacy v0.1 verification
- Keep the upstream RFC 8785 package as a declared dependency with an attributed Apache-2.0 fallback for dependency-less source-checkout runners
- Bind the final action-receipt JWT hash and kernel loss/kill-switch rollup in the signed behavioral attestation
- Redact kernel-capture daemon, MCP gateway, OPA backend, content safety scanner
- Strip hardcoded provider version pins from Gemini/Claude hooks
- Remove internal fixture/hashing helpers in favor of stdlib

### Added
- Kernel-bound script-launcher fingerprinting for opt-in Linux agent
  recognition: an optional non-enforcing BPF-LSM observer captures bounded
  original-object identity, mutable cmdline is confined to locator duty behind
  `openat2` plus `statx` equality, launcher digests bind to allowlisted final
  interpreter profiles, and unsupported shapes return explicit fail-low labels
- Real-Linux paired agent-recognition overhead and loss benchmarking with
  deterministic CI/release profiles, authenticated daemon health counters,
  raw AB/BA observations, privacy-bounded digested reports, and reviewed-budget
  enforcement
- Bounded native Linux executable fingerprint matching for opt-in agent
  recognition, with a daemon-owned versioned registry, pidfd plus
  `/proc/<pid>/exe` resolution, fixed asynchronous workers, explicit health
  counters, and privacy-safe observe-only results
- Add a versioned sanitized agent-recognition corpus, deterministic evaluator,
  95% Wilson intervals, stable error IDs, exact corpus/registry digests, and a
  maintained-corpus CI gate without making population-accuracy claims
- Opt-in, observe-only Linux AI-agent launch recognition with a versioned
  exact-name registry, separate in-kernel `comm` and successful-exec basename
  prefilters, operator class overrides, script-launcher smoke coverage, and
  explicit low-confidence identity boundaries
- Personal action-firewall profile and one-command provider-free ASK/DENY proof
- Readable Claude Code action summaries with signed action-budget evidence
- Execution Receipt v0.2 schema, embedded package copy, and canonical golden fixture
- Comprehensive E2E showcase test suite (28 tests, 7 layers)
- Live adversarial scoreboard and continuous harness
- Multi-backend policy evaluation (Native, Cedar, OPA)
- Deny-wins semantics with tri-state verifier
- Session end with attestation token issuance
- Concurrent session evaluation proof
- Phase 2 daemon custody scaffold
- Claude Code and Gemini CLI hook integrations
- Posture detector for agent behavioral profiling

### Changed
- Complete the bounded Linux agent-recognition evidence contract with separate
  name-only and synthetic content-fingerprint corpus strata, fail-closed
  match/mismatch transition gates, independently supplied launcher-interpreter
  inputs, and exclusive same-worker post-panic terminal-accounting proofs
- Claude Code hook rewired to stdlib hashlib/datetime
- Gemini CLI hook generalized beyond hardcoded version contracts
- Proxy kernel capture integration removed
- check-local.sh made resilient to missing knowledge-graph script
- Removed stale adversarial test-results directory from tracking

### Fixed
- Keep seccomp listener ownership in one goroutine and wake cancellation through
  a dedicated eventfd, preventing listener teardown from closing a reused
  control-connection descriptor
- Prevent torn `PolicyMaps` reads and use-after-close during BPF-LSM guard
  startup, degradation, and shutdown; reject late guards after seccomp fallback
- Reject attacker-signed JWT-SVIDs even when their SPIFFE ID matches the
  Biscuit holder claim; `svid_bound=true` now requires pinned-root verification
- Enforce cumulative direct-hook tool-call budgets from verified receipt chains
- Compose mission-declared policy backends in the direct Claude Code hook
- Canonicalize persisted forbid-rule hashes and key them by actual mission ID
- CI baseline repair after AskUserQuestion landing
- Claude AskUserQuestion hash handling
- Gemini hook contract aligned with CLI 0.44.1

## [0.1.0] — 2026-05-01

### Initial Public Release
- Tri-state verifier: Allow, Deny, InsufficientEvidence
- Signed receipt-chain evidence (JWT-based)
- Claim-bounded evidence bundles for observed AI-agent action boundaries
- Policy evaluation with mission declarations and delegation grants
- Execution receipts with verifiable audit trail
- Lineage budget enforcement
- Rate limiting and kill-switch
- SPIRE/SPIFFE-based workload identity
- Biscuit-based capability tokens
- Cedar policy language backend
- Native policy backend
- Prometheus metrics
- Helm chart skeleton
