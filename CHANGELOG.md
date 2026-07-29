# Changelog

All notable changes to Ardur will be documented in this file.

## [Unreleased]

### Security
- Detect PKCS#8 private keys in the root-level protect artifact scanner so
  leaked private-key material is flagged alongside existing PEM detection
- Cover hook-lifecycle runtime artifacts in `.gitignore` (receipt chains,
  governance log, state directory, daemon socket, seccomp markers)
- Harden daemon filesystem paths with `O_NOFOLLOW`, restrictive umask, and
  tighter socket directories so symlink-based attacks and world-readable
  artifacts are blocked before the daemon accepts connections
- Platform-abstract the daemon umask setter for Windows portability so the
  security-hardened path builds across OS targets
- Use validated (trimmed) socket and seccomp-socket paths consistently in
  `ardur-kernelcaptured` and `ardur-exec-shim` and guard non-positive
  `--prune-interval` / negative `--guard-ready-timeout` before daemon
  startup so raw flag pointers cannot bypass validation at bind/log/mkdir
  sites
- Reject whitespace-only `--api-token` on `proxy start` before the auth
  header is constructed, mirroring the existing `start --api-token` and
  `kill-switch --api-token` whitespace guards
- Bump `google.golang.org/grpc` v1.82.0 → v1.82.1 for GO-2026-6061 (xDS
  RBAC and HTTP/2 transport server vulnerabilities)
- Reject dangling-parent-symlink path confusion on `run`, `setup`, and
  `protect claude-code --home` so a symlinked parent cannot silently
  materialize Ed25519 keys, mission JWTs, state, and the governance log
  at an unintended resolved target

### Added

### Changed
- Exclude `worktrees/` from Hugo source-mirror sync so generated documentation
  cannot accidentally absorb worktree-local build state
- Add a Python minimum-version check to `conductor-bootstrap.sh`,
  `check-local.sh`, and `setup-dev.sh` so fresh macOS users with system
  Python 3.9 get a clear error message before confusing tracebacks
- Make the Claude Code latency benchmark CI-environment-aware so shared
  GitHub Actions runners do not report false failures for thresholds that
  assume Apple Silicon local performance

### Fixed
- Remove unused imports and dead monkey-patch scaffolding flagged by
  CodeQL (`py/unused-import`, `py/unused-local-variable`) in
  `test_protect_scope_parent_symlink.py` and `test_proxy_api_token_ws.py`
  so the static-analysis surface stays clean
- Reject empty or whitespace-only `type=Path` arguments in sibling CLI
  entry-point modules (`receiver_attestation_fixture`,
  `provider_adapter_fixture`, `drp_conformance`, `policy_conformance`)
  so they fail closed before file IO instead of silently resolving to the
  working directory
- Reject empty or whitespace-only `-out` in `benchcheck` and the path
  argument in `enforce-verify` before file operations
- Reject whitespace-only `--signing-key` in the operator reconciler so
  `loadSigningKey` is not called with a blank path
- Resolve cross-package `conftest` imports so `pytest` collection works from
  the repository root, not only from `python/`
- Eliminate `InsecureKeyLengthWarning` from the forged-JWT test fixture by
  using a 53-byte wrong secret (still fails verification, no warning)
- Preserve MIC conformance claims across delegation: `derive_child_passport`
  now inherits and validates the closed MIC policy bundle
  (`conformance_profile`, `receipt_policy`, `tool_manifest_digest`) on
  supported child derivation, enforcing exact parent-aware verification.
  Incomplete or partial MIC bundles now raise `PermissionError` during
  delegation, matching the fail-closed rule in
  `docs/specs/ardur-drp-mapping-v0.1.md` §3.3.
- Resolve CodeQL `py/unused-local-variable` in `proxy.py` by hoisting
  `tracker`/`operator_id` initialization before the `if`/`else` block and
  removing the redundant `else` branch.
- Restore full local lint hygiene: resolve all pre-existing Ruff and
  ShellCheck findings and add a regression guard for the selected-Python
  graph compile path.
- Harden the MIC showcase test suite: issue signed MIC-State and
  MIC-Evidence passports, assert exact fail-closed outcomes, and reflect
  annotated failures in the test footer.
- Preserve each original assistant turn around its ordered tool calls in
  multi-tool transcript tests, emit current Ollama tool-result fields, and
  fail honestly on rejected follow-up turns.
- Enforce fail-closed evaluation semantics in tests: only explicit
  `PERMIT` produces success; `DENY` is denied; missing or unusable
  evidence is unknown.
- Convert showcase class-scoped fixtures to `@classmethod` form so
  class-wide setup is preserved after pytest 10 removes instance-method
  fixture support.
- Normalize Ollama tool-call transcript formats in the test harness.
- Preserve `errno` across cleanup in the compiled Claude Code native client
  binary so receive timeouts, EINTR, connection resets, and I/O failures
  are distinguishable via sanitized stderr diagnostics (exit codes 11 and
  21 now emit `stage`/`errno`/symbolic name/`strerror`; EINTR is retried
  with a bounded deadline; `setsockopt` return is checked).
- Reject empty or whitespace-only `type=Path` arguments in
  `claude-code-daemon` and `claude-code-hook` so they fail closed before
  file IO.
- Guard the `python/pyproject.toml` grep in `conductor-bootstrap.sh` and
  `check-local.sh` with a `-f` existence check so fixture-repo contract
  tests that run in temp directories without `pyproject.toml` do not fail
  under `set -e`.
- Validate `--webhook-port` range (1–65535) before server start.
- Reject empty or whitespace-only path arguments in `proxy` startup
  (`--keys-dir`, `--state-dir`, `--log-path`) before key/state/log
  materialization.
- Reject non-positive `--max-requests` before daemon startup.
- Reject out-of-range `--port` with a structured error before bind.
- Validate empty or whitespace-only `nargs` list elements on
  `ardur issue --allowed-tools`, `--forbidden-tools`, and
  `--resource-scope` so blank entries cannot silently widen scope.
- Reject whitespace-only `flag.String` values in remaining Go daemon and
  command binaries (`ardur-agent-recognition-benchmark`,
  `ardur-agent-recognition-eval`, `ardur-exec-shim`,
  `auditbench-oracle`, `auditbench-label`, `ardur-seccomp-smoke`).
- Reject whitespace-only `--budget` in
  `ardur-agent-recognition-benchmark`.
- Reject whitespace-only `--signing-key` in the operator reconciler.
- Trust the Personal Hub's pinned self-signed TLS certificate in
  `status`/`doctor` clients so HTTPS loopback works without manual
  `--hub-url` overrides or certificate warnings.
- Resolve `hub_url` from the Personal Hub config (mirroring `hub_token`
  resolution) so `status` and `doctor` connect over HTTPS when the Hub
  serves TLS, without requiring an explicit `--hub-url` flag.
- Display the resolved `hub_url` in `doctor` hub check detail instead of
  the argparse default, so diagnostic output reflects the actual endpoint
  being queried.
- Reject whitespace-only `--api-token` on `kill-switch` before the network
  call, mirroring the existing `start --api-token` and
  `status`/`doctor`/`desktop-observe --hub-token` whitespace guards.
- Reject empty or whitespace-only `--home` on `ardur run` before the
  working directory is polluted with signing keys, governance log, and
  state files.
- Reject `--receipt-log` pointing to a directory or nonexistent file on
  `ardur anchor` before transparency-log processing.
- Document the `receipt_log_not_file` error code in the `ardur anchor`
  CLI reference.
- Align `ardur run` receipts path with the canonical `receipts.jsonl`
  filename so the governance summary no longer prints a `receipts_log.jsonl`
  path that never exists.
- Emit a structured error when a governed command cannot launch on
  `ardur run` instead of a bare traceback.
- Use `contextlib.suppress` for the `doctor` hub-URL display fallback so
  a transient display-resolution failure does not trigger a CodeQL
  `py/empty-except` alert.
- Reject `--home` and `--chain-dir` dangling-parent-symlink on
  `gemini-cli-fixture` and `codex-app-server-fixture` before fixture
  artifacts are written at a symlink-resolved target.
- Reject `--keys-dir` dangling-parent-symlink on `protect claude-code`
  before Ed25519 key generation.
- Reject `--scope` dangling-parent-symlink on `protect claude-code`
  before JWT issuance.
- Document `--home` and `--chain-dir` dangling-parent-symlink conditions
  in the fixture CLI reference.

## [0.2.0] — 2026-07-22

### Security
- Fail closed on every Claude Code `PreToolUse` processing error instead of
  allowing an action to continue after governance fails
- Update `golang.org/x/text` to the reviewed CVE-fixed release
- Constrain the published Python `dev` extra to `pyasn1>=0.6.4,<0.7`, excluding
  versions affected by CVE-2026-59884, CVE-2026-59885, and CVE-2026-59886;
  primary-source links, reproducible checks, and the live-metadata limitation
  are recorded in `docs/release-evidence-v0.2.0.md`
- Reject empty or whitespace-only path and flag values across Python verifier,
  evidence, telemetry, hook, fixture, Hub, profile, and Go command boundaries
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
- Make root `AGENTS.md` the canonical public agent contract and add a staleness
  gate for derived guidance
- Complete the documented CLI surface across operator and evidence workflows
- Route source-install quickstarts through the supported `setup-dev.sh` path
  instead of fragile ad-hoc virtual-environment commands
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
- Keep the fresh-user evidence harness out of gitignored virtual-environment
  symlink trees and resolve the tested Ardur version from the harness environment
- Tolerate non-object Claude Code tool input and response payloads without
  crashing the hook
- Require explicit fixture project directories and remove unused locals and
  imports reported by the release CodeQL quality scan
- Keep the reference-paired agent-recognition benchmark active during release
  promotion by falling back to the reviewed v0.3 same-VM reference used to
  calibrate v0.4 evidence when the `main` target predates the daemon
- Replace the yanked Python `build` 1.5.1 release-tool pin with the non-yanked
  1.5.0 predecessor; `docs/release-evidence-v0.2.0.md` records the auditable
  PyPI metadata check and its revalidation boundary
- Keep ignored Python package `build/` and `dist/` output out of generated Hugo
  source pages so release builds cannot make source-sync checks order-dependent
- Replace the nonexistent `make reproduce` testing instruction with runnable
  repository, protocol, and maintained-corpus release gates
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
