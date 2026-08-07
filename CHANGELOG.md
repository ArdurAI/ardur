# Changelog

All notable changes to Ardur will be documented in this file.

## [Unreleased]

### Added
- Show duration budget usage in the `ardur run` human-readable summary.
  When lifecycle evidence includes `duration_budget_s`, the process line
  now appends `budget Xs/Ys (Z%)` or `budget exceeded` so CI/automation
  consumers can detect runaway processes without parsing JSON output.
- Show descendant process count and max depth in the `ardur run`
  human-readable summary. When host-observer lifecycle evidence includes
  captured descendants (direct children, grandchildren, etc.), the summary
  now includes a `descendants   N captured (max depth D)` line so users
  get immediate visibility without parsing JSON output.

### Security
- Redact local paths in `_build_process_lifecycle_evidence` at the source
  via a new `_redact_process_lifecycle` helper that layers
  `_redact_local_path_embedded` with `redact_local_path_text`, before the
  evidence is signed into the ES256 attestation token. Previously
  the `command`, `run_command`, `cwd`, and `children[*].command` fields
  carried unredacted absolute paths that were cryptographically signed
  into the attestation JWT, permanently embedding the user's home dir,
  project layout, temp paths, and child argv in shareable evidence.
- Add `violations` count to `_build_summary` and `_child_lifecycle_summary`
  so VIOLATION decisions (credential compromise, chain tampering) are
  distinguishable from routine DENY verdicts in session summaries and
  child-lifecycle rollups. Previously VIOLATION was silently folded into
  the aggregate `denials` count with no separate audit trail.
- Ensure `_child_lifecycle_summary` default dict includes
  `unknowns`, `insufficient_evidence`, and `violations` keys on all
  error paths (missing child_jti, child session unavailable) so
  downstream consumers do not encounter `KeyError`.
- Sanitize child-lifecycle exception messages to use `type(exc).__name__`
  instead of raw `str(exc)`, preventing internal state from being signed
  into attestation evidence on error paths.
- Unify `_redact_local_path_string` with `redact_local_path_text` so
  `--redact-paths` also catches `file://` URIs, percent-encoded
  separators, and arbitrary local absolute paths under unknown roots
  (e.g. `/opt/…`). The previous hand-rolled regex pass only covered a
  fixed list of known roots and leaked the broader path class.
- Propagate `unknowns` and `insufficient_evidence` verdict counts from
  child session summaries in `_child_lifecycle_summary`, closing a
  verdict-taxonomy sibling-sweep gap after the `UNKNOWN` Decision enum
  was added.
- Bump `cryptography` upper bound from `<50` to `<51` to pull in
  `50.0.0`, which fixes CVE-2026-69247 (PKCS#7 EnvelopedData
  decryption Bleichenbacher oracle via distinguishable errors). The
  previous `<50` cap pinned Ardur to the vulnerable `49.0.0` release.
- Close catch-all `str(exc)` leak paths in the Personal Hub HTTP handler,
  the VIBAP proxy GET handler (which had no exception guard at all), the
  native messaging host, and `hub_request()` so unhandled exceptions
  return generic safe messages (`internal server error`, `hub_error`)
  instead of leaking raw Python internals, filesystem paths, or crypto
  library details to API consumers. Full exceptions are now logged for
  operator triage via `logger.exception()`.
- Route CLI error paths (`_verify_failure_response`,
  `cmd_evidence_correlate`, `_cmd_verify_receiver_attestation`,
  `cmd_telemetry_export`) through `_safe_exception_message()` so generic
  built-in exceptions (`OSError`, `TypeError`, `ValueError`) are
  sanitized to class name only while domain exceptions with safe
  messages are preserved.
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
- Sanitize SPIFFE library internals (e.g. segment-parse errors) and AAT
  decoder text from proxy HTTP error responses so `PermissionError`
  messages that reach 403 bodies use fixed codes
  (`peer_jwt_svid_verification_failed`, `parent_token_aat_validation_failed`,
  `aat_mission_resolution_failed`) instead of leaking library stack text
- Sanitize cryptography library internals (e.g. `Could not deserialize
  key data`, `asn1` errors) from proxy HTTP 400 error responses so
  `holder_public_key_pem` validation failures use the fixed code
  `holder_public_key_pem_invalid` instead of leaking PEM-decoder text
- Fix KeyError crash in offline verification (`_verdict_label`) and
  telemetry export severity map when a receipt chain contains an
  `unknown` verdict. The `unknown` verdict was added as a first-class
  outcome for honest observation-gap abstention, but the verdict label
  dict and OTel severity map were not updated, causing crashes that
  broke post-hoc verification and telemetry export. This was a
  denial-of-audit vector: an attacker who could trigger `unknown`
  verdicts could crash post-hoc verification paths.

### Added
- Add `UNKNOWN` as a first-class `Decision` enum value in the governance
  proxy, representing a genuine observation gap where the verifier
  observed the call but the evidence is structurally outside the capture
  boundary. This is the honest-abstention outcome — distinct from
  `INSUFFICIENT_EVIDENCE` (transient operational failure). Unknown
  decisions are fail-closed DENY with
  `metadata.x-ardur.verdict=unknown` and counted as denials in the
  session summary.
  fixture-module `_status_from_verdict` to map `unknown` verdicts to
  `"unknown"` status, and updates receipt v0.2 schema description from
  "Tri-state" to "Four-state verifier result."
- Capture zero-privilege host-observer process-lifecycle evidence for
  every `ardur run -- <cli>` launch. The launched root process's PID,
  command, started-at timestamp, wall-clock duration, exit code, and
  exit signal are now recorded in the governance result's
  `process_lifecycle` field and surfaced in both `--json` output and
  the human-readable summary. The `capture_tier` field honestly marks
  this as `"host-observer"` — root-process lifecycle only — so
  consumers never mistake it for full process-tree capture (which
  requires eBPF daemon correlation). This works with any CLI on
  macOS/Linux without any host plugin API dependency.
- When adapter wrapping transforms the argv before launch (Claude Code
  `--plugin-dir` injection, seccomp shim, launch-gate wrapping), the
  actual argv is now captured in the lifecycle evidence's `run_command`
  field alongside the original `command` field. This lets consumers
  distinguish "what the user asked to run" from "what the OS was told
  to execute." `run_command` is omitted when identical to `command`
  (the common `via=env` case). Both fields are redacted under
  `--redact-paths`.
- Capture the absolute working directory (`cwd`) the launched process
  was started in as part of the host-observer lifecycle evidence. This
  lets consumers reproduce the filesystem context of the run. The `cwd`
  field is redacted under `--redact-paths`.
- Host-observer process-lifecycle evidence now enumerates descendant
  processes recursively (direct children, grandchildren, etc.) instead
  of only direct children. Each descendant entry includes `depth` (0 =
  direct child) and `parent_pid` so consumers can reconstruct the full
  process-tree structure from the flat snapshot list. Depth is capped at
  16 and total count at 500 to prevent runaway recursion. The
  `capture_boundary` string honestly describes this as a point-in-time
  snapshot, not a real-time exec/fork event stream.
- Sign host-observer lifecycle evidence into the session-final attestation
  token. The `process_lifecycle` object (root_pid, command, run_command,
  cwd, duration_budget_s, started_at, wall_clock_s, exit_code, exit_signal,
  capture_tier) is now injected as a `process_lifecycle` claim in the
  ES256-signed attestation JWT, making the lifecycle evidence
  cryptographically verifiable in the attestation chain. The claim is
  omitted when no lifecycle evidence is available (backward-compatible).
- Add `SyntheticKernelReceiptVerdictUnknown` constant in the Go
  kernelcapture correlator and wire daemon-restart-gap and
  coverage-unknown events to emit verdict `"unknown"` instead of
  `"insufficient_evidence"`. This mirrors the Python receipt's
  first-class `"unknown"` verdict for honest observation-gap
  abstention, completing the cross-language consistency of the
  five-state Decision taxonomy (compliant, denied, blocked,
  insufficient_evidence, unknown) across both Python and Go receipt
  surfaces.
- Update v0.1 protocol specifications (verifier-contract,
  execution-receipt, conformance-profiles, EAT-profile,
  governance-telemetry, idm-extension, offline-verification-bundle,
  auditbench-evaluation-protocol) to include `unknown` in the verifier
  codomain alongside `compliant`, `violation`, and
  `insufficient_evidence`. Updates the DRP decision-projection mapping
  to include `unknown → DENY with metadata.x-ardur.verdict=unknown`.
  Historical "tri-state" references are preserved in the v0.2 extension
  note and precursor citation. This completes end-to-end alignment of
  the honest-abstention `unknown` verdict across the receipt schema,
  governance enforcement, security model, Go correlator, coverage map,
  and protocol specifications.
- Add `--output` flag to `ardur verify` so the JSON explorer report can be
  atomically written to an owner-only file instead of printing to stdout,
  matching the `--output` contract on `evidence correlate`, `posture scan`/
  `report`, `preflight tool-server`, and `telemetry export`. Works on all
  verify sub-paths (token, offline journal, anchor bundle, receiver
  attestation). Prints a confirmation JSON with `report_sha256` to stdout.
- Add `--json` flag to `ardur run` governance path that emits the result as
  machine-readable JSON to stderr (session id, permits/denials, attestation
  digest, receipt paths). stdout is reserved for the child process output so
  pipe chains like `ardur run --json -- pytest 2>governance.json` work cleanly.
  The JWT-like attestation token is omitted; use `attestation_digest` instead
- Add `--redact-paths` flag to `ardur run --json` that replaces local absolute
  paths (`home`, `passport_path`, `receipts_path`, `correlation.daemon_socket`,
  `correlation.cgroup_path`) with stable placeholders (`<tmp>`, `<home>`,
  `<var-folders>`, `<run-ardur>`, `<cgroup>`) so JSON output is safe to share
  in CI artifacts or bug reports without leaking the filesystem layout
- Add `--redact-paths` flag to `ardur status`, `ardur doctor`, and
  `ardur doctor-claude-code` so the hub status `home` field and any local
  paths in the JSON output are replaced with stable placeholders before
  sharing in CI artifacts or bug reports
- Add `--redact-paths` flag to `ardur protect claude-code --json` so the
  10+ path-bearing fields in the success response (`home`,
  `active_passport`, `plugin_dir`, `run_command`, `claims.resource_scope`,
  `claims.cwd`, etc.) are replaced with stable placeholders before
  sharing in CI artifacts or bug reports
- Add `--redact-paths` flag to `ardur setup` and `ardur uninstall` so
  local paths (`home`, `config`, `launch_agent`, `would_remove`,
  `removed`) are replaced with stable placeholders before sharing in
  CI artifacts or bug reports
- Accept `--json` as a no-op flag on always-JSON personal-path commands
  (`status`, `doctor`, `doctor-claude-code`, `setup`, `kill-switch`,
  `uninstall`) so users who expect `--json` (present on `run` and `verify`)
  do not get `unrecognized arguments: --json`. Output is identical with
  and without the flag.
- Accept `--json` as a no-op flag on always-JSON protocol-path commands
  (`issue`, `attest`, `anchor`) for the same CLI consistency reason.
- Accept `--json` as a no-op/override flag on the remaining JSON-emitting
  commands (`telemetry export`, `preflight tool-server`, `posture scan`,
  `posture report`) so the full CLI accepts `--json` uniformly. For
  `posture scan` and `posture report`, `--json` is equivalent to
  `--format json`.
- Emit machine-readable JSON latency reports with raw sample distributions,
  recomputable percentiles (median/p95/p99), functional outcome classification
  (stage + native exit/errno), separate functional-failure and threshold-
  violation fields, and runner metadata from an explicit allowlist only.
  Reports are written as atomic 0600 files and uploaded as CI artifacts with
  `if: always()` and bounded retention.
- Add `ardur latency-gate evaluate` CLI command that loads latency report
  JSON files from a directory, runs the deterministic multi-report gate
  evaluator (ADR-027), and emits a structured pass/fail/inconclusive verdict
  with per-report detail. Supports `--threshold-ms`, `--min-runs`,
  `--percentile`, and `--output-format json|text` for CI integration.
- Accept the `--json` flag on `ardur evidence correlate` and
  `ardur latency-gate evaluate` for consistency with all other
  JSON-emitting commands. These commands already emit JSON by default;
  the flag is a no-op accepted for DX consistency so users are not
  surprised by argparse rejections.
- Add help text to `personal-firewall demo --json` so the flag is
  documented in `--help` output like all other `--json` flags.
- Rename `latency-gate evaluate --output-format` to `--format` for
  consistency with every other `--format`-bearing command
  (`evidence correlate`, `telemetry export`, `posture scan/report`,
  `preflight tool-server`). `--output-format` is retained as a
  backward-compatible alias.
- Add `--max-retries 3` and `--retry-wait-time 5` to the lychee
  link-check CI workflow so transient network timeouts and rate-limit
  responses do not produce spurious exit-2 failures on otherwise
  clean link-check runs.
- Add retry logic to the ``test_http.py`` HTTP test helpers so
  ``TimeoutError`` from the local proxy thread under CI parallel-matrix
  load does not cause spurious test failures. Timeout increased from
  5s to 10s with up to 3 retries on transient connection errors.
- Add `--output` flag to `posture scan` and `posture report` for
  consistency with `evidence correlate`, `telemetry export`, and
  `preflight tool-server`, which all support atomic file output via
  the shared `write_report()` helper (rejects symlinks, directories,
  and nonexistent parent directories).
- Extend `preflight tool-server --fail-on` exit-2 semantics to cover
  config parse errors (malformed JSON, empty server collections), so
  CI pipelines using `--fail-on` catch broken configs at the same
  threshold as security findings. When `--fail-on` is `none` (default),
  config errors preserve the exit-1 behavior.
- Add `unknown` as a first-class receipt verdict for honest abstention when
  evidence is structurally absent (observation gaps, unobserved side effects).
  Distinct from `insufficient_evidence` (verifier tried but couldn't evaluate)
  — `unknown` means the verifier observed the call but cannot determine
  compliance because evidence is structurally outside the capture boundary.

### Docs
- Update `STATUS.md` and `docs/coverage-map.md` to document the direct-child
  process enumeration added to the host-observer lifecycle tier. The capture
  boundary is now accurately described as "root-process + direct children only
  — not the full recursive process tree."
- Add Decision taxonomy section to `docs/security-model.md` documenting the
  five-state governance decision model (`PERMIT`, `DENY`, `VIOLATION`,
  `INSUFFICIENT_EVIDENCE`, `UNKNOWN`) and the distinction between
  `INSUFFICIENT_EVIDENCE` (transient operational failure, retryable) and
  `UNKNOWN` (structural observation gap, not retryable). Both fail-closed.
- Add five-state Decision taxonomy summary to `STATUS.md` so the top-level
  status document reflects the `unknown` verdict alongside
  `insufficient_evidence` as first-class receipt outcomes.
- Update `README.md` AuditBench scoring description from "tri-state" to
  "four-state" (`compliant`, `violation`, `insufficient_evidence`,
  `unknown`) to match the updated v0.1 protocol spec codomain.

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
- Fix `_build_summary` in the governance proxy to count `Decision.UNKNOWN`
  as a denial. When the `UNKNOWN` verdict was added to the five-state
  Decision taxonomy, the summary's denials tuple was not updated — an
  `UNKNOWN` event would silently pass uncounted, understating the aggregate
  denial count and incorrectly reporting `scope_compliance: full`. The
  summary now also breaks out `unknowns` and `insufficient_evidence` as
  separate count fields for audit clarity.
- Standardise JSON-mode exit codes: all `--json` error paths now exit 1
  (argparse errors, `ardur run` legacy hub errors, handler validation
  errors). Previously argparse errors exited 0 and `run` legacy hub errors
  exited 2/126/127 depending on the failure class. Non-JSON exit codes are
  unchanged. A JSON consumer can now reliably check `$?` for success/failure.
- Fix argparse missing-required-argument errors so they honour the `--json`
  contract. When `--json` is set, `attest`, `anchor`, `issue`,
  `evidence correlate`, `telemetry export`, `preflight tool-server`,
  `posture scan`, and the top-level command selector now emit a structured
  JSON error (`{"ok": false, "error": "argument_error", ...}`) to stderr
  instead of the raw argparse usage block with exit code 2.
  Non-JSON behaviour is byte-identical (usage text + exit 2).
- Fix `ardur run --json` legacy hub-streaming error paths: when `--json` is
  set without `--mission` (the legacy hub path), structured JSON errors
  are now emitted to **stderr** instead of human-readable text, keeping the
  stdout=child / stderr=governance JSON contract consistent across both
  paths (missing command, empty `--home`, session-start failure,
  policy-check failure, and policy-blocked)
- Fix `ardur run --json` pre-execution error output streams: budget
  validation errors (`--max-tool-calls`/`--max-duration-s`) now emit
  structured JSON to **stderr** (not stdout) and command-not-found /
  command-not-executable errors emit structured JSON when `--json` is set,
  keeping stdout reserved for child process output as documented
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
- Emit a structured `start_port_in_use` / `hub_port_in_use` JSON error when
  `ardur start` or `ardur hub` cannot bind the configured port instead of
  leaking a raw `OSError: [Errno 48] Address already in use` traceback.
- Emit a structured JSON error with `error_code` / `message` / `detail`
  when `ardur kill-switch` cannot reach the proxy instead of leaking raw
  urllib internals (`<urlopen error [Errno 61] Connection refused>`).
- Classify Rekor transparency-log transport errors into structured
  `error_code` / `message` / `detail` triples instead of leaking raw
  urllib exception strings from `ardur anchor`.
- Sanitize `str(exc)` interpolation in conformance, daemon, run-bridge,
  transparency, and CLI output paths so raw exception messages
  (including filesystem paths) cannot leak into JSON error responses.
- Sanitize `str(exc)` in `receiver_attestation` envelope and MCP document
  loaders (`load_receiver_envelope`, `load_json_document`) so
  `FileNotFoundError` paths and parser internals are replaced with the
  exception class name in structured error output.
- Warn when `--redact-paths` is passed to `ardur run` without `--json`
  instead of silently ignoring it, so users do not believe local paths
  were redacted from the human-readable summary (they are not — path
  redaction applies only to the `--json` governance output).
- Catch `OSError` (e.g. read-only filesystem, permission denied) during
  key-directory creation in `ardur issue --keys-dir` so it returns a
  structured JSON error (`keys_dir_unreachable`) instead of leaking a
  raw Python traceback with filesystem paths.

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
