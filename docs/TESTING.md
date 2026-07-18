# Testing

The public tree includes curated Python and Go runtime code under `python/`
and `go/`. GitHub Actions now covers runtime tests, repository hygiene,
structured-file parsing, link checks, secret scanning, and CodeQL.

When changing external runtime-evidence correlation, run:

```bash
python -m pytest python/tests/test_runtime_evidence.py -q
```

This focused suite generates ephemeral P-256 receipts, exercises normalized,
Tetragon, and Falco JSONL adapters, and proves deterministic matching,
ambiguity, parser bounds, redaction, symlink handling, CLI behavior, public
fixture generation, and owner-only report output without network access or
private credentials.

When changing verified receipt telemetry or OTLP export, run:

```bash
PYTHONPATH=python python -m pytest python/tests/test_receipt_telemetry.py -q
```

This suite verifies signed PERMIT/DENY chain projection, parent linkage,
stable policy rule IDs, conservative no-content export, the canonical golden
event, deterministic OTLP IDs and nanosecond timestamps, partial rejection,
HTTPS/loopback endpoint policy, environment-header injection resistance,
owner-only output, symlink rejection, and CLI behavior. The generated trace and
log requests are also checked manually against the official
`opentelemetry-proto` protobuf JSON parser during release evidence review.

When changing governance performance paths or the Linux benchmark report, run:

```bash
python -m pytest python/tests/test_linux_benchmark.py -q
python scripts/run-linux-governance-benchmark.py \
  --mode smoke --source-ref "$(git rev-parse HEAD)" \
  --output-dir /tmp/ardur-linux-benchmark
```

The focused suite verifies the canonical/embedded schema pair, nearest-rank
percentiles, production policy/proxy/receipt paths, owner-only artifacts,
non-Linux claim gating, strict paired-command parsing, redaction, and stable
subprocess failures. The dedicated `linux-benchmark` workflow runs smoke on
relevant pull requests and offers manual Linux stress dispatch; it is not
scheduled. See the
[benchmark guide](benchmarks/linux-governance-overhead.md) for interpretation.

When changing opt-in Linux agent recognition, daemon health accounting, or the
recognition benchmark contract, run:

```bash
cd go
go test -race -count=1 \
  ./pkg/kernelcapture \
  ./cmd/ardur-kernelcaptured \
  ./cmd/ardur-agent-recognition-eval \
  ./cmd/ardur-agent-recognition-benchmark \
  ./cmd/ardur-agent-recognition-workload
```

The evaluator tests account for all 36 maintained samples while keeping the 28
name-only cases and eight synthetic content-fingerprint transitions separate.
They fail on name-only threshold drift, missing native/launcher content
coverage, any reviewed content-transition mismatch, or any confidence
promotion after a digest mismatch. Launcher cases bind an independently supplied
observed interpreter instead of inheriting it from the fixture registry.
Fingerprint-worker panic tests also require the same one-worker pool to complete
a second job after recovery and exclusive terminal accounting for an observer
panic.

The dedicated `agent-recognition-benchmark` workflow builds the exact candidate
daemon, controller, and native workload plus an exact target-branch reference
daemon. It runs one warm-up plus 20 three-arm groups on one fresh privileged
`ubuntu-24.04` runner, rotating through all six baseline/reference/candidate
orders. The report binds both source SHAs and both copied daemon digests,
records bounded CPU/scheduling identity, retains three diagnostic process-CPU
calibration samples, and uploads privacy-bounded raw JSON. CI fails on median
wall drift, same-VM candidate/reference daemon-CPU p95 drift, RSS drift, loss or
partial accounting in either enabled arm, rejection, unavailable fingerprint
work, schema drift, or digest mismatch. Automatic CI does not retry into a
pass. It requires the reviewed v0.3 budget before measurement; a missing or
invalid budget fails instead of silently reverting performance to
`not_evaluated`. Only an explicit manual `ci` dispatch may collect
budget-independent replacement evidence, and correctness still fails closed.
The committed budget is bound to three independent exact-head reports; the
larger release profile is manual and never substitutes for required CI. See the
[agent-recognition benchmark guide](benchmarks/agent-recognition-overhead.md).

When changing the AuditBench evaluation-protocol artifact pipeline, run:

```bash
make bench-protocol-test
```

This exercises strict and duplicate-name JSON parsing, raw-capture replay,
oracle/evidence separation, blind annotator roles, bundle provenance,
disagreement adjudication, protocol and corpus sealing, symlink/path/drift
rejection, held-out coverage, and tri-state score metrics. The test fixtures are
pipeline fixtures, not evidence from an externally governed annotation study.

Do not claim broader coverage than the workflows provide. If a feature needs a
manual smoke test, list the exact command and the observed result in the PR.

## What Runs Today

The repository uses dedicated GitHub Actions workflows for runtime, security,
format, site, link, package, OCI, kernel, and benchmark gates. Most run on push
to `dev`/`main` and on every pull request; `link-check` alone has a weekly cron,
while Linux benchmark stress is manual.

### `linux-benchmark` — shape smoke + manual stress

[`/.github/workflows/linux-benchmark.yml`](../.github/workflows/linux-benchmark.yml)

- Relevant pull requests run the focused benchmark tests and Linux smoke profile.
- Manual dispatch defaults to stress and uploads the JSON/Markdown report for seven days.
- No scheduled performance run exists; shared-runner variance and CI cost would make those numbers misleading.

### `agent-recognition-benchmark` — reference-paired real-Linux loss and budget gate

[`/.github/workflows/agent-recognition-benchmark.yml`](../.github/workflows/agent-recognition-benchmark.yml)

- Relevant pull requests and pushes to `dev` run the bounded CI profile with
  one warm-up and 20 deterministic three-arm groups.
- The required job uses authenticated daemon health to enforce exclusive
  lifecycle, classification, and fingerprint accounting; any unreported or
  unavailable work in either enabled arm fails the reviewed budget gate. The
  hard CPU signal is the candidate/exact-reference ratio on one VM; synthetic
  process-CPU calibration remains diagnostic without weakening those ledgers.
- Manual dispatch defaults to the longer release profile. There is no schedule,
  because privileged performance work consumes runner CPU and shared-runner
  variation is not longitudinal evidence.

### `secret-scan` — gitleaks + forbidden-term gate

[`/.github/workflows/secret-scan.yml`](../.github/workflows/secret-scan.yml)

- **gitleaks** scans the full git history (`fetch-depth: 0`) for secrets — API keys, tokens, private key material. It downloads the `gitleaks` v8.18.0 release tarball over HTTPS and verifies it against the published SHA-256 checksum before scanning.
- **forbidden-terms** is a custom `grep -RInE` job. The configured pattern is defined inline in [`/.github/workflows/secret-scan.yml`](../.github/workflows/secret-scan.yml) — read the workflow file for the authoritative regex (this page deliberately doesn't reproduce the pattern, because doing so would self-trip the gate). The pattern targets a small set of historical-internal references the repo cannot leak. Excludes `.github/`, `.git/`, `artifacts/`. Includes Markdown, YAML, JSON, asciinema casts, TOML, Python, Go, shell, `.gitignore`, `.env*`, `Dockerfile*`, `Makefile*`.

### `link-check` — lychee on Markdown links

[`/.github/workflows/link-check.yml`](../.github/workflows/link-check.yml)

- Runs on every pull request and weekly via cron, scanning `**/*.md`. Uses `lycheeverse/lychee-action@v2.9.0` (commit-pinned).
- Currently excludes five URL patterns/domains. One (`security/advisories/new`) requires being signed in to GitHub, so an unauthenticated checker gets a 404. Four bot-blocking domains (`developers.redhat.com`, `medium.com`, `answers.uillinois.edu`, `theregister.com`) return 403 to automated requests; these are legitimate research citations excluded rather than removed. The earlier Discussions-tab exclude was removed once Discussions was enabled on the repo.
- Timeouts remain failures. Prefer an immutable upstream primary reference over
  excluding a slow mirror or enabling `--accept-timeouts`; exclusions are for
  sources that are legitimate but structurally unavailable to automation, not
  a substitute for maintaining citations.

### `validate-formats` — JSON and YAML parsers

[`/.github/workflows/validate-formats.yml`](../.github/workflows/validate-formats.yml)

- **JSON job**: every `.json` file (excluding `.git`, `.claude`, `artifacts/`) parses with `python3 -c "import json; json.load(...)"`.
- **YAML job**: every `.yml`/`.yaml` file parses with PyYAML's `safe_load_all` (handles multi-document YAML).
This workflow exists because a misplaced comma in a JSON schema or a stray indent in an issue-template YAML would otherwise sit broken silently. A Markdown-table heuristic was prototyped and removed because the false-positive rate was too high; use a real Markdown parser before adding that gate back.

### `codeql` — CodeQL static analysis

[`/.github/workflows/codeql.yml`](../.github/workflows/codeql.yml)

- A pre-flight job (`detect-languages`) checks whether `python/` or `go/` carries source files. With the current dev tree, the matrix detects Python and Go and runs analysis per language.
- The CodeQL actions (`init`, `autobuild`, and `analyze`) are pinned to full commit SHAs in the workflow file, with the human-readable `v4` series noted in comments. Treat `.github/workflows/codeql.yml` as the authority for the exact pins so this testing guide does not drift when the pin is updated.
- Pairs with the `code_quality` ruleset rule on `main`: that rule reads from GitHub's code-scanning alerts table, so it passes vacuously while the matrix is empty and substantively once code lands. The CI job name (`codeql`) is intentionally **not** in the required-status-checks list — the ruleset already gates merges via the alerts mechanism.

### `tests` — Python and Go runtime tests

[`/.github/workflows/tests.yml`](../.github/workflows/tests.yml)

- **Python job**: installs `python/` with dev extras and runs
  `python -m pytest tests/ -q --tb=short` from the `python/` directory on
  Python 3.10 and Python 3.13. Because this runs the full `python/tests/`
  tree, it includes `python/tests/test_examples_smoke.py` for the offline,
  no-key examples smoke. That test covers checked-in mission fixtures and the
  examples claim ledger; it does **not** prove live-provider framework demos.
  The job then fails if pytest changed tracked files or left untracked files in
  the checkout; runtime keys, tokens, hooks, and reports belong in pytest temp
  directories unless a test explicitly directs output elsewhere. Coverage data
  and the uploaded XML report are written to the GitHub runner temp directory.
- **Go job**: runs `go test -count=1 ./...` and `go vet ./...` from `go/`.
- **Windows portability compile**: the Go job also cross-compiles
  `pkg/kernelcapture`, `ardur-kernelcaptured`, and the agent-recognition
  benchmark command for `windows/amd64` without executing them. This guards
  portable import boundaries; it does not claim Windows kernel capture or
  enforcement support.
- **Demo stack smoke**: starts the exact `make demo` target from fresh Compose
  volumes in detached/wait mode, then runs `scripts/verify-mvp.sh`. The job
  requires healthy public endpoints, authenticated issue/start, one `PERMIT`,
  one `DENY`, a signed attestation, session end, and authenticated metrics.
  Failure logs are emitted before containers and volumes are removed. The
  aggregate `tests` check requires this job to succeed.

### What's Not Enforced By CI Today

Explicit list, so the gap is visible:

- No content-fact verification (article claims, ADR cross-references) — caught only by review rounds and the cool-off re-read in the `dev → main` PR template.
- No Markdown lint — `markdownlint` adds noise we don't want yet, and the earlier table-pipe heuristic was removed.
- No YAML link-check (the issue-template `config.yml` URLs are not under `**/*.md`).
- No spelling.
- No external link-check on YAML or `.cast` files.

## Local Development Setup

```bash
# First-run setup — Python 3.13 required
cd /path/to/ardur/python
python3.13 -m venv .venv
.venv/bin/pip install -e '.[dev]'

# Run the curated test suite
.venv/bin/pytest tests/ -q

# Run a specific module
.venv/bin/pytest tests/test_passport.py -v

# End-to-end reproduce (Z3 proofs, signed proof bundle, corpus consistency)
make reproduce
```

## Module-Specific Gotchas

- **`test_mission_binding.py`**: one xfail (`test_tampered_md_returns_chain_invalid`) due to module-level `urllib.request.urlopen` state leak — runs green in isolation. CI invokes it as a separate `pytest` call.
- **`test_biscuit_passport.py`**: requires `biscuit-python==0.4.0`. ABI breaks on 0.5+ and on Python 3.14.
- **Live LLM tests**: tests under the semantic-judge / behavioral-fingerprint lanes need API access. Default test runs use test doubles; live runs require explicit env vars (`ARDUR_SEMANTIC_JUDGE=anthropic` + `ANTHROPIC_API_KEY`).

## Go AAT Test Suite

The `go/pkg/aat` package has 76 named tests covering the draft-00 DG v0.1
contract and the version-dispatched draft-01 DG v0.2 profile. The fixture
command has an additional byte-for-byte artifact regression:

```bash
cd go && go test ./pkg/aat ./cmd/aat-draft01-fixture -v
```

Covers: all 13 draft-00 constraint Check/Subsumes functions, the nine
draft-01 core constraints, IssueRoot validation, DeriveChild
depth/TTL/capability enforcement, BuildPoPJWT/VerifyPoPJWT round-trips, full
chain verification, revision dispatch, audience and approval enforcement,
holder/receipt-key separation, deterministic fixtures, and Registry operations.

## Cloud Model Governance Tests

Real-world integration tests proving governance proxy enforcement with live
LLMs can be run locally when provider credentials are available. The redacted
public tree keeps the runnable harnesses and aggregate reports, but does not
ship raw per-model result fixtures.

```bash
ARDUR_OLLAMA_API_KEY="<key>" python tests/run_cloud_model_test.py <model_name>
```

These are **not** CI-gated tests (they require live API access) but serve as
integration proof that the proxy evaluates every tool call correctly with
production models.

## Ardur Personal And Claude Code RC

When touching the Hub, browser adapter, Claude Code hook, posture index, or
`ARDUR.md` profile setup, run:

```bash
PYTHONPATH=python python -m pytest -q \
  python/tests/test_claude_code_hook.py \
  python/tests/test_claude_code_telemetry.py \
  python/tests/test_posture_index.py \
  python/tests/test_ardur_personal_hub.py \
  python/tests/test_ardur_profile.py
PYTHONPATH=python python plugins/claude-code/scripts/smoke.py
claude plugin validate plugins/claude-code
node --check examples/ardur-personal-extension/src/service_worker.js
node --check examples/ardur-personal-extension/src/content_script.js
node --check examples/ardur-personal-extension/src/popup.js
node examples/ardur-personal-extension/scripts/auth-header-smoke.mjs
```

The Hub test confirms browser observations produce standard Ardur Execution
Receipts through `GovernanceProxy`, CLI policy can block a controllable command,
the export path includes Session Reviews, and authenticated Hub endpoints reject
untrusted browser-origin requests. The posture-index tests cover valid and broken
receipt chains, missing telemetry, unknown tool boundaries, CLI JSON/Markdown
rendering, and redaction of credential-like values plus local path placeholders.

## Coverage Targets

| Surface | Minimum coverage | Source of bar |
|---------|------------------|---------------|
| `python/vibap/` | 80% | runtime package |
| `python/cli/` (when imported) | 60% | command surfaces |
| `python/integrations/<framework>/` (when imported) | 70% | public adapters |

Coverage runs against the renamed Ardur runtime only; legacy-era results are archived under `artifacts/legacy-era-*/` for lineage but never count for gates.

## Test-authoring rules (carry-over from private research, applies to all phases)

- **No rigged adapters.** Labels come from a separate file derived from public dataset labels. Adapters never see the ground truth. Violations are the single fastest way to get a benchmark retracted; the discipline that produced this rule is documented in the test-harness contract at the top of `python/tests/conftest.py`.
- **Regression tests for every bug fix.** If you fix bug X, write a test that fails on the pre-fix code and passes on the fixed code. The test goes in the same PR as the fix.
- **Name tests after what they prove, not what they exercise.** `test_passport_with_invalid_sig_is_rejected` beats `test_verify_passport_case_3`.
- **Avoid live-LLM tests by default.** Unit suites run with local test doubles; live-LLM paths are explicit opt-in via env var. CI doesn't burn API budget on every push.

## Before claiming "tests pass"

For docs/config-only changes: run a pre-commit local sweep — JSON parse over all `.json` files, YAML parse over all `.yml` / `.yaml` files, plus the forbidden-term grep. The exact `grep` invocation lives in [`/.github/workflows/secret-scan.yml`](../.github/workflows/secret-scan.yml); copy the include list, exclude list, and pattern string from there to run it locally:

```bash
# substitute <PATTERN> with the literal regex from secret-scan.yml's
# `PATTERN='...'` line; if you embed the pattern in this file the
# forbidden-term gate self-trips.
grep -RInE \
  --include='*.md' --include='*.yml' --include='*.yaml' \
  --include='*.json' --include='*.cast' --include='*.toml' \
  --include='*.py' --include='*.go' --include='*.sh' \
  --include='.gitignore' --include='.env*' \
  --include='Dockerfile*' --include='Makefile*' \
  --exclude-dir='.git' --exclude-dir='artifacts' \
  --exclude-dir='.github' \
  '<PATTERN>' .
```

For runtime changes:
- Exit code 0 on the full pytest suite
- Exit code 0 on the relevant Go build/test command when touching `go/`
- Known-failing / known-collecting-error count has not grown
- No `xfail` flipped to pass-or-fail without an explicit reason
- The pytest summary line (`N passed, M skipped, K xfailed`) pasted into the commit body so a reviewer can see the delta vs the known baseline without re-running
- When touching the Claude Code hook plugin, run
  `PYTHONPATH=python python3 -m pytest python/tests/test_claude_code_hook.py python/tests/test_claude_code_telemetry.py python/tests/test_ardur_profile.py -q`.
  Also run the end-to-end hook smoke:
  `PYTHONPATH=python python3 plugins/claude-code/scripts/smoke.py`
  (expects `PASS:` output and exit 0).
  Validate the current Claude Code plugin package:
  `claude plugin validate plugins/claude-code`.
  Live-binary smoke against an actual Claude Code session is optional and
  not gated in CI because it requires a Claude Code install.

## Why this page exists

Public security-software repos that fail their own CI on the first PR every
time train contributors not to trust the gates. This page keeps the automated
and manual checks explicit so release claims stay tied to evidence.
