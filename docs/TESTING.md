# Testing

The public tree includes curated Python and Go runtime code under `python/`
and `go/`. GitHub Actions now covers runtime tests, repository hygiene,
structured-file parsing, link checks, secret scanning, and CodeQL.

Do not claim broader coverage than the workflows provide. If a feature needs a
manual smoke test, list the exact command and the observed result in the PR.

## What Runs Today

Five GitHub Actions workflows. Most run on push to `dev`/`main` and on every
pull request; `link-check` runs on PRs and a weekly cron only.

### `secret-scan` — gitleaks + forbidden-term gate

[`/.github/workflows/secret-scan.yml`](../.github/workflows/secret-scan.yml)

- **gitleaks** scans the full git history (`fetch-depth: 0`) for secrets — API keys, tokens, private key material. Pinned to commit SHA `ff98106e...`.
- **forbidden-terms** is a custom `grep -RInE` job. The configured pattern is defined inline in [`/.github/workflows/secret-scan.yml`](../.github/workflows/secret-scan.yml) — read the workflow file for the authoritative regex (this page deliberately doesn't reproduce the pattern, because doing so would self-trip the gate). The pattern targets a small set of historical-internal references the repo cannot leak. Excludes `.github/`, `.git/`, `artifacts/`. Includes Markdown, YAML, JSON, asciinema casts, TOML, Python, Go, shell, `.gitignore`, `.env*`, `Dockerfile*`, `Makefile*`.

### `link-check` — lychee on Markdown links

[`/.github/workflows/link-check.yml`](../.github/workflows/link-check.yml)

- Runs on PRs touching `**/*.md` and weekly via cron. Uses `lycheeverse/lychee-action@v2.8.0` (commit-pinned).
- Currently excludes one URL pattern that 404s for an unauthenticated checker: `security/advisories/new` (the page requires being signed in to GitHub). The earlier Discussions-tab exclude was removed once Discussions was enabled on the repo.

### `validate-formats` — JSON and YAML parsers

[`/.github/workflows/validate-formats.yml`](../.github/workflows/validate-formats.yml)

- **JSON job**: every `.json` file (excluding `.git`, `.claude`, `artifacts/`) parses with `python3 -c "import json; json.load(...)"`.
- **YAML job**: every `.yml`/`.yaml` file parses with PyYAML's `safe_load_all` (handles multi-document YAML).
This workflow exists because a misplaced comma in a JSON schema or a stray indent in an issue-template YAML would otherwise sit broken silently. A Markdown-table heuristic was prototyped and removed because the false-positive rate was too high; use a real Markdown parser before adding that gate back.

### `codeql` — CodeQL static analysis

[`/.github/workflows/codeql.yml`](../.github/workflows/codeql.yml)

- A pre-flight job (`detect-languages`) checks whether `python/` or `go/` carries source files. With the current dev tree, the matrix detects Python and Go and runs analysis per language.
- Pinned to `github/codeql-action@ce64ddcb` (commit-pinned; `v3` is an annotated tag whose tag-object is `865f5f5c...` and whose underlying commit is `ce64ddcb...`). Same pin discipline as the rest of the workflow set.
- Pairs with the `code_quality` ruleset rule on `main`: that rule reads from GitHub's code-scanning alerts table, so it passes vacuously while the matrix is empty and substantively once code lands. The CI job name (`codeql`) is intentionally **not** in the required-status-checks list — the ruleset already gates merges via the alerts mechanism.

### `tests` — Python and Go runtime tests

[`/.github/workflows/tests.yml`](../.github/workflows/tests.yml)

- **Python job**: installs `python/` with dev extras and runs
  `python -m pytest tests/ -q --tb=short` from the `python/` directory on
  Python 3.10 and Python 3.13. Because this runs the full `python/tests/`
  tree, it includes `python/tests/test_examples_smoke.py` for the offline,
  no-key examples smoke. That test covers checked-in mission fixtures and the
  examples claim ledger; it does **not** prove live-provider framework demos.
- **Go job**: runs `go test -count=1 ./...` and `go vet ./...` from `go/`.

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

The `go/pkg/aat` package has 49 tests covering the full AAT specification:

```bash
cd go && go test ./pkg/aat/... -v
```

Covers: all 13 constraint Check/Subsumes functions, IssueRoot validation,
DeriveChild depth/TTL/capability enforcement, BuildPoPJWT/VerifyPoPJWT
round-trips, full §7 chain verification scenarios, and Registry operations.

## Cloud Model Governance Tests

Real-world integration tests proving governance proxy enforcement with live
LLMs. Results are in `python/tests/test-results/`.

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
