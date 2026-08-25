# Lineage Budget Delegation Plan Review

Generated: 2026-05-13T15:56:29Z (original plan review)
Original branch: `gnanirahul/lineage-budget-delegation-20260513T103128`
Original base: `origin/dev` at `c093964`
Original Kanban task: `t_566c8311`
Refreshed: 2026-05-13T19:52:25Z onto `origin/dev` at `4d76aad` in branch `gnanirahul/lineage-budget-delegation-refresh-20260513T144556` for Kanban task `t_e8dd9bbc`.
Design doc check: no existing gstack design doc found for the original branch. This file is the plan-review artifact required before code/doc changes; the refresh preserves its plan conclusions while applying the implementation to the current base.

## Decision

Choose the Phase 1 defer path.

Do not implement a new SQLite-backed lineage budget ledger in this sprint. Preserve the existing `FileLineageBudgetLedger` for delegation reservation accounting, add loud failure for mission-declared `lineage_budgets` in the mission compiler/issuance paths, and update status/claim docs so users do not infer runtime support that does not exist.

Why: the repo already has a concrete durable JSON ledger for sibling delegation reservations, but mission-declared lineage budget lowering is not wired into issuance/verifier state. A SQLite migration would touch storage, migrations, runtime state, docs, claim ledger, and concurrency behavior. That is too much blast radius for a release-readiness blocker whose safe Phase 1 outcome is "works where implemented, fails closed where not implemented."

## Step 0: Scope Challenge

1. Existing code that already solves sub-problems:
   - `python/vibap/lineage_budget.py` provides `LineageBudgetLedger` plus concrete `FileLineageBudgetLedger` with `fcntl`-locked JSON snapshots and idempotent reservation/release/reject semantics.
   - `python/tests/test_lineage_budget.py` already covers reservation success, oversubscription failure, reload/crash persistence, idempotent duplicate delegation request IDs, release, reject, and concurrent sibling reservations.
   - `python/vibap/passport.py::MissionPassport.from_dict` rejects unknown mission fields, so `/issue` already fails closed on raw `lineage_budgets` in a passport-shaped payload.
   - `python/vibap/mission_compile.py` has the existing loud-failure pattern: `MissionPolicyNotImplementedError` for unsupported non-empty `effect_policies` and `flow_policies`.

2. Minimum change that satisfies the task:
   - Add a failing test that `compile_mission(lineage_budgets=...)` raises `MissionPolicyNotImplementedError` with a Phase 1 deferred message.
   - Add a failing HTTP issuance test that `/issue` with `lineage_budgets` returns 400 and says the field is unsupported/Phase 1 deferred, rather than issuing a token.
   - Implement the smallest compiler/passport gate needed to produce that explicit failure.
   - Update `STATUS.md`, `site/data/claims.json`, and source-backed docs/mirrors only where claims could overread as mission-declared lineage budget enforcement.

3. Complexity check:
   - SQLite implementation path would likely touch more than 8 files and introduce migrations/state compatibility. Smell triggered. Defer.
   - Explicit defer path should touch roughly 5 to 7 files: tests, compiler/passport/error path, status/claim docs, and checkpoint/handoff docs if needed. Right-sized.

4. Search/check-local note:
   - No external architecture search is needed. This is not a new storage/concurrency design if we choose defer. For the existing ledger, the boring built-in path is Python JSON + `fcntl.flock`, already implemented and tested.

5. TODOs:
   - No tracked `TODOS.md` exists in this checkout. Future SQLite lineage-budget accounting should be captured in Ardur backlog/operator docs if this task exposes a durable follow-up.

6. Completeness check:
   - Complete Phase 1 behavior means no silent acceptance of unsupported mission-declared lineage budgets. It does not mean implementing every v0.1 spec concept. The complete safe option is fail-closed tests + claim limitation.

7. Distribution check:
   - No new package, binary, image, or public distribution surface in this task.

## What already exists

- Concrete delegation reservation ledger: reuse `FileLineageBudgetLedger`; do not replace it with SQLite now.
- Abstract `LineageBudgetLedger`: keep as interface only. Tests must prove the runtime uses the concrete ledger on delegation flows and does not fall through to abstract `NotImplementedError`.
- Mission compiler loud-failure pattern: reuse `MissionPolicyNotImplementedError` for `lineage_budgets`.
- `/issue` input rejection: keep fail-closed behavior, but make `lineage_budgets` error clearer than a generic unknown-field failure if practical with a small diff.
- Public claim ledger: update only claim/status text that could imply mission-declared lineage budgets are currently enforced.

## Architecture review

Issue 1: Mission-declared `lineage_budgets` has spec/doc presence but no runtime compiler enforcement.
Recommendation: add explicit Phase 1 deferred failure at the compiler and `/issue` edge.
Confidence: 9/10, verified in `mission_compile.py`, `passport.py`, and docs/spec references.

Data flow after the defer patch:

```text
Mission declaration / issue payload
        |
        v
  compile_mission(..., lineage_budgets=...)
        |
        +-- empty or omitted ---------------> existing resource/effect/flow logic
        |
        +-- non-empty lineage_budgets ------> MissionPolicyNotImplementedError
                                               "Phase 1 deferred; not enforced"

HTTP /issue payload
        |
        v
 MissionPassport.from_dict(...)
        |
        +-- no lineage_budgets --------------> existing passport issuance
        |
        +-- lineage_budgets present ---------> ValueError / 400, no token issued
```

Production failure scenario: a mission author copies v0.1 spec fields into a live issuance payload and assumes lineage ceilings are enforced. The patch must make that request fail before a token exists.

No new service, database, migration, network edge, or long-running process is introduced.

## Code quality review

Issue 1: A generic unknown-field error is fail-closed but not operator-friendly for a field that appears in public specs.
Recommendation: keep strict `_KNOWN_FIELDS`, but special-case `lineage_budgets` with an explicit unsupported/Phase 1 deferred message if the diff stays small. Do not add a dataclass field that then risks being serialized into tokens without enforcement.
Confidence: 8/10.

Issue 2: The abstract `LineageBudgetLedger` methods intentionally raise `NotImplementedError`, but the release blocker is runtime fall-through.
Recommendation: no broad interface rewrite. Add/keep smoke coverage proving the active proxy delegates through `FileLineageBudgetLedger` and oversubscription fails with a clear HTTP response.
Confidence: 8/10.

## Test review

Framework: Python `pytest`, per `AGENTS.md` and existing `python/tests` layout.

Coverage diagram:

```text
CODE PATHS                                                     USER / OPERATOR FLOWS
[+] python/vibap/mission_compile.py                            [+] Mission compiler use
  ├── [★★★ TESTED existing] resource policies compile            ├── [★★★ TESTED existing] resource-only mission compiles
  ├── [★★★ TESTED existing] effect policies fail loudly           ├── [GAP] mission-declared lineage_budgets fails loudly
  ├── [★★★ TESTED existing] flow policies fail loudly             └── [GAP] error message says unsupported/Phase 1 deferred
  └── [GAP] lineage_budgets fail loudly

[+] python/vibap/passport.py + proxy /issue                    [+] Mission issuance
  ├── [★★★ TESTED existing] unknown fields reject                ├── [GAP] /issue with lineage_budgets returns 400
  ├── [★★★ TESTED existing] non-object mission rejects            └── [GAP] no token issued for unsupported field
  └── [GAP] lineage_budgets rejection message is explicit

[+] python/vibap/lineage_budget.py + /delegate                 [+] Delegation reservation behavior
  ├── [★★★ TESTED existing] reserve/release/reject                ├── [★★★ TESTED existing] child budget reservation succeeds
  ├── [★★★ TESTED existing] oversubscription rejects              ├── [★★★ TESTED existing] duplicate request id is idempotent
  ├── [★★★ TESTED existing] reload/concurrent persistence         └── [★★★ TESTED existing] sibling reservations cap total budget
  └── [★★★ TESTED existing] HTTP shared-state concurrency

COVERAGE TARGET AFTER PATCH:
- Compiler lineage defer: add ★★★ negative test.
- HTTP issuance defer: add ★★★ negative test.
- Ledger reservation: preserve existing ★★★ tests and run the focused file.
```

Required RED tests:
1. `python/tests/test_mission_compile.py::TestCompileMissionAggregator::test_lineage_budgets_at_aggregator_raises_phase1_deferred`
   - Input: non-empty `lineage_budgets`.
   - Expected: `MissionPolicyNotImplementedError`, message includes `lineage_budgets` and `Phase 1`/`deferred`.
   - RED reason expected: `compile_mission()` currently does not accept `lineage_budgets`.

2. `python/tests/test_http.py::TestHTTPAuthAndValidation::test_issue_with_lineage_budgets_fails_phase1_deferred`
   - Input: `/issue` mission payload with normal passport fields plus `lineage_budgets`.
   - Expected: HTTP 400, message includes `lineage_budgets` and unsupported/deferred, and no token in body.
   - RED reason expected: current generic unknown-field error lacks the deferred reason.

3. Preserve/run `python/tests/test_lineage_budget.py -v` as the delegation pass/fail ledger suite. No new SQLite tests because SQLite is explicitly deferred.

## Performance review

No new hot path if defer path is chosen. The only runtime additions are validation branches before token issuance. Delegation performance stays on existing `FileLineageBudgetLedger`; this task must not replace the storage path or introduce migrations.

Performance risk: adding compiler checks is negligible. Adding SQLite now would add new I/O and migration failure modes without improving Phase 1 user truth enough to justify it.

## NOT in scope

- SQLite ledger implementation: deferred because it introduces migrations, compatibility behavior, and new persistence failure modes beyond this release-readiness blocker.
- Full `MD.lineage_budgets` verifier-state accounting: deferred because the compiler/runtime does not yet connect mission declarations to reserved-budget ceilings.
- New public release, PR, issue, push, package upload, or site/social/public metadata movement: out of scope per Kanban red lines.
- eBPF/tool-agnostic capture and daemon work: unrelated Phase 2 scope.
- Refactoring the whole passport schema: unnecessary; strict unknown-field rejection is already the right safety default.

## Failure modes

| Path | Failure mode | Test | Error handling | User sees |
|------|--------------|------|----------------|-----------|
| `compile_mission(lineage_budgets=...)` | unsupported budget silently compiles to no checks | new RED test | raise `MissionPolicyNotImplementedError` | explicit Phase 1 deferred error |
| `/issue` with `lineage_budgets` | token issued while budgets are not enforced | new RED test | HTTP 400 before issuance | explicit unsupported/deferred error |
| `/delegate` sibling reservations | child reservations exceed parent remaining budget | existing tests | ledger conflict / permission response | rejection, not abstract crash |
| repeated delegation request id | retry double-counts reservation | existing tests | idempotent reservation | one reservation retained |

Critical gaps after planned tests: none expected. If `/issue` cannot produce explicit deferred wording without broad schema changes, keep fail-closed behavior and document the limitation, but mark it as review concern.

## Worktree parallelization strategy

Sequential implementation, no parallelization opportunity. The core changes touch one Python validation/compiler lane plus related docs/claims. Splitting would create coordination overhead and risk inconsistent claims.

## Implementation plan

1. RED:
   - Add the two negative tests above.
   - Run them specifically and verify expected failures.

2. GREEN:
   - Add `lineage_budgets` optional input to `compile_mission` and lower/guard function that raises `MissionPolicyNotImplementedError` for non-empty input.
   - Special-case `lineage_budgets` in `MissionPassport.from_dict` unknown-field handling with explicit unsupported/Phase 1 deferred text, without adding it to `_KNOWN_FIELDS`.
   - Update status/claims/docs to split "delegation reservation ledger works" from "mission-declared lineage_budgets deferred".

3. VERIFY:
   - Focused RED/GREEN tests.
   - `PYTHONPATH=python python/.venv/bin/pytest python/tests/test_lineage_budget.py -v`.
   - Relevant focused HTTP/compiler tests.
   - Mission issuance smoke with delegation enabled and a separate unsupported `lineage_budgets` smoke.
   - `./scripts/check-local.sh --quick --python python/.venv/bin/python`.
   - Diff review/security scan per `requesting-code-review`.

4. HANDOFF:
   - Add project checkpoint/learning if behavior or claims changed.
   - Comment structured review-required handoff on task `t_566c8311`.
   - Block with `review-required:` for dependent reviewer `t_6cd5a3ee`.

## Completion summary

- Step 0: Scope Challenge — scope reduced to Phase 1 defer/fail-closed path.
- Architecture Review: 1 issue found, resolved by explicit unsupported-field gate.
- Code Quality Review: 2 issues found, resolved by small validation/error-message changes and existing ledger preservation.
- Test Review: diagram produced, 2 new gaps identified.
- Performance Review: 0 implementation issues for defer path; SQLite path rejected for blast radius.
- NOT in scope: written.
- What already exists: written.
- TODOS.md updates: tracked `TODOS.md` absent; future SQLite work should go to Ardur backlog/operator docs if needed.
- Failure modes: 0 critical gaps expected after planned tests.
- Outside voice: skipped for plan artifact; independent diff review remains required after implementation.
- Parallelization: sequential, no useful parallel lanes.
- Lake Score: 2/2 recommendations choose complete fail-closed coverage rather than happy-path-only docs.

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| Eng Review | `/plan-eng-review` | Architecture & tests before implementation | 1 | CLEAR FOR IMPLEMENTATION | defer SQLite; add 2 negative tests; preserve existing ledger suite |
| Code Review | `requesting-code-review` | Independent diff/security gate | 0 | PENDING | run after implementation |
| Release Readiness | release gate | pre-landing only | 0 | PENDING | out of scope for implementation card until reviewer approves |

VERDICT: ENG PLAN CLEARED — implement the defer/fail-closed path, then run diff review and block for human/reviewer approval.
