# Engineering Standards

These rules define the working standard for Ardur. They are inspired by public
large-engineering-org practices: small reviewable changes, code health over
short-term speed, risk-driven testing, secure coding by default, and release
discipline. They do not claim to describe private internal rules from any
specific company.

## Non-Negotiables

1. **Truth comes from the repo.** Before changing code, read the current branch,
   diff base, tests, workflows, and local docs.
2. **No claim without evidence.** Public claims need a command, test, artifact,
   verifier path, or explicit limitation.
3. **Security is a design constraint.** External input is untrusted, secrets are
   never committed, and least privilege is the default.
4. **Tests scale with risk.** More shared behavior means broader tests.
5. **Reviews protect code health.** A review can block code that works locally
   but makes the system harder to maintain, reason about, or operate.
6. **Generated artifacts stay out of source control** unless they are explicit,
   reviewed fixtures.

## Foundation Rules

- Every project area must have an obvious owner surface: README, package docs,
  or an ADR explaining the boundary.
- Every new capability must identify its authority boundary. For Ardur, avoid
  letting adapters invent their own policy authority when a central runtime or
  hub should own enforcement.
- Prefer boring interfaces: JSON schemas, typed structs/classes, stable CLI
  flags, and explicit error values.
- Avoid hidden global state. If state is necessary, document where it lives,
  how it is locked, and how it is migrated.
- Keep docs and implementation in the same PR when user-visible behavior
  changes.
- If a dependency is added, record why it is needed, the trust boundary it
  introduces, and what replaces it if it becomes unsafe or unmaintained.

## Work Process

- Start every Conductor session with `./scripts/conductor-bootstrap.sh`.
- Target `dev` for normal implementation work. `main` is release-only and
  should receive promoted work from `dev` after verification.
- Before editing, state the task-specific success criteria in plain language.
- Keep changes small enough to review. Split unrelated work into separate PRs or
  workspaces.
- Treat branch state as part of the work. Check `git status --short --branch`
  before and after edits.
- Do not mix public-product changes with private writeups, session logs, or
  research scratchpads.
- If a task reveals stale docs, fix the stale docs or explicitly call out why
  they are left unchanged.
- If a test is skipped, explain why and name the test that should exist.

## Design Rules

- Start with correctness, then reliability, security, performance, operability,
  and cost.
- Define failure modes before implementation: invalid input, partial state,
  network failure, clock skew, replay, corrupt files, missing dependencies, and
  interrupted writes.
- Prefer fail-closed behavior for auth, policy, validation, provenance, and
  receipt verification.
- Make idempotence explicit for setup, migration, and bootstrap scripts.
- Any persistent file format needs a version or a documented migration story.
- Public APIs must have stable input/output examples and negative examples.
- CLI commands must return useful exit codes and avoid success-looking output
  after a failed operation.

## Security Rules

- Never commit credentials, private keys, access tokens, local receipt stores,
  or generated runtime state.
- Validate at trust boundaries, not only at internal call sites.
- Do not log raw secrets, bearer tokens, private keys, full JWTs, or sensitive
  payloads. Log bounded identifiers, hashes, or redacted forms.
- Use cryptographic libraries through high-level, reviewed APIs when possible.
- Avoid homegrown crypto, parser, or sandbox logic unless the repo explicitly
  owns that domain and tests it adversarially.
- Every network fetch must consider SSRF, redirects, timeouts, size limits,
  compression bombs, and certificate validation.
- Every policy bypass, debug flag, or unauthenticated mode must be loud in the
  interface and unacceptable for production defaults.
- Security-sensitive changes require negative tests.

## Testing Rules

- Unit tests prove local logic.
- Integration tests prove module boundaries and adapters.
- End-to-end tests prove user workflows and receipt/proof paths.
- Regression tests are mandatory for bug fixes.
- Tests must name the behavior they prove, not just the function they call.
- Avoid live paid-provider tests by default. Make them explicit opt-in with
  environment variables and cost notes. If an operator explicitly approves a
  local live-provider smoke test, load credentials from the environment, never
  print, log, persist, or commit secret values, and skip/report the test if the
  credential is absent.
- Prefer deterministic fixtures over sleeps, random timing, or live network
  dependencies.
- Add adversarial tests for parsers, auth, policy, revocation, delegation,
  provenance, and filesystem boundaries.
- A passing test suite is not enough if coverage misses the changed behavior.
  Name the exact risk that remains.

## Review Rules

- Review the behavior, not just the diff.
- Check tests first: if the tests do not prove the change, ask for better tests.
- Check for simpler interfaces before accepting new abstractions.
- Reject changes that silently broaden authority, trust, permissions, or public
  claims.
- Prefer author preference when two approaches are equally correct and equally
  maintainable.
- Review comments should be concrete, actionable, and tied to code or behavior.
- Do not approve a PR that leaves failing CI, unexplained skipped tests, or
  stale public docs.

## CI And Release Rules

- CI must run without private credentials for public PRs.
- Required checks should be meaningful, not ceremonial.
- `dev` is the integration branch for new work.
- `main` should only receive tested, verified, public-facing releases promoted
  from `dev`.
- Do not make `main` carry future-tense promises as present-tense guarantees.
- Pin actions and security-sensitive tooling where practical.
- If a check is noisy, fix the check or remove it. Do not train contributors to
  ignore red builds.
- Every release or graduation PR must include what was tested, what was not
  tested, and what evidence backs user-visible claims.

## Operability Rules

- Setup scripts must be idempotent and safe to re-run.
- Long-running services must expose a health check.
- Errors should say what failed, why it matters, and the next useful action.
- Local scripts must not require cloud credentials unless the command name and
  docs make that explicit.
- Costly operations need opt-in flags and cost notes.
- Avoid unbounded logs, traces, caches, and generated artifacts.

## Documentation Rules

- The root README should say what is true now, not what might be true later.
- `STATUS.md` owns maturity and readiness.
- ADRs own architectural decisions and tradeoffs.
- `docs/TESTING.md` owns validation expectations.
- `scripts/` directory owns agent/session startup and local validation tooling.
- Public docs must not depend on private paths, private artifacts, or local
  machine state.
- If a document is aspirational, label it as design, roadmap, or intent.

## AI Agent Rules

- Bootstrap first, then inspect.
- Do not trust memory when the repo can answer directly.
- Use `.context/ardur-graph.json` to find likely files, then verify with source.
- Do not edit generated `.context/` files except by running bootstrap/index
  scripts.
- Never create secret-bearing fixtures for convenience.
- Preserve user changes and avoid unrelated refactors.
- Report validation honestly: exact command, pass/fail, and known caveats.

## Public References

- [Google Engineering Practices Documentation](https://google.github.io/eng-practices/)
- [Google Testing Blog: Risk-Driven Testing](https://testing.googleblog.com/2014/05/testing-on-toilet-risk-driven-testing.html)
- [Apple Secure Coding Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Introduction.html)
- [Apple Security Development Checklists](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/SecurityDevelopmentChecklists/SecurityDevelopmentChecklists.html)
