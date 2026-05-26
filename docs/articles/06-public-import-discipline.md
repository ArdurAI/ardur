# Public Import Discipline

> Article 06 of the Ardur journey-log series. Date: 2026-04-29.
> Prerequisite reading: none. Cross-references:
> [`docs/public-import-plan.md`](../public-import-plan.md),
> [`README.md` naming note](../../README.md),
> [`docs/known-limitations.md`](../known-limitations.md).

## The problem

We had a private research repo with three years of history, a paper,
six months of session journals, an IETF draft, code under two
language stacks, a Kubernetes deployment surface, asciinema
recordings, and a long list of internal codenames. We wanted the
*product* to be public. We did not want the *monorepo* to be public.

Those two goals pull in opposite directions. A clean public repo is
small, narrowly-scoped, and reads like a real project that someone
might choose to use. A monorepo dump is dense, inscrutable, and tells
the reader "this is dragged into the open against its will." We knew
which way we wanted to land.

This article is about the discipline that got us there — the
checklist, the redaction passes, the rename history we kept and
the rename history we erased, and what we'd do differently if we
were starting again.

## The naming history we erased, and the names we kept

Before the public surface existed, there were three names in play:

| Layer | Was | Now |
|---|---|---|
| Project | Radiantic | (erased) |
| Runtime / product | Wolverine | Ardur |
| Protocol | MCEP | MCEP (unchanged) |
| Library | VIBAP | VIBAP (kept as a subpath) |

The decision: erase the codenames, keep the protocol and library
names. Rationale:

- **MCEP, VIBAP, SPIFFE, Biscuit, AAT, EAT** — these describe real
  technical artifacts that exist in the field, in IETF drafts, or
  in standardization tracks. Renaming them would be local
  vandalism that breaks the connection to external work.
- **Wolverine, Radiantic** — these were internal codenames. They
  carry no external recognition; the only people who knew what they
  meant were the team. Erasing them costs nothing and removes
  noise.

The hard part wasn't deciding the policy. The hard part was
applying it without missing anything. There were references in
README files, ADR bodies, capability IDs (`WOLV-CAP-*` casts),
Helm chart paths (`/deploy/helm/wolverine/`), Docker image tags
(`rahulnutakki/wolverine-demo:lang`), and IETF draft filenames
(`draft-nutakki-oauth-wolverine-governance-00`).

The rename pass was a two-pass `rg -i` sweep on the imported
content, with a manual exception list:

1. **Pass 1 — sensitive-reference scrub.** Patterns covering
   internal-only references to an adjacent initiative we hadn't
   cleared for public release. Hits get replaced with neutral
   phrasing ("an adjacent internal initiative") or the file
   holds out of the import. The exact pattern set is enumerated
   in
   [`docs/public-import-plan.md`](../public-import-plan.md)'s
   exclude-by-default section so future contributors apply the
   same discipline. The scan is also enforced post-merge by the
   `secret-scan / forbidden-terms` CI workflow, which fails the
   build on any hit landing in a public path.
2. **Pass 2 — codename rename.** Case-sensitive sweeps for the
   two erased product names → replace with `Ardur` in prose.
   Preserve only in: (a) this article's naming-history passage
   (which is the documented exception), (b) ADR bodies where
   the decision predates the rename (history is itself a
   primary source), (c) cast filenames that were renamed in
   their new form.

The cast files themselves — the captured terminal output — were
re-recorded under the renamed binary so the on-screen text says
`ARDUR_LIVE_L5_*` and `spiffe://ardur-demo.local/...`, not the
codename. We left the original Wolverine-era recordings in a
private archive so the paper's references to past numbers stay
verifiable; the public repo cites only the Ardur-era artifacts.

## The source mapping

The plan we followed lives at
[`docs/public-import-plan.md`](../public-import-plan.md).

Its discipline in one sentence: **for every directory in the
private tree, decide explicitly whether it goes public verbatim,
public after rewrite, or stays private — and write that decision
down before doing the move.**

Decision categories used:

- **Verbatim copy.** Public-safe code (the Python runtime, the Go
  packages, the v0.1 specs). The directory moves, paths get
  rewritten, and tests follow.
- **Rewrite for public audience.** The README, status, and roadmap
  prose was written for an internal audience and used internal
  framing. We kept the substance, threw out the framing, and
  re-wrote.
- **Curated subset.** `vibap-prototype/tests/` had ~400 tests; we
  imported only the tests that back claims the public docs make,
  deferring corpus-heavy research tests to a future round.
  Examples were similarly curated to four directories
  (`langchain-quickstart`, `autogen-quickstart`, `_shared`,
  and the basic mission-JSON examples).
- **Stays private.** Session journals, paper sources (LaTeX,
  references.bib), the EDR-vendor connectors, branch coordination
  notes, AI-team runbooks, every `.env*` file, every key, every
  generated receipt with operator-identifying content. The full
  exclude-by-default list is in the plan.

The "stays private" list is longer than the "goes public" list.
That's intentional. Public repos are a project's first
impression; private repos are where research lives. Nothing in
the public repo claims to be a complete picture of what we did.

## The graduation gate

`dev` is where the imports land. `main` is what gets advertised.
Anything on `main` has to map to running code, a verifier output,
proof media, or an explicit limitation note.

The graduation gates we run before promoting a `dev` commit to
`main`:

1. **Link-check.** `lychee` on every changed markdown file. Dead
   links are how a serious project starts looking unmaintained.
2. **Secret-scan.** Custom forbidden-term gate plus the no-LLM-
   model-names rule. The forbidden terms include the codenames
   we erased; the model-names rule keeps editorial prose
   neutral.
3. **Schema sync.** The Mission Declaration v0.1 schema lives in
   two places —
   `docs/specs/mission-declaration-v0.1.schema.json` (canonical)
   and `python/vibap/_specs/mission_declaration_v01.schema.json`
   (the runtime's embedded copy). A CI gate fails the build on
   drift between them.
4. **Tests.** Python on 3.10 and 3.13; Go at the version pinned
   in `go.mod` (currently 1.25.9).
5. **CodeQL** for both Python and Go.
6. **A 24-hour cool-off re-read** of the diff by the maintainer
   before the merge. The graduation gate isn't just CI — it's
   also "did I actually understand what I'm putting on `main`?"

Article 07 (Public Branch Discipline For Security Software) goes
into the rationale for these gates in detail.

## What we'd do differently

Three things, in order of regret:

1. **Stop publishing under codenames in the first place.** We
   built Docker images as `rahulnutakki/wolverine-demo:*`, filed
   an IETF draft as
   `draft-nutakki-oauth-wolverine-governance-00`, and cited the
   Wolverine name in early outreach emails. None of that was
   ever supposed to be the public name. The rebrand cost us a
   weekend of reissuing tags and a re-record of every cast.
   Lesson: if a name is a codename, treat it like one — keep it
   inside the team. Use a placeholder like
   `<product-tbd>` in any artifact that might leak.
2. **Write the import plan before the imports.** The first
   import attempt happened before
   [`docs/public-import-plan.md`](../public-import-plan.md)
   existed. The plan came after the third "wait, why is this
   private file in the public diff?" moment. Reverse the
   ordering: write the source-mapping discipline first, then
   move files according to it.
3. **Treat the audit cycle as a planned phase, not an
   afterthought.** The 11-round hostile audit cycle that closed
   2026-04-29 took us from "we believed this was safe" to "an
   adversarial reviewer agrees with us." It found 1 CRITICAL +
   16 HIGH + 37 MEDIUM + 47 LOW issues we hadn't seen
   ourselves. None of those would have been caught by the
   public-import-plan's checklist alone. If we were doing this
   again, we'd budget time for the audit cycle as a
   first-class deliverable, not as something we'd do later.
   Article 11 (The Rigged-Tests Audit) goes into the specific
   rigging the cycle caught — including a test the auditor
   confirmed by physical mutation of the source — and why
   self-review never substitutes for hostile review.

## What this means for users

If you're reading this as a potential user, two things matter:

1. **What's in the public repo is real.** Every public claim
   maps to running code or an explicit limitation. The
   `docs/known-limitations.md` page is the documented compliance
   boundary; the
   [verifier-contract spec Section 13](../specs/verifier-contract-v0.1.md)
   names which `MUST` clauses the reference Python proxy
   actually enforces today versus which are design-only. We
   don't claim more than we can defend.
2. **The private parts staying private is the discipline, not
   a hidden snag.** The Mission Declaration spec is public; the
   policy review process that produced it is private. The
   reference proxy is public; the session journals where we
   debated the API shape are private. That separation is on
   purpose; a public repo that tries to also be the team's
   working notes is hostile to outside readers.

If you're reading this as someone considering opening their own
private research repo: the cost of doing it well is mostly
discipline, not engineering. Decide what's public before you
move it. Erase codenames before they leak into artifacts. Run a
hostile audit before you advertise. The rest is just file
moves.

---

*Article 06 — Public Import Discipline. Part of the Ardur journey-log
series. Source materials at
[`docs/public-import-plan.md`](../public-import-plan.md) and
[`README.md`](../../README.md). Comments and corrections via
GitHub Discussions.*
