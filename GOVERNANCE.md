# Governance

This document describes how decisions get made in Ardur and how code reaches
users. It describes the project as it is today, not as it might be later. If
you find a rule here that the repository does not actually follow, that is a
bug in this document — please report it.

## Project status and roles

Ardur is a **single-maintainer open-source project**. Gnani Rahul Nutakki is
the maintainer and is responsible for triage, review, release, and security
response.

There are two roles today:

- **Maintainer** — reviews and merges, cuts releases, responds to security
  reports, and is the final decision-maker on scope and claims.
- **Contributor** — anyone opening an issue or pull request.

There is **no CODEOWNERS file**, no automated reviewer routing, and no
approval-count rule. Review is a human judgment call. As the project grows,
additional maintainers would be added by the current maintainer, and this
document updated in the same change.

## Branches and gating

- **`dev` is the integration trunk.** All normal work — features, fixes, docs —
  targets `dev`. `origin/dev` is the default diff and PR base.
- **`main` is release-only and human-gated.** It receives work promoted from
  `dev` after that work has landed, passed verification, and is ready as a
  public-facing release. Promotion to `main` is an explicit, deliberate act by
  the maintainer; it is never a side effect of ordinary development.
- The published documentation site deploys from `main`, so `main` is also what
  the public reads.

Contributors and agents should not open PRs against `main` on their own
initiative. If a workspace was branched from `main` by accident, keep the
branch name and retarget the PR at `dev`.

## How a change lands

1. Open a PR against `dev`. Keep it scoped and reviewable.
2. CI runs. The required checks are the gate — see `.github/workflows/`, which
   is authoritative for what currently runs. Notable gates include the test
   suites, CodeQL, a secret scan (which also blocks specific LLM model
   identifiers in public surfaces), format validation, documentation-sync
   staleness checks, and, for kernel-facing changes, privileged enforcement
   jobs.
3. The maintainer reviews. Automated review tooling may also comment; its
   findings are advisory and the maintainer's judgment governs.
4. The maintainer merges. Branch protection is enabled on `dev` and `main`.

`Signed-off-by:` on commits (`git commit -s`) is the convention in this
repository's history. It is not currently enforced by a bot.

## How decisions get made

- **Architectural and protocol decisions are recorded as ADRs** under
  `docs/decisions/`. If a change alters a trust boundary, a credential format,
  an enforcement tier, or what the project claims, it should reference or add an
  ADR rather than living only in a PR description.
- **Claims are governed by evidence, not by consensus.** A capability is not
  described as proven unless the verifier and public artifacts back it, and
  documented limitations in `docs/known-limitations.md` and `STATUS.md` are
  treated as first-class project state. Disagreements about what Ardur can do
  are settled by running the verifier, not by discussion.
- **Disagreements** are worked out in the issue or PR thread. The maintainer
  decides when there is no consensus.

## Security

Vulnerability reports follow [`SECURITY.md`](SECURITY.md) — a GitHub Security
Advisory is preferred, and an active vulnerability should never be filed as a
public issue. Security response is the maintainer's responsibility and takes
priority over feature review.

## Code of conduct

Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Changing this document

Governance changes are made by PR to `dev` like any other change, and are the
maintainer's decision.
