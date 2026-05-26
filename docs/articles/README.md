# Articles

Long-form posts about how Ardur is built, what it does, and what it
deliberately doesn't try to do. The series is a journey log: each
article cites code that exists in this repo, an artifact you can
verify, or a limitation we've named.

| # | Title |
|---|---|
| **05** | **Proof Media That Actually Means Something** |
| **06** | **Public Import Discipline** |

Additional articles covering runtime governance rationale, mission declarations,
partial visibility, delegation narrowing, and branch discipline are planned for
future publication.

## Sources we cite

Articles routinely link to:

- `docs/specs/` — protocol specs (verifier contract, mission
  declaration, execution receipt, conformance profiles).
- `docs/security-model.md` — what the reference proxy enforces today.
- `docs/known-limitations.md` — the documented gap between protocol
  intent and runtime enforcement.
- `docs/public-import-plan.md` — the source-mapping discipline that
  turned a private research tree into this public repo.
- `python/vibap/` and `go/pkg/` — the Python and Go reference
  implementations.
- `media/casts/` — recorded terminal proofs.

## Hard rule

No specific LLM model identifiers appear in article prose. When a
specific model's behaviour is being discussed, the article uses
generic phrasing (e.g. "a frontier model from a major lab") and
defers exact identifiers to fenced data blocks where the slug is
mechanically derived from a benchmark artifact, not editorial.
