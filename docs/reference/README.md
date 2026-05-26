# Technical Reference

Flat technical reference pages for the public Ardur surface. These describe
*what* a surface accepts and emits, not *how* to use it day-to-day. For task
walkthroughs see [`../guides/`](../guides/); for protocol semantics see
[`../specs/`](../specs/).

## Pages

- [CLI Reference](cli.md) — every `ardur` subcommand, its flags, and what it
  emits
- [Personal Hub HTTP API](personal-hub-api.md) — endpoints exposed by
  `ardur hub`, auth model, request and response shapes, error codes
- [`ARDUR.md` Profile Format](ardur-md-profile.md) — the plain-Markdown
  guardrail format that compiles into a Mission Passport

## When To Update These Pages

These pages mirror the public source. When the underlying surface changes
(`python/vibap/cli.py`, `python/vibap/personal_hub.py`,
`python/vibap/ardur_profile.py`), update the matching page in the same change.
They are deliberately mechanical so the diff is easy to review.
