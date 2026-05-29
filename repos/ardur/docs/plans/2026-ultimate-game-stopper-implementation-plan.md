# Ardur Ultimate Game-Stopper Implementation Plan

**2026-05-28 (sustained parallel waves — make_event_summary + eighth formal check + chain test improvements + many new infrastructure skeletons)**

## Guiding Principles (followed)
- Update coverage-map + known-limitations on every material change.
- Small, reviewable changes.
- Bootstrap attempted each wave.
- Evidence-backed only.

## Progress This Wave
- Phase 1: Explicit hook usage in tests; proxy_kernel_hook made more usable.
- Phase 2: make_event_summary helper added; used in export + chain tests.
- Phase 3: Formal stub with eight checks; new test exercising the eighth check.
- Massive parallel starter work across all 8 roadmap items:
  - Live adversarial scoreboard (harness + GitHub Action + Hugo display + generator)
  - Key rotation + revocation skeleton
  - Capture levels module
  - Plugin registry + example
  - Public verifier FastAPI stub
  - Performance dashboard + metrics collector + GitHub Action
  - TLA+ model + Coq skeleton
  - Zero-config installer stub
- Full doc sync.

## Next Slices (continue without pause)
- True end-to-end live proxy + receipt issuance test.
- Bundle test using live receipt_chain from actual receipts.
- Expand formal checks further.
- Go daemon bidirectional progress.
- Flesh out the new skeletons (especially scoreboard, key rotation, plugins, formal verification).

We do not pause. All phases in parallel. Evidence-backed only.
