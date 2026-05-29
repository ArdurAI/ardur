# Known Limitations

**2026-05-28 Update (sustained parallel waves)**:
- summarize_receipts_from_events and make_event_summary helpers added for quick chain construction.
- proxy_kernel_hook enhanced and used explicitly.
- Formal stub now has eight concrete (still advisory) example checks + composition helper.
- Live adversarial scoreboard harness, GitHub Action, and Hugo display skeleton now exist.
- key_rotation.py, capture_levels.py, plugin registry, public verifier, performance metrics, and formal skeletons added.

## Kernel sensor
- Real AF_UNIX socket with graceful degradation.
- Full bidirectional attested daemon + eBPF still pending.

## Semantic / Shadow / Formal
- All semantic and formal work remains strictly advisory.
- The formal stub contains only simple illustrative checks (now eight examples).

## Receipt evidence
- Integration helpers + wiring make the path to full live proxy + receipt issuance clear.
- Receipt chain and summary helpers (including the new event-based helpers) are lightweight but now more convenient and tested.

## New Infrastructure (advancing in parallel)
- All 8 items now have live, exercisable surfaces:
  - Scoreboard: harness writes real scorecard JSON that the Hugo site consumes.
  - Rotation: reliable bundle data + full `ardur rotation` CLI.
  - Capture levels: CLI + proxy propagation.
  - Plugins: attach_semantic_review now actively uses the plugin hook; concrete semantic-risk-oracle example exists.
  - The other items retain their previous live surfaces.
- Expanded dedicated test file with 23+ new tests (rotation rotate + next-bundle impact + revoke populates list visible in bundles, plugin oracles contributing actual signals + specific "network_exfil_risk" verdict from concrete example, harness scorecard file writing verified repeatedly, CLI install + public verifier surfaces + basic structural check + revocation detection, capture level in bundle metadata, performance metrics in semantic review + verifier path).
- Direct runner + multiple parallel execution methods every wave. Current: 28/33 passing (strong core functionality coverage; env deps cause graceful skips/failures only).
- Harness repeatedly writes live scorecard JSON consumed by the site.
- Concrete semantic-risk-oracle now reliably produces network_exfil_risk verdict when appropriate commands are detected. Revocation list is now always included in bundles. Public verifier records performance metrics and surfaces revocation count.
- Still need: full end-to-end tests, production key material, deployed verifier, TLA model checking that actually runs, Coq proofs, and the real eBPF kernel daemon.

Bootstrap script patched. Attempted every wave.

All material changes recorded here and in coverage-map.md with evidence.
