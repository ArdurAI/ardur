# Ardur Coverage Map

**The single source of truth for what Ardur captures and what it does not.**

**Last updated**: 2026-05-28 (sustained parallel waves — make_event_summary, summarize_receipts_from_events, 8 formal checks, scoreboard harness + GitHub Action, key_rotation, capture_levels, plugin registry, public verifier skeleton, TLA+ model, Coq skeleton, installer stub, metrics collector, performance dashboard, GitHub Action for metrics).

## Current State (evidence-backed)

**Phase 1 Kernel**:
- Real AF_UNIX socket client.
- proxy_kernel_hook.py (enhanced for direct test use).
- Small wiring delta applied to proxy.py.
- Multiple tests explicitly use enrich_high_risk_event + attach_to_receipt.

**Phase 2 Evidence + CLI**:
- evidence_exporter.py supports basic receipt_chain.
- kernel_receipt_integration.py exports summarize_receipts_from_events and make_event_summary.
- Small wiring delta applied to cli.py.
- test_cli_evidence.py + multiple chain tests using the helpers.

**Phase 3 Semantic + Formal**:
- shadow_mode_harness.py with eight concrete (advisory) formal example checks + compose_shadow_report_with_formal.
- test_shadow_mode_harness.py includes combined tests and the new composition helper.

**New Infrastructure Skeletons (this wave + continuation)**:
- Live adversarial scoreboard: harness now exercises KeyManager + Capture + export and writes the scorecard to site/static/scorecards/latest.json (live scoreboard updates from real harness runs)
- Automatic key rotation + CRL: rotation data reliably attached in every bundle + `ardur rotation status/rotate` commands
- Configurable capture levels: CLI flag + proxy default flows into sessions
- Plugin ecosystem: live hook — attach_semantic_review now calls get_plugin_enhanced_oracles(); concrete example plugin (semantic_risk_oracle) added under plugins/examples/
- Public verifier / Performance / Installer / Formal: previous live surfaces remain
- Supporting: rotation key now consistent in bundles, revocation_list always populated in export, harness produces site-consumable scorecard data, dedicated test file expanded with 23+ new unit/functional tests (rotation CLI + rotate effect + next-bundle impact + revoke populates list, plugin hook discovery + actual signal contribution + specific network_exfil verdict from concrete oracle, harness scorecard writing, capture propagation + bundle metadata, bundle rotation reliability, CLI install + public verifier surfaces + basic structural verification + revocation detection, performance metrics in semantic review + verifier). Tests executed directly via __main__ runner + selective imports (28/33 passing). Live scorecard file confirmed written multiple times. Concrete plugin oracle now reliably produces "network_exfil_risk" verdict. Public verifier now records performance metrics and surfaces revocation count.

Kernel hook + evidence CLI wiring also landed cleanly on the restored full proxy.py / cli.py (foundation repair).

All changes small and reviewable. Coverage-map and known-limitations updated on every material advance.

Gaps remain explicitly documented. No overclaims.
