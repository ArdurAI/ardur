# Ardur Coverage Map

**The single source of truth for what Ardur captures and what it does not.**

**Last updated**: 2026-05-28 (sustained parallel waves — make_event_summary helper + eighth formal check + explicit hook usage + chain tests).

## Current State (evidence-backed)

**Phase 1 Kernel**:
- Real AF_UNIX socket client.
- proxy_kernel_hook.py (enhanced for direct test use).
- Small wiring delta applied to proxy.py.
- Multiple tests explicitly use enrich_high_risk_event + attach_to_receipt.

**Phase 2 Evidence + CLI**:
- evidence_exporter.py supports basic receipt_chain.
- kernel_receipt_integration.py now exports make_event_summary (tiny single-event helper, used in tests).
- Small wiring delta applied to cli.py.
- test_cli_evidence.py + chain tests using the helpers.

**Phase 3 Semantic + Formal**:
- shadow_mode_harness.py with eight concrete (advisory) formal example checks.
- test_shadow_mode_harness.py includes combined shadow + formal + receipt tests and the new identical-scope example.

All changes small and reviewable. Coverage-map and known-limitations updated on every material advance.

| Layer | Status | Evidence |
|-------|--------|----------|
| Layer 2 Kernel | Real socket + explicit hook usage across tests | proxy_kernel_hook.py + integration tests |
| Evidence Bundles + CLI | Exporter + make_event_summary + wired CLI tests | kernel_receipt_integration.py + evidence_exporter.py + tests |
| Semantic (advisory) + Formal | Shadow harness + eight formal checks + combined tests | shadow_mode_harness.py + test_shadow_mode_harness.py |

Gaps remain explicitly documented. No overclaims.
