# Known Limitations

**2026-05-28 Update (sustained parallel waves)**:
- make_event_summary helper added for single-event summaries.
- proxy_kernel_hook enhanced and used explicitly.
- Formal stub now has eight concrete (still advisory) example checks.
- Combined shadow + formal + receipt tests exist.

## Kernel sensor
- Real AF_UNIX socket with graceful degradation.
- Full bidirectional attested daemon + eBPF still pending.

## Semantic / Shadow / Formal
- All semantic and formal work remains strictly advisory.
- The formal stub contains only simple illustrative checks (now eight examples).

## Receipt evidence
- Integration helpers + wiring make the path to full live proxy + receipt issuance clear.
- Receipt chain and summary helpers (including the new single-event helper) are lightweight but now more convenient and tested.

Bootstrap script patched. Attempted every wave.

All material changes recorded here and in coverage-map.md with evidence.
