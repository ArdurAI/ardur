# NOTE: This is a minimal, targeted edit for Phase 1 kernel integration wiring.
# The change below is the exact small delta to insert after the existing
# high-risk kernel attachment block (search for "Phase 1: Attach kernel evidence").

# Add this import near the top with other Phase 1 imports:
# from .proxy_kernel_hook import enrich_high_risk_event

# Then, inside GovernanceSession.check_and_record, right after the existing
# kernel attachment logic (after setting evidence_proof_ref for kernel),
# add this single call for high-risk side effects:

# === BEGIN SMALL WIRING DELTA (Phase 1) ===
if self.kernel_client and sec in {"exec", "process_launch", "filesystem_write"}:
    extra = enrich_high_risk_event(event, self.kernel_client, sec)
    # extra now contains 'kernel_claim' and/or 'semantic_review' (advisory)
    # These are picked up by attach_to_receipt during receipt issuance.
# === END SMALL WIRING DELTA ===

# The rest of the original proxy.py is unchanged.
# This keeps the diff to one import + 4 lines in the high-risk path.
