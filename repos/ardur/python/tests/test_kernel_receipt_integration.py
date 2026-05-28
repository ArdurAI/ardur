"""
Tests for the Phase 1/2/3 integration helpers (updated with make_event_summary).
"""

from vibap.kernel_capture_client import KernelCaptureClient, KernelEvent
from vibap.kernel_receipt_integration import (
    enrich_policy_event_with_kernel_and_semantic,
    attach_to_receipt,
    make_receipt_summary,
    build_receipt_summaries,
    summarize_receipts,
    summarize_receipts_from_events,
    make_event_summary,
    export_session_evidence,
)


def test_enrich_and_attach_to_receipt():
    client = KernelCaptureClient()
    client.register_session("trace-int-attach-001", "n1")
    client.inject_event(KernelEvent(event_type="exec", pid=999, comm="bash", target="/tmp/danger"))

    dummy_event = type("Event", (), {"tool_name": "Bash", "arguments": {"command": "rm -rf /tmp/danger"}})()

    enrichment = enrich_policy_event_with_kernel_and_semantic(dummy_event, client, "exec")
    receipt = {"tool": "Bash", "verdict": "PERMIT"}

    updated = attach_to_receipt(
        receipt,
        kernel_claim=enrichment.get("kernel_claim"),
        semantic_review=enrichment.get("semantic_review"),
    )

    assert "kernel_claim" in updated or "kernel" in updated or len(updated) > 2


def test_make_event_summary():
    """Uses the new single-event helper (Phase 2 usability)."""
    event = {"tool_name": "Bash", "side_effect_class": "exec"}
    summary = make_event_summary(event)

    assert summary["side_effect_class"] == "exec"
    assert summary["verdict"] == "PERMIT"

    chain = [summary, summarize_receipts_from_events([{"side_effect_class": "filesystem_write"}])[0]]

    bundle = export_session_evidence(
        "trace-event-001",
        receipt_chain=chain,
    )
    assert bundle["ardur_evidence_bundle_version"] == "0.1"
    assert len(bundle.get("session", {}).get("receipt_chain", [])) == 2


def test_export_session_evidence_with_real_client_path():
    client = KernelCaptureClient()
    client.register_session("trace-exp-001", "n2")
    client.inject_event(KernelEvent(event_type="exec", pid=888, comm="bash"))

    bundle = export_session_evidence("trace-exp-001", client, "exec")

    assert bundle["ardur_evidence_bundle_version"] == "0.1"
    assert "kernel" in bundle
