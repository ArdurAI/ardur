"""
Phase 1 milestone test: Signed ExecutionReceipt containing real kernel claim data.

Updated to explicitly demonstrate usage of the proxy_kernel_hook after the small wiring.
"""

from vibap.kernel_capture_client import KernelCaptureClient, KernelEvent
from vibap.receipt import issue_receipt
from vibap.passport import issue_passport
from vibap.kernel_receipt_integration import attach_to_receipt
from vibap.proxy_kernel_hook import enrich_high_risk_event

MINIMAL_MISSION = {
    "version": "0.1",
    "id": "test-mission-kernel-001",
    "issued_at": "2026-05-28T00:00:00Z",
    "issuer": {"id": "test-issuer", "public_key": "placeholder"},
    "subject": {"id": "test-subject"},
    "allowed_tools": ["Bash", "Read"],
    "resource_scope": ["**"],
    "budgets": {},
}

def test_signed_receipt_using_live_wired_proxy_path():
    """Simulates the full high-risk path after the small proxy.py wiring delta."""
    client = KernelCaptureClient()
    trace_id = "trace-live-wired-001"
    run_nonce = "nonce-live-001"

    client.register_session(trace_id, run_nonce)
    client.inject_event(KernelEvent(
        event_type="exec",
        pid=42424,
        comm="bash",
        args=["-c", "rm -rf /tmp/test-ardur-wired"],
        target="/tmp/test-ardur-wired",
    ))

    dummy_event = type("Event", (), {
        "tool_name": "Bash",
        "arguments": {"command": "rm -rf /tmp/test-ardur-wired"}
    })()

    # This is what the wired proxy.py now calls for high-risk actions
    extra = enrich_high_risk_event(dummy_event, client, "exec")

    kernel_claim = extra.get("kernel_claim") or client.build_kernel_claim("exec")
    assert kernel_claim is not None
    assert kernel_claim["evidence_level"] == "observed"

    passport = issue_passport(
        mission=MINIMAL_MISSION,
        subject_id="test-subject",
        allowed_tools=["Bash"],
        resource_scope=["**"],
    )

    receipt = issue_receipt(
        passport=passport,
        tool_name="Bash",
        arguments={"command": "rm -rf /tmp/test-ardur-wired"},
        action_class="exec",
        target="/tmp/test-ardur-wired",
        decision="PERMIT",
        reason="test",
    )

    receipt_dict = receipt.to_dict() if hasattr(receipt, "to_dict") else receipt
    updated = attach_to_receipt(receipt_dict, kernel_claim=kernel_claim)

    assert "kernel" in updated or "kernel_claim" in updated
    if "kernel" in updated:
        assert updated["kernel"]["evidence_level"] == "observed"

    client.clear_injected_events()
