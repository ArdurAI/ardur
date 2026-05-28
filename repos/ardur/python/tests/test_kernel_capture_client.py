"""
Basic tests for the kernel capture client stub (Phase 1 foundation).

These tests validate the interface and dataclass even while the real
daemon integration is under development.
"""

import pytest

from vibap.kernel_capture_client import KernelCaptureClient, KernelEvent


def test_kernel_event_dataclass():
    event = KernelEvent(
        event_type="exec",
        pid=1234,
        comm="bash",
        args=["-c", "echo hello"],
        target="/bin/bash",
    )
    assert event.event_type == "exec"
    assert event.pid == 1234


def test_kernel_capture_client_interface():
    client = KernelCaptureClient()
    assert hasattr(client, "connect")
    assert hasattr(client, "register_session")
    assert hasattr(client, "on_event")
    assert hasattr(client, "start")
    assert hasattr(client, "close")
    assert hasattr(client, "build_kernel_claim")


def test_kernel_capture_client_graceful_without_daemon():
    client = KernelCaptureClient(socket_path="/tmp/nonexistent_ardur_kernel.sock")
    client.connect()
    client.register_session("trace-xyz", "run-abc")
    client.close()
    assert not client._connected


def test_kernel_event_for_high_risk_side_effect():
    event = KernelEvent(
        event_type="exec",
        pid=4242,
        comm="bash",
        args=["-c", "curl https://evil.example.com"],
        target="curl",
    )
    assert event.event_type == "exec"
    assert "curl" in str(event.args)


def test_full_high_risk_path_with_kernel_data():
    client = KernelCaptureClient()
    trace = "trace-test-001"
    nonce = "nonce-xyz"

    client.register_session(trace, nonce)
    client.inject_event(KernelEvent(event_type="exec", pid=7777, comm="bash", target="/bin/bash"))

    attachment = client.attach_kernel_events_to_context("exec", "/bin/bash")
    assert attachment["kernel_evidence_level"] == "observed"
    assert len(attachment["kernel_events"]) == 1
    assert attachment["kernel_events"][0]["pid"] == 7777

    claim = client.build_kernel_claim("exec")
    assert claim is not None
    assert claim["evidence_level"] == "observed"

    client.clear_injected_events()


def test_simulate_receive_and_attachment():
    client = KernelCaptureClient()
    client.register_session("trace-sim", "nonce-sim")
    client.simulate_receive(KernelEvent(event_type="exec", pid=5555, comm="bash"))

    attachment = client.attach_kernel_events_to_context("exec")
    assert attachment["kernel_evidence_level"] == "observed"
    assert len(attachment["kernel_events"]) == 1

    client.clear_injected_events()


def test_send_registration_and_real_path_sketch():
    client = KernelCaptureClient()
    client.register_session("trace-reg-001", "nonce-001")

    msg = client.send_registration()
    assert msg is not None
    assert msg["type"] == "register"
    assert msg["trace_id"] == "trace-reg-001"


def test_events_only_returned_for_registered_sessions():
    client = KernelCaptureClient()
    client.inject_event(KernelEvent(event_type="exec", pid=1234))

    assert client.get_events_for_side_effect("exec") == []

    client.register_session("trace-filter", "nonce-1")
    events = client.get_events_for_side_effect("exec")
    assert len(events) == 1

    client.clear_injected_events()


def test_build_kernel_claim_insufficient_evidence():
    client = KernelCaptureClient()
    client.register_session("trace-no-events", "nonce-x")
    claim = client.build_kernel_claim("exec")
    assert claim is None  # no events injected


def test_e2e_high_risk_session_with_kernel_data_and_receipt(monkeypatch):
    """True end-to-end stub test for high-risk path + kernel + receipt claim."""
    from vibap import proxy as proxy_mod

    client = KernelCaptureClient()
    trace_id = "trace-e2e-kernel-receipt-001"
    run_nonce = "nonce-e2e-kernel-001"

    client.register_session(trace_id, run_nonce)
    client.inject_event(KernelEvent(
        event_type="exec",
        pid=42424,
        comm="bash",
        args=["-c", "rm -rf /tmp/test-ardur"],
        target="/tmp/test-ardur",
    ))

    monkeypatch.setattr(proxy_mod, "KernelCaptureClient", lambda *a, **k: client)

    session = proxy_mod.GovernanceSession(
        jti=trace_id,
        run_nonce=run_nonce,
        kernel_client=client,
    )

    decision, reason, event = session.check_and_record(
        actor="test-agent",
        verifier_id="test-verifier",
        tool_name="Bash",
        arguments={"command": "rm -rf /tmp/test-ardur"},
        action_class="exec",
        target="/tmp/test-ardur",
        resource_family="filesystem",
    )

    assert event is not None
    assert event.evidence_proof_ref is not None
    assert "kernel" in event.evidence_proof_ref
    kdata = event.evidence_proof_ref["kernel"]
    assert kdata["kernel_evidence_level"] == "observed"

    # Test the new build_kernel_claim helper
    claim = client.build_kernel_claim("exec")
    assert claim is not None
    assert claim["count"] > 0

    client.clear_injected_events()
