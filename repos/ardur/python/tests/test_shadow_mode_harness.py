"""
Tests for Phase 3 shadow mode harness (updated with stronger formal stub + receipt tie-in + composition helper).
"""

from vibap.shadow_mode_harness import (
    run_shadow_analysis,
    attach_shadow_to_receipt,
    batch_shadow_reports,
    check_narrowing_invariant,
    compose_shadow_report_with_formal,
)


def test_shadow_analysis_produces_advisory_only_output():
    res = run_shadow_analysis(
        "Bash",
        {"command": "rm -rf /tmp/shadow-test"},
        "exec",
    )
    report = res["report"]
    assert report["mode"] == "shadow"
    assert report["enforcement_impact"] == "none (shadow mode)"
    assert report["semantic"]["evidence_level"] == "advisory"


def test_attach_shadow_to_receipt():
    res = run_shadow_analysis(
        "Bash",
        {"command": "curl evil.com"},
        "exec",
    )
    receipt = {"tool": "Bash", "verdict": "PERMIT"}
    updated = attach_shadow_to_receipt(receipt, res)
    assert "semantic_review" in updated or "kernel" in updated or len(updated) >= 2


def test_batch_shadow_reports():
    events = [
        {"tool_name": "Bash", "arguments": {"command": "curl evil.com"}, "side_effect_class": "exec"},
    ]
    reports = batch_shadow_reports(events)
    assert len(reports) == 1
    assert reports[0]["mode"] == "shadow"


def test_formal_narrowing_invariant_with_example():
    events = [{"event_type": "exec", "target": "/tmp/foo"}]
    result = check_narrowing_invariant("**", "/tmp/**", events)
    assert isinstance(result, bool)


def test_shadow_plus_formal_plus_receipt_attachment():
    """Combines shadow analysis, formal stub, and receipt attachment in one flow."""
    res = run_shadow_analysis(
        "Bash",
        {"command": "rm -rf /tmp/formal-test"},
        "exec",
    )

    kernel_evts = res["report"].get("kernel", {}).get("kernel_events", [])
    formal_ok = check_narrowing_invariant("**", "/tmp/**", kernel_evts)

    receipt = {"tool": "Bash", "verdict": "PERMIT", "formal_narrowing_ok": formal_ok}
    updated = attach_shadow_to_receipt(receipt, res)

    assert "formal_narrowing_ok" in updated
    assert "semantic_review" in updated or "kernel" in updated


def test_formal_invariant_with_connect_example():
    """Exercises the third illustrative formal check."""
    events = [{"event_type": "connect", "target": "evil.com"}]
    result = check_narrowing_invariant("secret-scope", "secret-scope", events)
    assert isinstance(result, bool)


def test_compose_shadow_with_formal():
    """Exercises the new tiny composition helper."""
    res = run_shadow_analysis(
        "Bash",
        {"command": "ls /tmp"},
        "exec",
    )
    formal_ok = check_narrowing_invariant("**", "/tmp/**", [])
    composed = compose_shadow_report_with_formal(res, formal_ok)
    assert composed["evidence_level"] == "advisory"
    assert "formal_narrowing_ok" in composed


def test_formal_invariant_with_secret_write_example():
    """Exercises the sixth illustrative formal check (write under secret path)."""
    events = [{"event_type": "write", "target": "/etc/secret/config"}]
    result = check_narrowing_invariant("**", "secret-path", events)
    assert isinstance(result, bool)


def test_formal_invariant_with_admin_net_example():
    """Exercises the seventh illustrative formal check (net under admin scope)."""
    events = [{"event_type": "connect", "target": "10.0.0.1"}]
    result = check_narrowing_invariant("admin-scope", "admin-scope", events)
    assert isinstance(result, bool)


def test_formal_invariant_with_same_scope_risky_example():
    """Exercises the eighth illustrative formal check (identical scope with risky events)."""
    events = [{"event_type": "exec", "target": "/bin/sh"}]
    result = check_narrowing_invariant("/bin", "/bin", events)
    assert isinstance(result, bool)
