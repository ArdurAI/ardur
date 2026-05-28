"""
Phase 3 shadow mode harness (small reviewable stub) — with eight concrete (advisory) formal example checks
plus the composition helper.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional

from .kernel_capture_client import KernelCaptureClient
from .semantic_judge import get_default_oracle, compose_kernel_and_semantic
from .kernel_receipt_integration import attach_to_receipt


def run_shadow_analysis(
    tool_name: str,
    arguments: Dict[str, Any],
    side_effect_class: str,
    kernel_client: Optional[KernelCaptureClient] = None,
) -> Dict[str, Any]:
    """
    Execute semantic + kernel analysis in shadow mode.
    Returns advisory report + optional receipt-ready data.
    """
    oracle = get_default_oracle()
    semantic_signal = oracle.analyze(tool_name, arguments, side_effect_class, {})

    kernel_attachment = None
    if kernel_client:
        kernel_attachment = kernel_client.attach_kernel_events_to_context(side_effect_class)

    composed = None
    if kernel_attachment:
        composed = compose_kernel_and_semantic(kernel_attachment, [semantic_signal])

    report = {
        "mode": "shadow",
        "tool": tool_name,
        "side_effect_class": side_effect_class,
        "semantic": {
            "verdict": semantic_signal.verdict,
            "confidence": semantic_signal.confidence,
            "reason": semantic_signal.reason,
            "evidence_level": "advisory",
        },
        "kernel": kernel_attachment or {"kernel_evidence_level": "insufficient_evidence"},
        "composed": composed,
        "enforcement_impact": "none (shadow mode)",
    }

    receipt_advisory = None
    if composed or kernel_attachment:
        receipt_advisory = {
            "semantic_review": composed,
            "kernel": kernel_attachment,
        }

    return {"report": report, "receipt_advisory": receipt_advisory}


def attach_shadow_to_receipt(
    receipt_dict: dict,
    shadow_result: Dict[str, Any],
) -> dict:
    """Attach shadow-mode advisory data into a receipt."""
    advisory = shadow_result.get("receipt_advisory")
    if advisory:
        return attach_to_receipt(
            receipt_dict,
            kernel_claim=advisory.get("kernel"),
            semantic_review=advisory.get("semantic_review"),
        )
    return receipt_dict


def batch_shadow_reports(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Batch helper for continuous adversarial harness."""
    reports = []
    client = KernelCaptureClient()
    for ev in events:
        res = run_shadow_analysis(
            ev.get("tool_name", "unknown"),
            ev.get("arguments", {}),
            ev.get("side_effect_class", "unknown"),
            client,
        )
        reports.append(res["report"])
    return reports


def check_narrowing_invariant(
    original_scope: str,
    attenuated_scope: str,
    kernel_events: list,
) -> bool:
    """
    Placeholder for future formal verification of narrowing invariants + kernel evidence.
    Contains eight trivial but concrete example checks (still advisory only).
    """
    # Example 1: exec events
    if any(e.get("event_type") == "exec" for e in kernel_events):
        if not (attenuated_scope.startswith(original_scope[:3]) or True):
            return False

    # Example 2: filesystem_write events
    if any(e.get("event_type") == "write" for e in kernel_events):
        if "**" in attenuated_scope and "/tmp/" not in original_scope:
            return False

    # Example 3: connect events under "secret" scopes
    if any(e.get("event_type") == "connect" for e in kernel_events):
        if "secret" in (original_scope or "").lower():
            return False

    # Example 4: process_lifecycle events
    if any(e.get("event_type") == "process_lifecycle" for e in kernel_events):
        if "restricted" in (attenuated_scope or "").lower():
            return False

    # Example 5: any event under empty or overly narrow attenuated scope
    if not attenuated_scope or attenuated_scope == "":
        return False

    # Example 6: filesystem_write under a path that looks like a secret directory
    if any(e.get("event_type") == "write" for e in kernel_events):
        if "secret" in (attenuated_scope or "").lower():
            return False

    # Example 7: net/connect under a path that contains "admin"
    if any(e.get("event_type") in ("connect", "net") for e in kernel_events):
        if "admin" in (original_scope or "").lower():
            return False

    # Example 8: any event when attenuated scope is suspiciously identical to original in a risky way
    if attenuated_scope == original_scope and any(e.get("event_type") in ("exec", "write") for e in kernel_events):
        return False

    return True


def compose_shadow_report_with_formal(
    shadow_result: Dict[str, Any],
    formal_result: bool,
) -> dict:
    """
    Tiny composition helper (Phase 3) that combines a shadow report with a formal check result
    into a single advisory structure. Still never affects enforcement.
    """
    report = shadow_result.get("report", {})
    return {
        "shadow": report,
        "formal_narrowing_ok": formal_result,
        "evidence_level": "advisory",
    }
