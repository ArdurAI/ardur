"""
Phase 1/2/3 integration helpers (small reviewable module).

Central bridge used by proxy, receipt issuance, exporter, and shadow mode.

This version adds a small helper `make_event_summary` that turns a single high-risk
event dict into a minimal receipt summary. Useful for quick one-off chains in tests
and CLI examples (Phase 2 usability).
"""

from __future__ import annotations
from typing import Any, Optional, Dict, List

from .kernel_capture_client import KernelCaptureClient
from .semantic_judge import get_default_oracle, compose_kernel_and_semantic
from .evidence_exporter import export_evidence_bundle


def enrich_policy_event_with_kernel_and_semantic(
    policy_event: Any,
    kernel_client: Optional[KernelCaptureClient] = None,
    side_effect_class: str = "",
) -> dict:
    """
    Enrich a PolicyEvent with kernel data and advisory semantic signals.
    Called from the wired high-risk path in proxy.py.
    """
    kernel_attachment = None
    kernel_claim = None
    if kernel_client and side_effect_class:
        kernel_attachment = kernel_client.attach_kernel_events_to_context(side_effect_class)
        kernel_claim = kernel_client.build_kernel_claim(side_effect_class)

    oracle = get_default_oracle()
    semantic_signal = oracle.analyze(
        tool_name=getattr(policy_event, "tool_name", "unknown"),
        arguments=getattr(policy_event, "arguments", {}),
        side_effect_class=side_effect_class,
        context={},
    )

    semantic_composed = None
    if kernel_attachment:
        semantic_composed = compose_kernel_and_semantic(kernel_attachment, [semantic_signal])

    enrichment = {}
    if kernel_attachment:
        enrichment["kernel"] = kernel_attachment
    if kernel_claim:
        enrichment["kernel_claim"] = kernel_claim
    if semantic_composed:
        enrichment["semantic_review"] = semantic_composed

    return enrichment


def attach_to_receipt(
    receipt_dict: dict,
    kernel_claim: Optional[dict] = None,
    semantic_review: Optional[dict] = None,
) -> dict:
    """Helper for receipt.py to attach kernel claim and/or semantic review cleanly."""
    if kernel_claim:
        receipt_dict["kernel"] = kernel_claim
    if semantic_review:
        receipt_dict["semantic_review"] = semantic_review
    return receipt_dict


def make_receipt_summary(receipt_dict: dict) -> dict:
    """
    Lightweight summary helper for receipt chains in evidence bundles (Phase 2).
    Produces a minimal dict suitable for the receipt_chain field.
    """
    return {
        "receipt_id": receipt_dict.get("receipt_id") or receipt_dict.get("jti"),
        "verdict": receipt_dict.get("verdict") or receipt_dict.get("decision"),
        "side_effect_class": receipt_dict.get("side_effect_class"),
        "has_kernel": bool(receipt_dict.get("kernel") or receipt_dict.get("kernel_claim")),
        "has_semantic": bool(receipt_dict.get("semantic_review")),
    }


def build_receipt_summaries(receipts: List[dict]) -> List[dict]:
    """
    Convenience helper (Phase 2) that takes a list of receipt dicts and returns
    a list of summaries ready for receipt_chain in bundles.
    """
    return [make_receipt_summary(r) for r in receipts]


def summarize_receipts(receipts: List[dict]) -> List[dict]:
    """
    Even smaller alias for build_receipt_summaries (Phase 2 usability).
    Preferred in quick tests and CLI examples.
    """
    return build_receipt_summaries(receipts)


def summarize_receipts_from_events(events: List[dict]) -> List[dict]:
    """
    Phase 2 convenience: given a list of high-risk event dicts
    (with at least "tool_name" and "side_effect_class"), produce
    minimal receipt summaries that can be used for receipt_chain.
    This makes it easy to build example chains in tests without
    constructing full receipt objects.
    """
    summaries = []
    for ev in events:
        summaries.append({
            "receipt_id": f"rec-{len(summaries)+1}",
            "verdict": "PERMIT",
            "side_effect_class": ev.get("side_effect_class", "unknown"),
            "has_kernel": False,
            "has_semantic": False,
        })
    return summaries


def make_event_summary(event: dict) -> dict:
    """
    Phase 2 tiny helper: turn a single high-risk event dict into one
    minimal receipt summary. Complements summarize_receipts_from_events
    for one-off cases.
    """
    return {
        "receipt_id": event.get("receipt_id", "rec-1"),
        "verdict": event.get("verdict", "PERMIT"),
        "side_effect_class": event.get("side_effect_class", "unknown"),
        "has_kernel": event.get("has_kernel", False),
        "has_semantic": event.get("has_semantic", False),
    }


def export_session_evidence(
    session_jti: str,
    kernel_client: Optional[KernelCaptureClient] = None,
    side_effect_class: str = "",
    output_path: Optional[str] = None,
    receipt_chain: Optional[List[dict]] = None,
) -> dict:
    """
    End-to-end helper used by CLI and tests.
    Accepts pre-built receipt_chain (or summaries via the caller).
    """
    enrichment = {}
    kernel_data = None
    if kernel_client and side_effect_class:
        kernel_data = kernel_client.attach_kernel_events_to_context(side_effect_class)
        enrichment = enrich_policy_event_with_kernel_and_semantic(
            type("DummyEvent", (), {"tool_name": "Bash", "arguments": {}})(),
            kernel_client,
            side_effect_class,
        )

    semantic_data = enrichment.get("semantic_review") if enrichment else None

    return export_evidence_bundle(
        session_jti,
        output_path=output_path,
        include_kernel=bool(kernel_data),
        include_semantic=bool(semantic_data),
        kernel_data=kernel_data,
        semantic_data=semantic_data,
        receipt_chain=receipt_chain or [],
    )
