"""
Phase 1 wiring hook for proxy.py (small, reviewable delta) — further cleaned for production use.

This is the exact minimal surface that should be called from the high-risk
branch in GovernanceSession.check_and_record after the small wiring delta
we applied to proxy.py.
"""

from __future__ import annotations
from typing import Any

def enrich_high_risk_event(
    event: Any,
    kernel_client: Any,
    side_effect_class: str,
) -> dict:
    """
    Single call site for the wired high-risk path.
    Returns enrichment dict containing kernel_claim and/or semantic_review (advisory).
    """
    from .kernel_receipt_integration import enrich_policy_event_with_kernel_and_semantic
    return enrich_policy_event_with_kernel_and_semantic(event, kernel_client, side_effect_class)
