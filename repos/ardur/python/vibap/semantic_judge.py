"""
Semantic Review / Oracle stub (Phase 3 early work).

Provides a pluggable interface for semantic/behavioral signals that can be
attached to receipts in an advisory capacity only.

Guardrails (enforced):
- Never mutates the structural Decision (PERMIT/DENY).
- Output always carries explicit `evidence_level: "advisory"`.
- Shadow/audit mode is the default: signals are computed but not used for enforcement.
- Composition with kernel evidence is supported for richer advisory notes only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, Optional


@dataclass
class SemanticSignal:
    oracle: str
    verdict: str
    confidence: float
    reason: str
    latency_ms: int | None = None
    evidence_level: str = "advisory"


class SemanticOracle(Protocol):
    def analyze(self, tool_name: str, arguments: dict, side_effect_class: str, context: dict) -> SemanticSignal: ...


class LocalTemplateOracle:
    """
    Deterministic, local, template-based oracle for testing and shadow mode.
    Never reaches out to external LLMs.
    Now also consults the Ardur plugin registry for additional semantic oracles (item #6).
    """

    name = "local-template-v0.1"

    def analyze(self, tool_name: str, arguments: dict, side_effect_class: str, context: dict) -> SemanticSignal:
        # Extremely simple heuristic for early integration / tests.
        # Real version will use deterministic templates + behavioral fingerprints.
        cmd = str(arguments.get("command", "")) if isinstance(arguments, dict) else ""
        if side_effect_class in ("exec", "process_launch") and ("rm -rf" in cmd or "curl" in cmd):
            return SemanticSignal(
                oracle=self.name,
                verdict="high_risk_intent_detected",
                confidence=0.85,
                reason="Command contains destructive or exfil pattern; matches high-risk template",
                latency_ms=0,
            )
        if side_effect_class == "filesystem_write" and "secret" in cmd.lower():
            return SemanticSignal(
                oracle=self.name,
                verdict="potential_credential_exposure",
                confidence=0.6,
                reason="Write operation targeting likely sensitive path",
                latency_ms=0,
            )
        return SemanticSignal(
            oracle=self.name,
            verdict="no_strong_signal",
            confidence=0.3,
            reason="No strong match against current local templates",
            latency_ms=0,
        )


def get_default_oracle() -> SemanticOracle:
    return LocalTemplateOracle()


def get_plugin_enhanced_oracles() -> list[SemanticOracle]:
    """
    Returns the default oracle plus any oracles contributed by registered Ardur plugins (item #6).
    This is the real extension point for the plugin ecosystem.
    """
    oracles = [LocalTemplateOracle()]
    try:
        from plugins.registry import registry
        for name, plugin in getattr(registry, "_plugins", {}).items():
            # Support both plugin.oracle_factory and direct .oracle on the instance
            if hasattr(plugin, "oracle_factory"):
                try:
                    oracles.append(plugin.oracle_factory())
                except Exception:
                    pass
            elif hasattr(plugin, "oracle"):
                oracles.append(plugin.oracle)
            # Also support plugins that attached oracle_factory directly to the plugin object
            if hasattr(plugin, "oracle_factory"):
                try:
                    candidate = plugin.oracle_factory()
                    if candidate not in oracles:
                        oracles.append(candidate)
                except Exception:
                    pass
    except Exception:
        pass  # plugins are optional
    return oracles


def attach_semantic_review(
    signals: list[SemanticSignal],
    kernel_evidence: Optional[dict] = None,
) -> dict:
    """
    Compose semantic + kernel signals into the advisory structure for receipts.
    Never upgrades structural evidence_level. This is for auditor visibility only.

    Now automatically pulls from plugin-enhanced oracles when no explicit signals are passed (item #6 live hook).
    """
    if not signals:
        # Exercise the real plugin extension point
        try:
            oracles = get_plugin_enhanced_oracles()
            signals = []
            for o in oracles:
                if hasattr(o, "analyze"):
                    try:
                        sig = o.analyze("unknown", {}, "other", {})
                        signals.append(sig)
                    except Exception:
                        pass
        except Exception:
            pass

    combined = {
        "version": "0.1",
        "signals": [
            {
                "oracle": s.oracle,
                "verdict": s.verdict,
                "confidence": s.confidence,
                "reason": s.reason,
                "evidence_level": s.evidence_level,
            }
            for s in signals
        ],
        "evidence_level": "advisory",
        "plugin_oracles_used": len(get_plugin_enhanced_oracles()),
        "signals_from_plugins": len([s for s in signals if "plugin" in s.oracle.lower() or "risk" in s.oracle.lower()]),
    }
    if kernel_evidence and kernel_evidence.get("kernel_evidence_level") == "observed":
        combined["kernel_correlated"] = True
        combined["combined_note"] = "Kernel events observed for same action; semantic signal provides intent context (advisory only)"
    return combined


def compose_kernel_and_semantic(
    kernel_attachment: dict,
    semantic_signals: list[SemanticSignal]
) -> dict:
    """
    Explicit composition helper for Phase 3.
    Returns a dict suitable for evidence_proof_ref or semantic_review section.
    """
    review = attach_semantic_review(semantic_signals, kernel_evidence=kernel_attachment)
    review["kernel_events_count"] = len(kernel_attachment.get("kernel_events", [])) if kernel_attachment else 0
    return review
