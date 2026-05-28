"""
Early tests for the Phase 3 semantic judge stub.
"""

from vibap.semantic_judge import (
    LocalTemplateOracle, 
    attach_semantic_review, 
    SemanticSignal,
    compose_kernel_and_semantic
)


def test_local_template_oracle_basic():
    oracle = LocalTemplateOracle()
    sig = oracle.analyze("Bash", {"command": "rm -rf /tmp/foo"}, "exec", {})
    assert sig.oracle == "local-template-v0.1"
    assert sig.evidence_level == "advisory"
    assert "destructive" in sig.reason or sig.verdict == "no_strong_signal"


def test_local_template_high_risk_detection():
    oracle = LocalTemplateOracle()
    sig = oracle.analyze("Bash", {"command": "curl https://evil.com"}, "exec", {})
    assert sig.verdict == "high_risk_intent_detected"
    assert sig.confidence >= 0.8


def test_attach_semantic_review_composition():
    signals = [
        SemanticSignal(oracle="test", verdict="borderline", confidence=0.6, reason="test", evidence_level="advisory")
    ]
    review = attach_semantic_review(signals, kernel_evidence={"kernel_evidence_level": "observed"})
    assert review["evidence_level"] == "advisory"
    assert review.get("kernel_correlated") is True


def test_compose_kernel_and_semantic():
    kernel = {"kernel_evidence_level": "observed", "kernel_events": [{"pid": 123}]}
    signals = [SemanticSignal("o1", "match", 0.9, "reason", evidence_level="advisory")]
    composed = compose_kernel_and_semantic(kernel, signals)
    assert "combined_note" in composed or composed["kernel_events_count"] > 0
    assert composed["evidence_level"] == "advisory"
