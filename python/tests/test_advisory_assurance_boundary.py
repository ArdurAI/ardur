"""Regression coverage for advisory AI-control assurance boundaries."""

from __future__ import annotations

from pathlib import Path

from vibap.behavioral_fingerprint import (
    CanaryPool,
    FingerprintVerdict,
    enforce_fingerprint,
    make_challenge,
)
from vibap.semantic_judge import JudgeRequest, NullJudge, judge_from_env


REPO_ROOT = Path(__file__).resolve().parents[2]
REFERENCE_PATH = REPO_ROOT / "docs" / "reference" / "advisory-ai-controls.md"
PROXY_PATH = REPO_ROOT / "python" / "vibap" / "proxy.py"


class _UnsureChallenger:
    def run(self, challenges):  # noqa: ANN001
        return FingerprintVerdict(
            verdict="UNSURE",
            total_count=len(challenges),
            reason="provider unavailable",
            fingerprint_version="test",
        )


def test_behavioral_fingerprint_default_allows_unsure_with_diagnostic() -> None:
    """The omitted policy argument must remain visibly fail-open."""

    pool = CanaryPool(challenges=[make_challenge("q", "a", pool_tag="test")])
    verdict = enforce_fingerprint(pool, _UnsureChallenger())

    assert verdict.verdict == "OK"
    assert "policy=fail_open" in verdict.reason
    assert "raw=UNSURE" in verdict.reason


def test_semantic_judge_default_is_advisory_unsure(monkeypatch) -> None:
    """An unset provider gate selects the no-op advisor, not a permit."""

    monkeypatch.delenv("ARDUR_SEMANTIC_JUDGE", raising=False)
    judge = judge_from_env()
    assert isinstance(judge, NullJudge)

    verdict = judge.evaluate(
        JudgeRequest(
            mission="summarize the report",
            tool_name="read_file",
            arguments={"path": "report.txt"},
            allowed_tools=["read_file"],
            forbidden_tools=[],
            resource_scope=["report.txt"],
        )
    )
    assert verdict.verdict == "UNSURE"
    assert verdict.reason == "null judge"


def test_advisory_modules_are_not_authoritative_proxy_dependencies() -> None:
    """If production proxy wiring is added, its assurance docs must be revisited."""

    proxy_source = PROXY_PATH.read_text(encoding="utf-8")
    assert "semantic_judge" not in proxy_source
    assert "behavioral_fingerprint" not in proxy_source


def test_public_reference_states_advisory_failure_and_authority_boundaries() -> None:
    """Operator docs must make the prototype boundary impossible to miss."""

    reference = " ".join(REFERENCE_PATH.read_text(encoding="utf-8").split())
    required_phrases = (
        "not wired into `python/vibap/proxy.py`",
        "not an authoritative governance verdict",
        "`UNSURE`",
        '`policy="fail_closed"`',
        "availability trade-off",
        "provider API cost",
    )
    for phrase in required_phrases:
        assert phrase in reference
