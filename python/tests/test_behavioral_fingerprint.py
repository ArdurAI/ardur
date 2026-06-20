"""Unit tests for vibap.behavioral_fingerprint (Direction 1).

Exercises the Challenger Protocol + NullChallenger + AnthropicChallenger
(with a mocked Anthropic client) + CanaryPool + enforce_fingerprint
policy evaluation. No real network calls — AnthropicChallenger tests
inject a mock client.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from vibap.behavioral_fingerprint import (
    AnthropicChallenger,
    BehavioralChallenger,
    CanaryPool,
    ChallengeResponse,
    FingerprintVerdict,
    NullChallenger,
    _hash_answer,
    enforce_fingerprint,
    is_fingerprint_active,
    make_challenge,
)


@pytest.fixture(autouse=True)
def _anthropic_model_for_tests(monkeypatch):
    """Auto-set ANTHROPIC_MODEL for every test in this module.

    AnthropicChallenger requires a model id at construction time (no
    hard-coded default). Tests don't actually call the real API — they
    inject a mock client — but the constructor still needs *some* model
    id to satisfy the contract. Tests that want to assert the
    no-model-id failure path explicitly delenv inside their own scope.
    """
    monkeypatch.setenv("ANTHROPIC_MODEL", "test-model-id")


# --------------------------------------------------------------------------
# Protocol / runtime-checkable
# --------------------------------------------------------------------------


def test_null_challenger_satisfies_protocol() -> None:
    assert isinstance(NullChallenger(), BehavioralChallenger)


def test_null_challenger_returns_ok_without_network() -> None:
    pool = CanaryPool(challenges=[make_challenge("q", "a", pool_tag="test")])
    challenges = pool.draw(1, seed=0)
    verdict = NullChallenger().run(challenges)
    assert verdict.verdict == "OK"
    assert verdict.fingerprint_version == "null"
    assert verdict.responses == []


# --------------------------------------------------------------------------
# Hashing + normalization
# --------------------------------------------------------------------------


def test_hash_answer_is_case_insensitive() -> None:
    assert _hash_answer("Hello") == _hash_answer("hello")
    assert _hash_answer("HELLO") == _hash_answer("hello")


def test_hash_answer_normalizes_whitespace() -> None:
    assert _hash_answer("hello world") == _hash_answer("  hello  world  ")
    assert _hash_answer("hello world") == _hash_answer("hello\tworld")
    assert _hash_answer("hello world") == _hash_answer("hello\n\nworld")


def test_hash_answer_distinguishes_different_content() -> None:
    assert _hash_answer("yes") != _hash_answer("no")
    assert _hash_answer("three") != _hash_answer("four")


# --------------------------------------------------------------------------
# Challenge factory
# --------------------------------------------------------------------------


def test_make_challenge_computes_stable_hash() -> None:
    c1 = make_challenge("What is 2+2?", "four", pool_tag="arithmetic")
    c2 = make_challenge("What is 2+2?", "four", pool_tag="arithmetic")
    assert c1.expected_answer_hash == c2.expected_answer_hash
    assert c1.challenge_id == c2.challenge_id


def test_make_challenge_preview_is_truncated() -> None:
    long_answer = "x" * 200
    c = make_challenge("prompt", long_answer, pool_tag="t")
    assert len(c.expected_answer_preview) <= 67  # 64 + "..." truncation marker


def test_make_challenge_preview_preserves_short_answers() -> None:
    c = make_challenge("prompt", "brief", pool_tag="t")
    assert c.expected_answer_preview == "brief"
    assert not c.expected_answer_preview.endswith("...")


# --------------------------------------------------------------------------
# CanaryPool.draw
# --------------------------------------------------------------------------


def test_pool_draw_covers_every_tag_when_n_equals_tag_count() -> None:
    """If the pool has 3 tags and we draw 3, every tag appears exactly once."""
    pool = CanaryPool(challenges=[
        make_challenge("a1", "x", pool_tag="refusal"),
        make_challenge("a2", "y", pool_tag="refusal"),
        make_challenge("b1", "z", pool_tag="arithmetic"),
        make_challenge("b2", "z2", pool_tag="arithmetic"),
        make_challenge("c1", "w", pool_tag="classification"),
    ])
    picked = pool.draw(3, seed=0)
    assert len(picked) == 3
    tags = {c.pool_tag for c in picked}
    assert tags == {"refusal", "arithmetic", "classification"}


def test_pool_draw_returns_empty_for_zero() -> None:
    pool = CanaryPool(challenges=[make_challenge("q", "a", pool_tag="t")])
    assert pool.draw(0) == []


def test_pool_draw_returns_full_pool_when_n_exceeds_size() -> None:
    pool = CanaryPool(challenges=[
        make_challenge("q1", "a", pool_tag="t"),
        make_challenge("q2", "b", pool_tag="t"),
    ])
    picked = pool.draw(10, seed=0)
    assert len(picked) == 2


def test_pool_draw_seed_produces_deterministic_order() -> None:
    pool = CanaryPool(challenges=[
        make_challenge(f"q{i}", f"a{i}", pool_tag=f"tag{i % 3}")
        for i in range(9)
    ])
    first = pool.draw(3, seed=42)
    second = pool.draw(3, seed=42)
    assert [c.challenge_id for c in first] == [c.challenge_id for c in second]


# --------------------------------------------------------------------------
# AnthropicChallenger — constructor env-gating
# --------------------------------------------------------------------------


def test_anthropic_challenger_refuses_construction_without_env(monkeypatch) -> None:
    monkeypatch.delenv("ARDUR_BEHAVIORAL_FINGERPRINT", raising=False)
    with pytest.raises(RuntimeError, match="ARDUR_BEHAVIORAL_FINGERPRINT"):
        AnthropicChallenger()


def test_anthropic_challenger_refuses_wrong_env_value(monkeypatch) -> None:
    monkeypatch.setenv("ARDUR_BEHAVIORAL_FINGERPRINT", "disabled")
    with pytest.raises(RuntimeError):
        AnthropicChallenger()


def test_anthropic_challenger_accepts_activation_value(monkeypatch) -> None:
    monkeypatch.setenv("ARDUR_BEHAVIORAL_FINGERPRINT", "anthropic")
    monkeypatch.setenv("ANTHROPIC_MODEL", "test-model-id")
    c = AnthropicChallenger(anthropic_client=Mock())
    # Model id comes from the env var; no specific model name is hard-coded.
    assert c.model == "test-model-id"
    assert len(c._version) == 12  # sha256[:12]


def test_anthropic_challenger_requires_model_id(monkeypatch) -> None:
    monkeypatch.setenv("ARDUR_BEHAVIORAL_FINGERPRINT", "anthropic")
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
    with pytest.raises(RuntimeError, match="requires a model id"):
        AnthropicChallenger(anthropic_client=Mock())


# --------------------------------------------------------------------------
# AnthropicChallenger — run-path with mocked client
# --------------------------------------------------------------------------


def _mock_anthropic_client_returning(text: str) -> Mock:
    """Build a mock that mimics anthropic.Anthropic().messages.create's
    response shape: an object with .content = [objects with .text = <txt>]."""
    mock_client = Mock()
    mock_client.messages.create.return_value = SimpleNamespace(
        content=[SimpleNamespace(text=text)],
    )
    return mock_client


def test_challenger_run_hashes_responses_and_matches(monkeypatch) -> None:
    monkeypatch.setenv("ARDUR_BEHAVIORAL_FINGERPRINT", "anthropic")
    # Two challenges, both expected to say "four"
    challenges = [
        make_challenge("What is 2+2?", "four", pool_tag="arithmetic"),
        make_challenge("How many sides does a square have?", "four", pool_tag="arithmetic"),
    ]
    c = AnthropicChallenger(anthropic_client=_mock_anthropic_client_returning("four"))
    verdict = c.run(challenges)
    assert verdict.verdict == "OK"
    assert verdict.matched_count == 2
    assert verdict.total_count == 2
    for resp in verdict.responses:
        assert resp.matched
        assert resp.answer_hash == _hash_answer("four")


def test_challenger_run_fails_when_answers_mismatch(monkeypatch) -> None:
    monkeypatch.setenv("ARDUR_BEHAVIORAL_FINGERPRINT", "anthropic")
    challenges = [
        make_challenge("What is 2+2?", "four", pool_tag="arithmetic"),
        make_challenge("What is 3+1?", "four", pool_tag="arithmetic"),
    ]
    # Jailbroken model returns something completely different
    c = AnthropicChallenger(
        anthropic_client=_mock_anthropic_client_returning("banana")
    )
    verdict = c.run(challenges)
    assert verdict.verdict == "FAIL"
    assert verdict.matched_count == 0
    assert verdict.total_count == 2


def test_challenger_is_case_and_whitespace_tolerant(monkeypatch) -> None:
    monkeypatch.setenv("ARDUR_BEHAVIORAL_FINGERPRINT", "anthropic")
    challenges = [make_challenge("q", "four", pool_tag="arithmetic")]
    # Response has different case + trailing whitespace + markdown asterisks
    # stripping isn't applied, but normalization handles case and whitespace.
    c = AnthropicChallenger(
        anthropic_client=_mock_anthropic_client_returning("  FOUR\n")
    )
    verdict = c.run(challenges)
    assert verdict.matched_count == 1


def test_challenger_returns_unsure_on_api_error(monkeypatch) -> None:
    monkeypatch.setenv("ARDUR_BEHAVIORAL_FINGERPRINT", "anthropic")
    failing_client = Mock()
    failing_client.messages.create.side_effect = RuntimeError("boom")
    c = AnthropicChallenger(anthropic_client=failing_client)
    verdict = c.run([make_challenge("q", "a", pool_tag="t")])
    assert verdict.verdict == "UNSURE"
    assert "boom" in verdict.reason


def test_challenger_threshold_is_two_thirds(monkeypatch) -> None:
    """With 3 challenges, need 2/3 matches. With 6, need 4/6. Spot-check."""
    monkeypatch.setenv("ARDUR_BEHAVIORAL_FINGERPRINT", "anthropic")
    # 3 challenges, 2 correct answers, 1 wrong answer expected:
    # threshold = 3 - (3//3) = 2, matched = 2 → OK
    # Simulate by making the mock return different things per call.
    mock_client = Mock()
    mock_client.messages.create.side_effect = [
        SimpleNamespace(content=[SimpleNamespace(text="four")]),
        SimpleNamespace(content=[SimpleNamespace(text="four")]),
        SimpleNamespace(content=[SimpleNamespace(text="banana")]),  # mismatch
    ]
    c = AnthropicChallenger(anthropic_client=mock_client)
    challenges = [
        make_challenge("q1", "four", pool_tag="arithmetic"),
        make_challenge("q2", "four", pool_tag="arithmetic"),
        make_challenge("q3", "four", pool_tag="arithmetic"),
    ]
    verdict = c.run(challenges)
    assert verdict.matched_count == 2
    assert verdict.match_threshold == 2
    assert verdict.verdict == "OK"  # meets threshold


# --------------------------------------------------------------------------
# Policy evaluation — enforce_fingerprint
# --------------------------------------------------------------------------


class _CannedChallenger:
    """Test helper that returns a pre-canned verdict."""

    def __init__(self, verdict: FingerprintVerdict) -> None:
        self._verdict = verdict

    def run(self, challenges):  # noqa: ARG002
        return self._verdict


def _verdict(kind: str) -> FingerprintVerdict:
    return FingerprintVerdict(
        verdict=kind, responses=[], matched_count=0, total_count=0,
        match_threshold=0, reason="canned", fingerprint_version="v1", elapsed_ms=0,
    )


def test_policy_fail_open_ok_accepts() -> None:
    pool = CanaryPool(challenges=[make_challenge("q", "a", pool_tag="t")])
    v = enforce_fingerprint(pool, _CannedChallenger(_verdict("OK")), policy="fail_open")
    assert v.verdict == "OK"


def test_policy_fail_open_unsure_accepts() -> None:
    pool = CanaryPool(challenges=[make_challenge("q", "a", pool_tag="t")])
    v = enforce_fingerprint(pool, _CannedChallenger(_verdict("UNSURE")), policy="fail_open")
    assert v.verdict == "OK"  # fail-open treats UNSURE as accept
    assert "UNSURE" in v.reason  # but diagnostic preserved


def test_policy_fail_open_fail_rejects() -> None:
    pool = CanaryPool(challenges=[make_challenge("q", "a", pool_tag="t")])
    v = enforce_fingerprint(pool, _CannedChallenger(_verdict("FAIL")), policy="fail_open")
    assert v.verdict == "FAIL"


def test_policy_fail_closed_ok_accepts() -> None:
    pool = CanaryPool(challenges=[make_challenge("q", "a", pool_tag="t")])
    v = enforce_fingerprint(pool, _CannedChallenger(_verdict("OK")), policy="fail_closed")
    assert v.verdict == "OK"


def test_policy_fail_closed_unsure_rejects() -> None:
    pool = CanaryPool(challenges=[make_challenge("q", "a", pool_tag="t")])
    v = enforce_fingerprint(pool, _CannedChallenger(_verdict("UNSURE")), policy="fail_closed")
    assert v.verdict == "FAIL"


def test_policy_fail_closed_fail_rejects() -> None:
    pool = CanaryPool(challenges=[make_challenge("q", "a", pool_tag="t")])
    v = enforce_fingerprint(pool, _CannedChallenger(_verdict("FAIL")), policy="fail_closed")
    assert v.verdict == "FAIL"


def test_policy_unknown_raises() -> None:
    pool = CanaryPool(challenges=[make_challenge("q", "a", pool_tag="t")])
    with pytest.raises(ValueError, match="unknown fingerprint policy"):
        enforce_fingerprint(
            pool, _CannedChallenger(_verdict("OK")), policy="bogus"
        )


def test_enforce_preserves_diagnostic_fields() -> None:
    """The policy-aware verdict rewrite must NOT erase matched_count /
    total_count / per-challenge responses. Operators need to see them to
    triage mismatches."""
    pool = CanaryPool(challenges=[make_challenge("q", "a", pool_tag="t")])
    raw = FingerprintVerdict(
        verdict="FAIL",
        responses=[ChallengeResponse("cid", "bad", "h", False, 5)],
        matched_count=0,
        total_count=3,
        match_threshold=2,
        reason="canned",
        fingerprint_version="v1",
        elapsed_ms=42,
    )
    v = enforce_fingerprint(pool, _CannedChallenger(raw), policy="fail_closed")
    assert v.verdict == "FAIL"
    assert v.matched_count == 0
    assert v.total_count == 3
    assert v.match_threshold == 2
    assert v.elapsed_ms == 42
    assert len(v.responses) == 1


# --------------------------------------------------------------------------
# Convenience helper
# --------------------------------------------------------------------------


def test_is_fingerprint_active_returns_false_by_default(monkeypatch) -> None:
    monkeypatch.delenv("ARDUR_BEHAVIORAL_FINGERPRINT", raising=False)
    assert is_fingerprint_active() is False


def test_is_fingerprint_active_returns_true_when_set(monkeypatch) -> None:
    monkeypatch.setenv("ARDUR_BEHAVIORAL_FINGERPRINT", "anthropic")
    assert is_fingerprint_active() is True


def test_is_fingerprint_active_rejects_wrong_value(monkeypatch) -> None:
    monkeypatch.setenv("ARDUR_BEHAVIORAL_FINGERPRINT", "true")
    assert is_fingerprint_active() is False
