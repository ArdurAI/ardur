"""Credential-free transcript regressions for the live E2E showcase."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from tests import test_e2e_showcase as showcase


@pytest.mark.parametrize(
    "call_specs",
    [
        [("read_file", '{"path": "/tmp/input.txt"}')],
        [
            ("read_file", '{"path": "/tmp/input.txt"}'),
            (
                "write_file",
                {"path": "/tmp/output.txt", "content": "summary"},
            ),
        ],
    ],
    ids=["single-call", "multi-call"],
)
@pytest.mark.parametrize(
    ("decision_body", "expected_tool_result"),
    [
        (
            {"decision": "PERMIT"},
            {"status": "ok", "result": "processed"},
        ),
        (
            {"decision": "DENY"},
            {"status": "denied", "result": "not processed"},
        ),
        (
            {"decision": "VIOLATION"},
            {"status": "unknown", "result": "not processed"},
        ),
        (
            None,
            {"status": "unknown", "result": "not processed"},
        ),
    ],
    ids=["permit", "deny", "other-decision", "missing-decision"],
)
def test_tool_turn_preserves_original_assistant_message_and_order(
    monkeypatch,
    call_specs,
    decision_body,
    expected_tool_result,
):
    """Single and parallel tool turns reach the next request without reshaping."""
    tool_calls = [
        SimpleNamespace(function=SimpleNamespace(name=name, arguments=arguments))
        for name, arguments in call_specs
    ]
    assistant_message = SimpleNamespace(
        role="assistant",
        content="I will read the input and write the summary.",
        tool_calls=tool_calls,
    )
    final_message = SimpleNamespace(
        role="assistant",
        content="Done.",
        tool_calls=[],
    )
    responses = [
        SimpleNamespace(message=assistant_message),
        SimpleNamespace(message=final_message),
    ]
    model_requests = []

    class FakeClient:
        def chat(self, *, model, messages, tools):
            model_requests.append(list(messages))
            return responses.pop(0)

    evaluations = []

    def fake_post(url, payload, token=None):
        evaluations.append((url, payload, token))
        return 200, decision_body, {}

    showcase_results = []
    monkeypatch.setattr(showcase, "_post", fake_post)
    monkeypatch.setattr(
        showcase,
        "_show",
        SimpleNamespace(
            test=lambda name, detail: showcase_results.append((name, detail)) or True
        ),
    )

    showcase.TestSessionAndPassportLayer.test_multi_turn_conversation(
        object(),
        FakeClient(),
        ("http://proxy.test", "session-123", "token", object()),
    )

    assert len(model_requests) == 2
    expected_tool_messages = [
        {
            "role": "tool",
            "tool_name": name,
            "content": json.dumps(expected_tool_result),
        }
        for name, _arguments in call_specs
    ]
    assert model_requests[1] == [
        *model_requests[0],
        assistant_message,
        *expected_tool_messages,
    ]
    assert model_requests[1][len(model_requests[0])] is assistant_message
    assert evaluations == [
        (
            "http://proxy.test/evaluate",
            {
                "session_id": "session-123",
                "tool_name": name,
                "arguments": showcase._parse_tool_args(arguments),
            },
            None,
        )
        for name, arguments in call_specs
    ]
    assert showcase_results == [
        (
            "Multi-Turn Conversation",
            f"LLM made {len(call_specs)} tool call(s) through proxy across multiple turns",
        )
    ]


@pytest.mark.parametrize(
    ("status", "decision", "expected"),
    [
        (
            503,
            {"decision": "PERMIT"},
            {"status": "unknown", "result": "not processed"},
        ),
        (
            200,
            "not-a-decision-object",
            {"status": "unknown", "result": "not processed"},
        ),
    ],
    ids=["non-200", "unusable-decision"],
)
def test_tool_result_without_valid_evidence_is_unknown(status, decision, expected):
    """Missing or unusable evaluation evidence never becomes success."""
    assert showcase._tool_result_for_evaluation(status, decision) == expected


def test_follow_up_model_error_fails_multi_turn_showcase(monkeypatch):
    """A provider rejection after a governed call cannot become a showcase pass."""
    tool_call = SimpleNamespace(
        function=SimpleNamespace(
            name="read_file",
            arguments={"path": "/tmp/input.txt"},
        )
    )
    first_response = SimpleNamespace(
        message=SimpleNamespace(
            role="assistant",
            content="I will read the input.",
            tool_calls=[tool_call],
        )
    )

    class RejectingClient:
        def __init__(self):
            self.calls = 0

        def chat(self, *, model, messages, tools):
            self.calls += 1
            if self.calls == 1:
                return first_response
            raise RuntimeError("server rejected follow-up transcript")

    showcase_results = []
    monkeypatch.setattr(
        showcase,
        "_post",
        lambda *_args, **_kwargs: (200, {"decision": "PERMIT"}, {}),
    )
    monkeypatch.setattr(
        showcase,
        "_show",
        SimpleNamespace(
            test=lambda name, detail: showcase_results.append((name, detail)) or True
        ),
    )

    with pytest.raises(RuntimeError, match="server rejected follow-up transcript"):
        showcase.TestSessionAndPassportLayer.test_multi_turn_conversation(
            object(),
            RejectingClient(),
            ("http://proxy.test", "session-123", "token", object()),
        )
    assert showcase_results == []
