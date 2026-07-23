from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import run_adversarial_suite as adversarial
import run_all_models as all_models
import run_cloud_model_test as cloud_model
import test_ardur_comprehensive_integration as comprehensive
import test_ardur_overhead_ab as overhead
import test_ollama_integration as ollama_integration


class FakeMessage:
    """Minimal attribute-based Ollama message used without live credentials."""

    role = "assistant"

    def __init__(
        self, *, content: str | None = None, tool_calls: list[Any] | None = None
    ):
        self.content = content
        self.tool_calls = tool_calls


class FakeResponse:
    def __init__(self, message: FakeMessage):
        self.message = message
        self.prompt_eval_count = 0
        self.eval_count = 0
        self.total_duration = 0


class RecordingClient:
    """Return scripted responses while freezing each request transcript."""

    def __init__(self, responses: Iterable[FakeResponse | BaseException]):
        self._responses = iter(responses)
        self.calls: list[dict[str, Any]] = []
        self.message_refs: list[list[Any]] = []

    def chat(self, **kwargs: Any) -> FakeResponse:
        self.message_refs.append(kwargs["messages"])
        call = dict(kwargs)
        call["messages"] = list(kwargs["messages"])
        self.calls.append(call)
        response = next(self._responses)
        if isinstance(response, BaseException):
            raise response
        return response


def _tool_call(name: str, arguments: dict[str, Any] | str) -> Any:
    return SimpleNamespace(
        function=SimpleNamespace(name=name, arguments=arguments),
    )


def _empty_response(*, content: str | None = None) -> FakeResponse:
    return FakeResponse(FakeMessage(content=content, tool_calls=[]))


def _assert_ordered_tool_turn(
    messages: list[Any],
    assistant: FakeMessage,
    expected_names: list[str],
) -> list[dict[str, Any]]:
    assert sum(message is assistant for message in messages) == 1
    assistant_index = next(
        index for index, message in enumerate(messages) if message is assistant
    )
    tool_results = messages[
        assistant_index + 1 : assistant_index + 1 + len(expected_names)
    ]
    assert [message["role"] for message in tool_results] == ["tool"] * len(
        expected_names
    )
    assert [message["tool_name"] for message in tool_results] == expected_names
    assert all("name" not in message for message in tool_results)
    assert messages[assistant_index : assistant_index + 1 + len(expected_names)] == [
        assistant,
        *tool_results,
    ]
    return tool_results


def _two_call_turn() -> tuple[FakeMessage, list[Any], list[dict[str, Any]]]:
    expected_arguments = [
        {"path": "alpha.txt", "content": "alpha"},
        {"path": "beta.txt", "content": "beta"},
    ]
    calls = [
        _tool_call("write_file", expected_arguments[0]),
        _tool_call("write_file", json.dumps(expected_arguments[1])),
    ]
    return FakeMessage(tool_calls=calls), calls, expected_arguments


@pytest.mark.parametrize("governed", [False, True], ids=["without-ardur", "with-ardur"])
def test_overhead_functions_preserve_original_multi_call_turn(
    monkeypatch: pytest.MonkeyPatch,
    governed: bool,
) -> None:
    assistant, calls, expected_arguments = _two_call_turn()
    client = RecordingClient([FakeResponse(assistant), _empty_response()])
    evaluations: list[dict[str, Any]] = []
    monkeypatch.setattr(overhead, "TURNS", 2)

    if governed:

        def fake_post(_base: str, path: str, payload: dict[str, Any]):
            assert path == "/evaluate"
            evaluations.append(payload)
            return 200, {"decision": "PERMIT"}, {}

        monkeypatch.setattr(overhead, "_post_tls", fake_post)
        result = overhead.run_with_ardur(client, "https://proxy.invalid", "session")
    else:
        result = overhead.run_without_ardur(client)

    assert assistant.tool_calls is calls
    tool_results = _assert_ordered_tool_turn(
        client.calls[1]["messages"],
        assistant,
        ["write_file", "write_file"],
    )
    assert [json.loads(message["content"])["path"] for message in tool_results] == [
        arguments["path"] for arguments in expected_arguments
    ]
    assert result["tool_calls"] == 2
    assert result["files_created"] == 2

    if governed:
        assert [(body["tool_name"], body["arguments"]) for body in evaluations] == [
            ("write_file", arguments) for arguments in expected_arguments
        ]
    else:
        assert evaluations == []
    assert result["turns_used"] == 2


def test_overhead_single_call_turn_remains_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = {"path": "one.txt"}
    call = _tool_call("read_file", arguments)
    assistant = FakeMessage(tool_calls=[call])
    client = RecordingClient([FakeResponse(assistant), _empty_response()])
    monkeypatch.setattr(overhead, "TURNS", 2)

    result = overhead.run_without_ardur(client)

    tool_results = _assert_ordered_tool_turn(
        client.calls[1]["messages"],
        assistant,
        ["read_file"],
    )
    assert json.loads(tool_results[0]["content"])["path"] == arguments["path"]
    assert result["tool_calls"] == 1


def test_overhead_followup_provider_rejection_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assistant, _, _ = _two_call_turn()
    client = RecordingClient(
        [
            FakeResponse(assistant),
            RuntimeError("provider rejected follow-up transcript"),
        ]
    )
    monkeypatch.setattr(overhead, "TURNS", 2)

    with pytest.raises(RuntimeError, match="provider rejected follow-up transcript"):
        overhead.run_without_ardur(client)

    _assert_ordered_tool_turn(
        client.calls[1]["messages"],
        assistant,
        ["write_file", "write_file"],
    )


def test_overhead_second_evaluation_failure_keeps_transcript_atomic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assistant, _, _ = _two_call_turn()
    client = RecordingClient([FakeResponse(assistant)])
    evaluations = 0
    monkeypatch.setattr(overhead, "TURNS", 1)

    def fail_second_evaluation(_base: str, path: str, _payload: dict[str, Any]):
        nonlocal evaluations
        assert path == "/evaluate"
        evaluations += 1
        if evaluations == 2:
            raise RuntimeError("second evaluation failed")
        return 200, {"decision": "PERMIT"}, {}

    monkeypatch.setattr(overhead, "_post_tls", fail_second_evaluation)

    with pytest.raises(RuntimeError, match="second evaluation failed"):
        overhead.run_with_ardur(client, "https://proxy.invalid", "session")

    assert evaluations == 2
    original_transcript = client.message_refs[0]
    assert all(message is not assistant for message in original_transcript)
    assert not any(
        isinstance(message, dict) and message.get("role") == "tool"
        for message in original_transcript
    )


def _adversarial_scenario(max_turns: int = 2) -> adversarial.AdversarialScenario:
    return adversarial.AdversarialScenario(
        scenario_id="transcript-regression",
        title="Transcript regression",
        description="Credential-free transcript regression",
        violation_target="none",
        max_turns=max_turns,
        max_tool_calls=4,
        allowed_tools=["write_file"],
        forbidden_tools=[],
        resource_scope=["**"],
        seed_workdir=False,
        build_prompt=lambda _work_dir: [{"role": "user", "content": "write files"}],
    )


def _configure_adversarial(
    monkeypatch: pytest.MonkeyPatch,
    evaluations: list[tuple[str, dict[str, Any]]],
    executions: list[dict[str, Any]],
) -> None:
    import vibap.passport

    monkeypatch.setattr(
        vibap.passport, "issue_passport", lambda *_args, **_kwargs: "token"
    )
    monkeypatch.setattr(
        adversarial,
        "_post_tls",
        lambda *_args, **_kwargs: (200, {"session_id": "session"}, {}),
    )

    def evaluate(
        _base: str,
        _sid: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        evaluations.append((tool_name, arguments))
        return "PERMIT", {"decision": "PERMIT"}

    def execute(arguments: dict[str, Any], _work_dir: Path) -> dict[str, Any]:
        executions.append(arguments)
        return {"status": "ok", "path": arguments["path"]}

    monkeypatch.setattr(adversarial, "_evaluate_tool_call", evaluate)
    monkeypatch.setitem(adversarial.TOOL_HANDLERS, "write_file", execute)


def test_adversarial_runner_preserves_multi_call_turn_and_exactly_once_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    assistant, calls, expected_arguments = _two_call_turn()
    client = RecordingClient([FakeResponse(assistant), _empty_response()])
    evaluations: list[tuple[str, dict[str, Any]]] = []
    executions: list[dict[str, Any]] = []
    _configure_adversarial(monkeypatch, evaluations, executions)

    result = adversarial._run_scenario(
        _adversarial_scenario(),
        "configured-model",
        client,
        tmp_path,
        "https://proxy.invalid",
        object(),
        object(),
    )

    assert result.errors == []
    assert assistant.tool_calls is calls
    _assert_ordered_tool_turn(
        client.calls[1]["messages"],
        assistant,
        ["write_file", "write_file"],
    )
    assert evaluations == [
        ("write_file", arguments) for arguments in expected_arguments
    ]
    assert executions == expected_arguments


def test_adversarial_followup_provider_rejection_is_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    assistant, _, _ = _two_call_turn()
    rejection = RuntimeError("provider rejected follow-up transcript")
    client = RecordingClient([FakeResponse(assistant), rejection])
    evaluations: list[tuple[str, dict[str, Any]]] = []
    executions: list[dict[str, Any]] = []
    _configure_adversarial(monkeypatch, evaluations, executions)

    result = adversarial._run_scenario(
        _adversarial_scenario(),
        "configured-model",
        client,
        tmp_path,
        "https://proxy.invalid",
        object(),
        object(),
    )

    assert result.passed is False
    assert result.errors == [
        "Turn 1: model error: provider rejected follow-up transcript"
    ]


def test_adversarial_proxy_evaluation_error_is_failure_and_keeps_transcript_atomic(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    assistant, _, _ = _two_call_turn()
    client = RecordingClient([FakeResponse(assistant)])
    evaluations: list[tuple[str, dict[str, Any]]] = []
    executions: list[dict[str, Any]] = []
    _configure_adversarial(monkeypatch, evaluations, executions)
    monkeypatch.setattr(
        adversarial,
        "_evaluate_tool_call",
        lambda *_args, **_kwargs: (
            "ERROR",
            {"error": "evaluate HTTP 503"},
        ),
    )

    result = adversarial._run_scenario(
        _adversarial_scenario(),
        "configured-model",
        client,
        tmp_path,
        "https://proxy.invalid",
        object(),
        object(),
    )

    assert result.passed is False
    assert result.tool_calls_evaluated == 1
    assert result.errors == [
        "Turn 0: proxy evaluation failed for write_file: {'error': 'evaluate HTTP 503'}"
    ]
    assert executions == []
    assert all(message is not assistant for message in client.message_refs[0])


def _configure_cloud_main(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    client: RecordingClient,
    posts: list[tuple[str, dict[str, Any]]],
    *,
    evaluate_status: int = 200,
    evaluate_decision: dict[str, Any] | None = None,
) -> Path:
    import vibap.passport
    import vibap.tls

    report_path = tmp_path / "cloud-report.json"
    monkeypatch.setattr(cloud_model, "API_KEY", "configured")
    monkeypatch.setattr(cloud_model, "CLOUD_MODEL", "configured-model")
    monkeypatch.setattr(cloud_model, "WORK_DIR", tmp_path)
    monkeypatch.setattr(cloud_model, "REPORT_PATH", report_path)
    monkeypatch.setattr(cloud_model, "_free_port", lambda: 8443)
    monkeypatch.setattr(
        vibap.tls,
        "generate_self_signed_cert",
        lambda _path: (tmp_path / "key.pem", tmp_path / "cert.pem", object()),
    )
    proxy = SimpleNamespace(receipt_private_key=object())
    monkeypatch.setattr(
        cloud_model,
        "_start_proxy",
        lambda *_args, **_kwargs: (proxy, object(), "https://proxy.invalid"),
    )
    monkeypatch.setattr(
        vibap.passport, "issue_passport", lambda *_args, **_kwargs: "token"
    )
    monkeypatch.setitem(sys.modules, "ollama", SimpleNamespace(Client=lambda: client))

    def post(_base: str, path: str, body: dict[str, Any]):
        posts.append((path, body))
        if path == "/session/start":
            return 200, {"session_id": "session"}, b""
        if path == "/evaluate":
            decision = (
                {"decision": "PERMIT"}
                if evaluate_decision is None
                else evaluate_decision
            )
            return evaluate_status, decision, b""
        if path == "/session/end":
            return 200, {}, b""
        raise AssertionError(f"unexpected path: {path}")

    monkeypatch.setattr(cloud_model, "_post_tls", post)
    return report_path


def test_cloud_runner_preserves_multi_call_turn_and_distinct_evaluations(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    assistant, calls, expected_arguments = _two_call_turn()
    client = RecordingClient(
        [FakeResponse(assistant), _empty_response(content="finished")]
    )
    posts: list[tuple[str, dict[str, Any]]] = []
    report_path = _configure_cloud_main(monkeypatch, tmp_path, client, posts)

    cloud_model.main()

    assert assistant.tool_calls is calls
    _assert_ordered_tool_turn(
        client.calls[1]["messages"],
        assistant,
        ["write_file", "write_file"],
    )
    evaluations = [body for path, body in posts if path == "/evaluate"]
    assert [(body["tool_name"], body["arguments"]) for body in evaluations] == [
        ("write_file", arguments) for arguments in expected_arguments
    ]
    assert json.loads(report_path.read_text(encoding="utf-8"))["completed"] is True


def test_cloud_runner_expected_denial_is_not_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    decision = {"decision": "DENY", "reason": "forbidden tool"}
    assistant = FakeMessage(
        tool_calls=[_tool_call("delete_file", {"path": "forbidden.txt"})]
    )
    client = RecordingClient(
        [FakeResponse(assistant), _empty_response(content="finished")]
    )
    posts: list[tuple[str, dict[str, Any]]] = []
    report_path = _configure_cloud_main(
        monkeypatch,
        tmp_path,
        client,
        posts,
        evaluate_decision=decision,
    )

    cloud_model.main()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["completed"] is True
    assert report["errors"] == []
    assert report["denials"] == [
        {
            "tool": "delete_file",
            "args_keys": ["path"],
            "status": 200,
            "decision": decision,
        }
    ]
    assert report["tool_calls_total"] == 0
    tool_results = _assert_ordered_tool_turn(
        client.calls[1]["messages"],
        assistant,
        ["delete_file"],
    )
    assert json.loads(tool_results[0]["content"])["status"] == "denied"


@pytest.mark.parametrize(
    ("evaluate_status", "decision"),
    [
        (503, {"decision": "DENY", "reason": "proxy unavailable"}),
        (200, {"decision": "UNKNOWN"}),
    ],
    ids=["non-200", "unknown-decision"],
)
def test_cloud_runner_invalid_evaluation_is_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    evaluate_status: int,
    decision: dict[str, Any],
) -> None:
    assistant = FakeMessage(
        tool_calls=[_tool_call("write_file", {"path": "blocked.txt", "content": "x"})]
    )
    client = RecordingClient(
        [FakeResponse(assistant), _empty_response(content="finished")]
    )
    posts: list[tuple[str, dict[str, Any]]] = []
    report_path = _configure_cloud_main(
        monkeypatch,
        tmp_path,
        client,
        posts,
        evaluate_status=evaluate_status,
        evaluate_decision=decision,
    )

    with pytest.raises(
        RuntimeError,
        match=r"cloud model run failed with 1 error\(s\)",
    ):
        cloud_model.main()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["completed"] is False
    assert report["denials"] == []
    assert report["errors"] == [
        {
            "tool": "write_file",
            "args_keys": ["path", "content"],
            "status": evaluate_status,
            "decision": decision,
        }
    ]
    assert len(client.calls) == 1
    assert all(message is not assistant for message in client.message_refs[0])
    assert not any(
        isinstance(message, dict) and message.get("role") == "tool"
        for message in client.message_refs[0]
    )


def test_cloud_summary_counts_new_and_legacy_denial_schemas(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(all_models, "RESULTS_DIR", tmp_path)
    results = [
        {
            "model": "new-schema",
            "total_elapsed_s": 60,
            "tool_calls_total": 1,
            "files_created": ["one"],
            "denials": [{"decision": {"decision": "DENY"}}],
            "errors": [{"status": 503, "decision": {"decision": "UNKNOWN"}}],
        },
        {
            "model": "legacy-deny",
            "errors": [{"decision": {"decision": "DENY"}}],
        },
        {
            "model": "legacy-permit-in-errors",
            "errors": [{"decision": {"decision": "PERMIT"}}],
        },
        {
            "model": "legacy-unknown",
            "errors": [{"decision": {"decision": "UNKNOWN"}}],
        },
        {
            "model": "legacy-provider-failure",
            "errors": [
                {
                    "decision": {"decision": "DENY"},
                    "error": "provider failed",
                }
            ],
        },
        {
            "model": "legacy-empty-error",
            "errors": [{}],
        },
    ]

    all_models.write_summary(results)

    summary = json.loads((tmp_path / "SUMMARY.json").read_text(encoding="utf-8"))
    rows = {row["model"]: row for row in summary["models"]}
    assert rows["new-schema"]["denials"] == 1
    assert rows["new-schema"]["exceptions"] == 1
    assert rows["new-schema"]["clean"] is False
    assert rows["legacy-deny"]["denials"] == 1
    assert rows["legacy-deny"]["exceptions"] == 0
    for model in (
        "legacy-permit-in-errors",
        "legacy-unknown",
        "legacy-provider-failure",
        "legacy-empty-error",
    ):
        assert rows[model]["denials"] == 0
        assert rows[model]["exceptions"] == 1
        assert rows[model]["clean"] is False


def test_cloud_runner_empty_response_is_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    client = RecordingClient([_empty_response()])
    posts: list[tuple[str, dict[str, Any]]] = []
    report_path = _configure_cloud_main(monkeypatch, tmp_path, client, posts)

    with pytest.raises(
        RuntimeError,
        match=r"cloud model run failed with 1 error\(s\)",
    ):
        cloud_model.main()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["completed"] is False
    assert report["errors"] == [
        {"turn": 0, "error": "model returned no tool calls and no content"}
    ]


def test_cloud_runner_followup_provider_rejection_is_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    assistant, _, _ = _two_call_turn()
    client = RecordingClient(
        [
            FakeResponse(assistant),
            RuntimeError("provider rejected follow-up transcript"),
        ]
    )
    posts: list[tuple[str, dict[str, Any]]] = []
    report_path = _configure_cloud_main(monkeypatch, tmp_path, client, posts)

    with pytest.raises(
        RuntimeError,
        match=r"cloud model run failed with 1 error\(s\)",
    ):
        cloud_model.main()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["completed"] is False
    assert report["errors"] == [
        {"turn": 1, "error": "provider rejected follow-up transcript"}
    ]


def test_comprehensive_runner_preserves_each_original_multi_call_turn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assistants: list[FakeMessage] = []
    expected_evaluations: list[tuple[str, dict[str, Any]]] = []
    responses: list[FakeResponse] = []
    for turn in range(5):
        turn_arguments = [
            {"path": f"file-{turn}-a.txt", "content": "a"},
            {"path": f"file-{turn}-b.txt", "content": "b"},
        ]
        calls = [
            _tool_call("write_file", turn_arguments[0]),
            _tool_call("write_file", json.dumps(turn_arguments[1])),
        ]
        assistant = FakeMessage(tool_calls=calls)
        assistants.append(assistant)
        responses.append(FakeResponse(assistant))
        expected_evaluations.extend(
            ("write_file", arguments) for arguments in turn_arguments
        )
    # Five tool-call turns, fifteen empty turns, then the function's final chat.
    responses.extend(_empty_response() for _ in range(16))
    client = RecordingClient(responses)
    posts: list[tuple[str, dict[str, Any]]] = []
    ticks = iter(range(0, 120, 3))

    monkeypatch.setitem(sys.modules, "ollama", SimpleNamespace(Client=lambda: client))
    monkeypatch.setattr(
        comprehensive,
        "_start_jwt_session",
        lambda *_args, **_kwargs: ("session", "token"),
    )
    monkeypatch.setattr(comprehensive.time, "time", lambda: next(ticks))

    def post(_base: str, path: str, body: dict[str, Any]):
        posts.append((path, body))
        if path == "/evaluate":
            return 200, {"decision": "PERMIT"}, {}
        if path == "/session/end":
            return 200, {}, {}
        raise AssertionError(f"unexpected path: {path}")

    monkeypatch.setattr(comprehensive, "_post_tls", post)

    comprehensive._verify_ollama_multiturn(
        "https://proxy.invalid",
        SimpleNamespace(),
        object(),
    )

    for index, assistant in enumerate(assistants):
        _assert_ordered_tool_turn(
            client.calls[index + 1]["messages"],
            assistant,
            ["write_file", "write_file"],
        )
    evaluations = [
        (body["tool_name"], body["arguments"])
        for path, body in posts
        if path == "/evaluate"
    ]
    assert evaluations == expected_evaluations


def test_comprehensive_followup_provider_rejection_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assistant, _, expected_arguments = _two_call_turn()
    client = RecordingClient(
        [
            FakeResponse(assistant),
            RuntimeError("provider rejected follow-up transcript"),
        ]
    )
    posts: list[tuple[str, dict[str, Any]]] = []
    ticks = iter([0, 3, 6])

    monkeypatch.setitem(sys.modules, "ollama", SimpleNamespace(Client=lambda: client))
    monkeypatch.setattr(
        comprehensive,
        "_start_jwt_session",
        lambda *_args, **_kwargs: ("session", "token"),
    )
    monkeypatch.setattr(comprehensive.time, "time", lambda: next(ticks))

    def post(_base: str, path: str, body: dict[str, Any]):
        posts.append((path, body))
        assert path == "/evaluate"
        return 200, {"decision": "PERMIT"}, {}

    monkeypatch.setattr(comprehensive, "_post_tls", post)

    with pytest.raises(RuntimeError, match="provider rejected follow-up transcript"):
        comprehensive._verify_ollama_multiturn(
            "https://proxy.invalid",
            SimpleNamespace(),
            object(),
        )

    _assert_ordered_tool_turn(
        client.calls[1]["messages"],
        assistant,
        ["write_file", "write_file"],
    )
    assert [
        (body["tool_name"], body["arguments"])
        for path, body in posts
        if path == "/evaluate"
    ] == [("write_file", arguments) for arguments in expected_arguments]


def test_ollama_integration_roundtrip_preserves_multi_call_turn(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    expected_arguments = [{"path": "/alpha"}, {"path": "/beta"}]
    calls = [
        _tool_call("read_file", expected_arguments[0]),
        _tool_call("read_file", json.dumps(expected_arguments[1])),
    ]
    assistant = FakeMessage(tool_calls=calls)
    client = RecordingClient(
        [FakeResponse(assistant), _empty_response(content="finished")]
    )
    evaluations: list[dict[str, Any]] = []
    receipts_path = tmp_path / "receipts.jsonl"
    receipts_path.write_text("{}\n", encoding="utf-8")
    proxy = SimpleNamespace(receipts_log_path=receipts_path)

    def post(_url: str, body: dict[str, Any], _token: str | None = None):
        evaluations.append(body)
        return 200, {"decision": "PERMIT"}, {}

    monkeypatch.setattr(ollama_integration, "_post", post)

    ollama_integration.TestOllamaGovernanceIntegration().test_multi_turn_conversation_with_tool_roundtrips(
        client,
        ("https://proxy.invalid", "session", "token", proxy),
    )

    assert assistant.tool_calls is calls
    tool_results = _assert_ordered_tool_turn(
        client.calls[1]["messages"],
        assistant,
        ["read_file", "read_file"],
    )
    assert [json.loads(message["content"])["path"] for message in tool_results] == [
        arguments["path"] for arguments in expected_arguments
    ]
    assert [(body["tool_name"], body["arguments"]) for body in evaluations] == [
        ("read_file", arguments) for arguments in expected_arguments
    ]


def test_ollama_integration_followup_provider_rejection_propagates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    expected_arguments = [{"path": "/alpha"}, {"path": "/beta"}]
    assistant = FakeMessage(
        tool_calls=[
            _tool_call("read_file", expected_arguments[0]),
            _tool_call("read_file", json.dumps(expected_arguments[1])),
        ]
    )
    client = RecordingClient(
        [
            FakeResponse(assistant),
            RuntimeError("provider rejected follow-up transcript"),
        ]
    )
    evaluations: list[dict[str, Any]] = []
    proxy = SimpleNamespace(receipts_log_path=tmp_path / "unused.jsonl")

    def post(_url: str, body: dict[str, Any], _token: str | None = None):
        evaluations.append(body)
        return 200, {"decision": "PERMIT"}, {}

    monkeypatch.setattr(ollama_integration, "_post", post)

    with pytest.raises(RuntimeError, match="provider rejected follow-up transcript"):
        ollama_integration.TestOllamaGovernanceIntegration().test_multi_turn_conversation_with_tool_roundtrips(
            client,
            ("https://proxy.invalid", "session", "token", proxy),
        )

    _assert_ordered_tool_turn(
        client.calls[1]["messages"],
        assistant,
        ["read_file", "read_file"],
    )
    assert [(body["tool_name"], body["arguments"]) for body in evaluations] == [
        ("read_file", arguments) for arguments in expected_arguments
    ]


def test_fake_client_captures_transcripts_without_mutation() -> None:
    """Guard the test seam itself so identity/order assertions remain meaningful."""
    original_messages = [{"role": "user", "content": "hello"}]
    client = RecordingClient([_empty_response()])

    client.chat(messages=original_messages)
    original_messages.append({"role": "user", "content": "later"})

    assert client.calls[0]["messages"] == [{"role": "user", "content": "hello"}]
