from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from vibap.passport import MissionPassport, issue_passport


REPO_ROOT = Path(__file__).resolve().parents[2]
SHARED_EXAMPLES = REPO_ROOT / "examples" / "_shared"
LANGGRAPH_DEMO = REPO_ROOT / "examples" / "langgraph-quickstart" / "demo.py"


def _shared_module(name: str):
    path = str(SHARED_EXAMPLES)
    sys.path.insert(0, path)
    try:
        return importlib.import_module(name)
    finally:
        sys.path.remove(path)


def _langgraph_demo_module():
    pytest.importorskip("langchain")
    pytest.importorskip("langgraph")
    _shared_module("demo_scenes")
    spec = importlib.util.spec_from_file_location(
        "ardur_langgraph_quickstart_test",
        LANGGRAPH_DEMO,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load LangGraph quickstart")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _parent_token(keypair) -> str:
    private_key, _public_key = keypair
    mission = MissionPassport(
        agent_id="integration-parent",
        mission="coordinate a bounded multiagent report",
        allowed_tools=["read_file", "write_report"],
        forbidden_tools=["delete_file"],
        resource_scope=["**"],
        max_tool_calls=8,
        max_duration_s=300,
        delegation_allowed=True,
        max_delegation_depth=2,
    )
    return issue_passport(mission, private_key, ttl_s=300)


def _spawn_handle(response: str) -> str:
    match = re.search(r"child_handle=(ardur_child_[A-Za-z0-9_-]{43})", response)
    assert match is not None
    return match.group(1)


def test_demo_engine_uses_adapter_and_exports_credential_free_verified_bundle(
    proxy,
    keypair,
    tmp_path,
):
    demo_scenes = _shared_module("demo_scenes")
    verifier = _shared_module("verify_bundle")
    private_key, _public_key = keypair
    parent_token = _parent_token(keypair)
    parent_session = proxy.start_session(parent_token)
    workspace = tmp_path / "workspace"
    (workspace / "sales").mkdir(parents=True)
    (workspace / "reports").mkdir()
    (workspace / "sales" / "q1-revenue.csv").write_text(
        "region,revenue\nus-east,48200\n",
        encoding="utf-8",
    )
    engine = demo_scenes.MultiagentLifecycleEngine(
        proxy=proxy,
        parent_session=parent_session,
        parent_token=parent_token,
        private_key=private_key,
        workspace=workspace,
        bundle_root=tmp_path,
        framework="integration-test",
        provider="none",
    )

    handles = {
        "sales-reader": _spawn_handle(
            engine.spawn_subagent(
                "sales-reader",
                "Read Q1 sales data",
                ["read_file"],
                ["sales/*"],
                2,
            )
        ),
        "report-writer": _spawn_handle(
            engine.spawn_subagent(
                "report-writer",
                "Write Q1 child summary report",
                ["write_report"],
                ["reports/*"],
                2,
            )
        ),
        "safety-probe": _spawn_handle(
            engine.spawn_subagent(
                "safety-probe",
                "Attempt forbidden cleanup then read safely",
                ["read_file"],
                ["sales/*"],
                2,
            )
        ),
    }

    assert "48200" in engine.run_subagent(handles["sales-reader"], "read sales")
    assert "Child report" in engine.run_subagent(
        handles["report-writer"],
        "write report",
    )
    safety_result = engine.run_subagent(
        handles["safety-probe"],
        "try cleanup and read",
    )
    assert "DENIED delete_file" in safety_result
    assert "48200" in safety_result
    assert (workspace / "sales" / "q1-revenue.csv").exists()

    for handle in handles.values():
        engine.close_subagent(handle)
    parent_attestation, parent_claims = proxy.issue_attestation_for_session(
        parent_session.jti,
        private_key,
    )
    bundle = engine.export_bundle(parent_attestation, parent_claims)
    verification = verifier.verify_bundle(bundle)

    assert verification.ok, verification.errors
    assert parent_claims["children_spawned"] == 3
    assert parent_claims["children_closed"] == 3
    tool_calls = (bundle / "parent_tool_calls.jsonl").read_text(encoding="utf-8")
    assert "Read Q1 sales data" not in tool_calls
    assert "try cleanup and read" not in tool_calls
    assert "arguments_sha256" in tool_calls
    for session_path in (bundle / "children").glob("*.session.json"):
        exported = json.loads(session_path.read_text(encoding="utf-8"))
        assert "passport_token" not in exported
        assert "attestation_token" not in exported

    safety_jti = engine.adapter.lifecycle_snapshot(handles["safety-probe"])["child_jti"]
    safety_receipts = [
        json.loads(line)
        for line in (bundle / "receipts.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip() and json.loads(line).get("session_id") == safety_jti
    ]
    assert any(receipt["verdict"] == "violation" for receipt in safety_receipts)


class _RecordingEngine:
    handle = "ardur_child_" + ("A" * 43)

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def spawn_subagent(
        self,
        name,
        mission,
        allowed_tools,
        resource_scope,
        max_tool_calls,
        *,
        request_id,
    ):
        self.calls.append(
            (
                "spawn",
                {
                    "name": name,
                    "mission": mission,
                    "allowed_tools": allowed_tools,
                    "resource_scope": resource_scope,
                    "max_tool_calls": max_tool_calls,
                    "request_id": request_id,
                },
            )
        )
        return f"spawned {name}; child_handle={self.handle}"

    def run_subagent(self, child_handle, task, *, operation_id):
        self.calls.append(
            (
                "run",
                {
                    "child_handle": child_handle,
                    "task": task,
                    "operation_id": operation_id,
                },
            )
        )
        return "completed"

    def close_subagent(self, child_handle):
        self.calls.append(("close", {"child_handle": child_handle}))
        return "closed"


def _invoke_tool_node(
    module, engine, *, tool_name: str, arguments: dict[str, Any], call_id: str
):
    from langchain_core.messages import AIMessage
    from langgraph.graph import END, START, StateGraph
    from langgraph.prebuilt import ToolNode

    tools = module.make_langgraph_multiagent_tools()
    graph = StateGraph(
        module.GraphState,
        context_schema=module.GovernedSubagentRuntimeContext,
    )
    graph.add_node("tools", ToolNode(tools))
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    compiled = graph.compile(checkpointer=None)
    return tools, compiled.invoke(
        {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": tool_name,
                            "args": arguments,
                            "id": call_id,
                            "type": "tool_call",
                        }
                    ],
                )
            ]
        },
        context=module.GovernedSubagentRuntimeContext(engine=engine),
    )


def test_langgraph_toolruntime_is_hidden_stable_and_invocation_scoped():
    module = _langgraph_demo_module()
    first = _RecordingEngine()
    second = _RecordingEngine()
    spawn_args = {
        "name": "reader",
        "mission": "read bounded data",
        "allowed_tools": ["read_file"],
        "resource_scope": ["sales/*"],
        "max_tool_calls": 1,
    }

    tools, _result = _invoke_tool_node(
        module,
        first,
        tool_name="spawn_subagent",
        arguments=spawn_args,
        call_id="call-spawn-1",
    )
    _invoke_tool_node(
        module,
        second,
        tool_name="spawn_subagent",
        arguments=spawn_args,
        call_id="call-spawn-1",
    )
    _invoke_tool_node(
        module,
        first,
        tool_name="run_subagent",
        arguments={"child_handle": first.handle, "task": "read"},
        call_id="call-run-1",
    )
    _invoke_tool_node(
        module,
        first,
        tool_name="run_subagent",
        arguments={"child_handle": first.handle, "task": "read"},
        call_id="call-run-1",
    )

    spawn_schema = tools[0].tool_call_schema.model_json_schema()
    assert "runtime" not in spawn_schema.get("properties", {})
    assert "resource_scope" in spawn_schema["properties"]
    assert len(first.calls) == 3
    assert len(second.calls) == 1
    assert first.calls[0][1]["request_id"] == second.calls[0][1]["request_id"]
    assert first.calls[1][1]["operation_id"] == first.calls[2][1]["operation_id"]
    expected = hashlib.sha256(b"run\0call-run-1").hexdigest()
    assert first.calls[1][1]["operation_id"] == f"langgraph:run:{expected}"
