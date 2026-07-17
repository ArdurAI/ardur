"""Ardur live-governance demo — LangGraph (native StateGraph) flavor.

Shares the scene structure from demo_scenes.py. Only the agent
construction uses LangGraph's native StateGraph primitives instead of
LangChain's prebuilt create_react_agent — so the recording shows the
same governance story against a different agent runtime.
"""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass
from typing import Annotated, Any, TypedDict

sys.path.insert(0, "/app/ardur")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from langchain_core.messages import AnyMessage, HumanMessage
from langchain.tools import ToolRuntime, tool
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from demo_scenes import (
    DIM,
    RESET,
    fetch_svid_via_spiffe_python,
    make_langchain_governed_tools,
    make_langchain_llm,
    provider_label,
    run_demo,
)


FRAMEWORK = "LangGraph (native StateGraph)"


class GraphState(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]


@dataclass(frozen=True)
class GovernedSubagentRuntimeContext:
    """Non-serializable authority injected once per graph invocation."""

    engine: Any


def _runtime_operation_id(runtime: ToolRuntime[Any], purpose: str) -> str:
    tool_call_id = runtime.tool_call_id
    if not isinstance(tool_call_id, str) or not tool_call_id:
        raise RuntimeError("LangGraph tool execution is missing tool_call_id")
    digest = hashlib.sha256(f"{purpose}\0{tool_call_id}".encode("utf-8")).hexdigest()
    return f"langgraph:{purpose}:{digest}"


def make_langgraph_multiagent_tools():
    """Build tools whose governance dependency comes only from runtime context."""

    @tool
    def spawn_subagent(
        name: str,
        mission: str,
        allowed_tools: list[str],
        resource_scope: list[str],
        runtime: ToolRuntime[GovernedSubagentRuntimeContext],
        max_tool_calls: int = 2,
    ) -> str:
        """Spawn a governed child with attenuated tools, resources, and budget."""
        return runtime.context.engine.spawn_subagent(
            name,
            mission,
            allowed_tools,
            resource_scope,
            max_tool_calls,
            request_id=_runtime_operation_id(runtime, "spawn"),
        )

    @tool
    def run_subagent(
        child_handle: str,
        task: str,
        runtime: ToolRuntime[GovernedSubagentRuntimeContext],
    ) -> str:
        """Run one spawned child using its exact opaque child_handle."""
        return runtime.context.engine.run_subagent(
            child_handle,
            task,
            operation_id=_runtime_operation_id(runtime, "run"),
        )

    @tool
    def close_subagent(
        child_handle: str,
        runtime: ToolRuntime[GovernedSubagentRuntimeContext],
    ) -> str:
        """Close one child by exact opaque handle and issue its attestation."""
        return runtime.context.engine.close_subagent(child_handle)

    return [spawn_subagent, run_subagent, close_subagent]


def build_agent(proxy, session, workspace):
    session_ref = [session]
    tools = make_langchain_governed_tools(proxy, session_ref, workspace)
    llm = make_langchain_llm().bind_tools(tools)

    code = '''
      class GraphState(TypedDict):
          messages: Annotated[list[AnyMessage], add_messages]

      llm_with_tools = ChatOllama(...).bind_tools(tools)
      tool_node = ToolNode(tools)

      def agent_node(state): return {"messages": [llm_with_tools.invoke(state["messages"])]}
      def should_continue(state):
          return "tools" if state["messages"][-1].tool_calls else END

      graph = StateGraph(GraphState)
      graph.add_node("agent", agent_node)
      graph.add_node("tools", tool_node)
      graph.add_edge(START, "agent")
      graph.add_conditional_edges("agent", should_continue,
                                   {"tools": "tools", END: END})
      graph.add_edge("tools", "agent")
      compiled = graph.compile()
    '''
    print(f"{DIM}{code}{RESET}")

    tool_node = ToolNode(tools)

    def agent_node(state: GraphState) -> dict:
        return {"messages": [llm.invoke(state["messages"])]}

    def should_continue(state: GraphState) -> str:
        last = state["messages"][-1]
        if hasattr(last, "tool_calls") and last.tool_calls:
            return "tools"
        return END

    graph = StateGraph(GraphState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_edge(START, "agent")
    graph.add_conditional_edges(
        "agent", should_continue, {"tools": "tools", END: END})
    graph.add_edge("tools", "agent")
    compiled = graph.compile()

    def invoke(compiled, prompt):
        result = compiled.invoke(
            {"messages": [HumanMessage(content=prompt)]},
            config={"recursion_limit": 12},
        )
        print(f"\n      (graph emitted {len(result.get('messages', []))} "
              f"messages total)")

    return compiled, session_ref, invoke, invoke


def _build_graph(tools, *, context_schema=None):
    llm = make_langchain_llm().bind_tools(tools)
    tool_node = ToolNode(tools)

    def agent_node(state: GraphState) -> dict:
        return {"messages": [llm.invoke(state["messages"])]}

    def should_continue(state: GraphState) -> str:
        last = state["messages"][-1]
        if hasattr(last, "tool_calls") and last.tool_calls:
            return "tools"
        return END

    graph = StateGraph(GraphState, context_schema=context_schema)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_edge(START, "agent")
    graph.add_conditional_edges(
        "agent", should_continue, {"tools": "tools", END: END})
    graph.add_edge("tools", "agent")
    return graph.compile()


def build_multiagent_agent(engine):
    tools = make_langgraph_multiagent_tools()
    code = f'''
      llm_with_tools = make_langchain_llm().bind_tools(multiagent_tools)
      tool_node = ToolNode([spawn_subagent, run_subagent, close_subagent])
      compiled = StateGraph(
          GraphState,
          context_schema=GovernedSubagentRuntimeContext,
      ).compile(checkpointer=None)
      compiled.invoke(..., context=GovernedSubagentRuntimeContext(engine))
      # provider = {provider_label()}
    '''
    print(f"{DIM}{code}{RESET}")
    compiled = _build_graph(
        tools,
        context_schema=GovernedSubagentRuntimeContext,
    )

    def invoke(compiled, prompt):
        result = compiled.invoke(
            {"messages": [HumanMessage(content=prompt)]},
            config={"recursion_limit": 40},
            context=GovernedSubagentRuntimeContext(engine=engine),
        )
        print(f"\n      (multiagent graph emitted "
              f"{len(result.get('messages', []))} messages total)")

    return compiled, invoke


def main():
    return run_demo(
        framework=FRAMEWORK,
        ollama_model=provider_label(),
        svid_fetch=fetch_svid_via_spiffe_python,
        build_agent=build_agent,
        build_multiagent_agent=build_multiagent_agent,
    )


if __name__ == "__main__":
    sys.exit(main())
