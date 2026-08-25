"""Ardur live-governance demo — AutoGen v0.4+ flavor.

Shares the scene structure from demo_scenes.py. SVID fetching uses
the official spire-agent CLI binary (copied from the real
ghcr.io/spiffe/spire-agent:1.14.2 image at build time) because
autogen-core pins protobuf ~= 5.29 which collides with the
spiffe-python 0.2.x gencode. The Biscuit, Cedar, native, forbid-rules,
and receipt/attestation layers are identical to the LangChain and
LangGraph variants.

Honest limitation: because spiffe-python is absent from this image,
`proxy.start_session_from_biscuit(..., peer_jwt_svid=...)` raises on
verification (the proxy imports spiffe for SVID validation). The
demo falls back to a non-SVID-bound session — the Biscuit is still
verified cryptographically and the `holder_spiffe_id` claim still
names the real SVID's ID, but the cryptographic binding check at
session start is NOT performed on this path. This is visible on
screen as `svid_bound=False`.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time

sys.path.insert(0, "/app/ardur")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.ui import Console
from autogen_core.tools import FunctionTool

from demo_scenes import (
    BOLD,
    DIM,
    GREEN,
    RED,
    RESET,
    PACE,
    execute_delete_file,
    execute_read_file,
    execute_send_email,
    execute_write_report,
    fetch_svid_via_cli,
    make_autogen_client,
    provider_label,
    run_demo,
)


FRAMEWORK = "AutoGen v0.4+ (AssistantAgent)"


def _make_autogen_governed_tools(proxy, session_ref, workspace):
    """AutoGen FunctionTool wrappers, each routing through
    proxy.evaluate_tool_call — the public receipt-writing API."""

    def govern(tool_name, args):
        session = session_ref[0]
        decision, reason = proxy.evaluate_tool_call(session, tool_name, args)
        event = session.events[-1] if session.events else None
        pds = event.policy_decisions if event else []
        print(f"      {BOLD}[ARDUR] {tool_name}({args}){RESET} -> "
              f"{RED if decision.name == 'DENY' else GREEN}{decision.name}{RESET}")
        print(f"        reason: {reason}")
        for pd in pds:
            color = RED if pd["decision"] == "Deny" else (
                GREEN if pd["decision"] == "Allow" else DIM)
            rs = ", ".join(pd.get("reasons", [])) or "—"
            print(f"          - {pd['backend']:>14} ({pd['label']:>14}): "
                  f"{color}{pd['decision']:>8}{RESET}  [{rs}]")
        time.sleep(PACE * 0.4)
        return decision, reason

    def read_file(path: str) -> str:
        """Read a text file from the sandbox workspace."""
        d, r = govern("read_file", {"path": path})
        if d.name != "PERMIT":
            return f"DENIED by Ardur: {r}"
        return execute_read_file(workspace, path)

    def write_report(path: str, content: str) -> str:
        """Write a short summary report to a file in the sandbox."""
        d, r = govern("write_report",
                      {"path": path, "content": content})
        if d.name != "PERMIT":
            return f"DENIED by Ardur: {r}"
        return execute_write_report(workspace, path, content)

    def send_email(to: str, subject: str, body: str) -> str:
        """Send an email to someone."""
        d, r = govern("send_email",
                      {"to": to, "subject": subject, "body": body})
        if d.name != "PERMIT":
            return f"DENIED by Ardur: {r}"
        return execute_send_email(to, subject, body)

    def delete_file(path: str) -> str:
        """Delete a file from the sandbox."""
        d, r = govern("delete_file", {"path": path})
        if d.name != "PERMIT":
            return f"DENIED by Ardur: {r}"
        return execute_delete_file(workspace, path)

    return [
        FunctionTool(read_file, description="Read a text file."),
        FunctionTool(write_report, description="Write a summary report."),
        FunctionTool(send_email, description="Send an email."),
        FunctionTool(delete_file, description="Delete a file."),
    ]


def _make_autogen_multiagent_tools(engine):
    def spawn_subagent(
        name: str,
        mission: str,
        allowed_tools: list[str],
        resource_scope: list[str],
        max_tool_calls: int = 2,
    ) -> str:
        """Spawn a governed child with attenuated tools, resources, and budget."""
        return engine.spawn_subagent(
            name,
            mission,
            allowed_tools,
            resource_scope,
            max_tool_calls,
        )

    def run_subagent(child_handle: str, task: str) -> str:
        """Run one spawned child using its exact opaque child_handle."""
        return engine.run_subagent(child_handle, task)

    def close_subagent(child_handle: str) -> str:
        """Close one child by exact opaque handle and issue its attestation."""
        return engine.close_subagent(child_handle)

    return [
        FunctionTool(spawn_subagent, description="Spawn a governed child agent."),
        FunctionTool(run_subagent, description="Run a spawned child agent."),
        FunctionTool(close_subagent, description="Close a child and attest it."),
    ]


def build_agent(proxy, session, workspace):
    session_ref = [session]
    tools = _make_autogen_governed_tools(proxy, session_ref, workspace)

    code = f'''
      model_client = make_autogen_client()   # provider = {provider_label()}
      agent = AssistantAgent(
          name="sales_analyst",
          model_client=model_client,
          tools=tools,
          reflect_on_tool_use=False,
      )
    '''
    print(f"{DIM}{code}{RESET}")

    model_client = make_autogen_client()
    agent = AssistantAgent(
        name="sales_analyst",
        model_client=model_client,
        tools=tools,
        system_message=(
            "You are a helpful data-analyst agent. Call tools directly "
            "to accomplish the user's task."
        ),
        reflect_on_tool_use=False,
    )

    # Create a single event loop and reuse it for both scenarios so
    # AutoGen's httpx/anyio cleanup doesn't trip across asyncio.run
    # boundaries ("Event loop is closed" on the second call).
    loop = asyncio.new_event_loop()

    def invoke(agent, prompt):
        try:
            loop.run_until_complete(Console(agent.run_stream(task=prompt)))
        except RuntimeError as e:
            # Known AutoGen-ext + httpx cleanup interaction on some
            # Python 3.13 builds; the tool calls and governance have
            # already happened by the time this lands.
            if "Event loop is closed" not in str(e):
                raise

    return agent, session_ref, invoke, invoke


def build_multiagent_agent(engine):
    tools = _make_autogen_multiagent_tools(engine)
    code = f'''
      model_client = make_autogen_client()   # provider = {provider_label()}
      agent = AssistantAgent(
          name="parent_orchestrator",
          tools=[spawn_subagent, run_subagent, close_subagent],
      )
    '''
    print(f"{DIM}{code}{RESET}")

    model_client = make_autogen_client()
    agent = AssistantAgent(
        name="parent_orchestrator",
        model_client=model_client,
        tools=tools,
        system_message=(
            "You are a parent orchestrator. Call the provided tools directly "
            "to spawn, run, and close exactly the requested child agents."
        ),
        reflect_on_tool_use=False,
    )
    loop = asyncio.new_event_loop()

    def invoke(agent, prompt):
        try:
            loop.run_until_complete(Console(agent.run_stream(task=prompt)))
        except RuntimeError as e:
            if "Event loop is closed" not in str(e):
                raise

    return agent, invoke


def main():
    return run_demo(
        framework=FRAMEWORK,
        ollama_model=provider_label(),
        svid_fetch=fetch_svid_via_cli,
        build_agent=build_agent,
        build_multiagent_agent=build_multiagent_agent,
    )


if __name__ == "__main__":
    sys.exit(main())
