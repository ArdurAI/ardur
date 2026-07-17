# Governed subagent adapter

`GovernedSubagentAdapter` is the framework-neutral Python boundary for deriving,
running, recovering, and closing an attenuated child agent. It keeps child
credentials and governance sessions out of model-visible tool results and
framework checkpoints.

## Contract

Create one adapter per parent invocation. Inject that adapter through immutable
framework runtime context or explicit invocation-scoped dependency injection.
Never place the adapter, proxy, signer, parent session, or child passport in
model messages or serializable framework state.

Spawn accepts an explicit `GovernedSubagentRequest` and returns only a
`GovernedSubagentHandle`. A child request declares:

- a stable request ID for idempotency;
- child agent ID and mission;
- allowed tools and resource scope;
- a positive tool-call budget and TTL;
- optional spend/risk caps, which fail closed when the active runtime has no
  supported signed cap surface.

Every child tool call must use `run_tool` or `arun_tool` with the exact opaque
handle. Missing, malformed, forged, wrong-parent, spawning, expired, closed,
cancelled, quarantined, conflicting, or replayed handles never fall back to the
parent session.

## Minimal synchronous flow

```python
from vibap import (
    GovernedSubagentAdapter,
    GovernedSubagentRequest,
)

adapter = GovernedSubagentAdapter(
    proxy=proxy,
    parent_session=parent_session,
    delegation_private_key=delegation_private_key,
)

child = adapter.spawn(
    GovernedSubagentRequest(
        request_id="graph-call-0187",
        child_agent_id="sales-reader",
        mission="Read the bounded Q1 sales input",
        allowed_tools=["read_file"],
        resource_scope=["sales/*"],
        max_tool_calls=2,
        ttl_s=120,
    )
)

result = adapter.run_tool(
    child,
    operation_id="graph-tool-call-0271",
    tool_name="read_file",
    arguments={"path": "sales/q1-revenue.csv"},
    executor=lambda: read_file("sales/q1-revenue.csv"),
)

if result.status == "replay_suppressed":
    # Recover the earlier value from the framework checkpoint. Do not execute
    # the tool again.
    recover_framework_result(result.result_sha256)

closure = adapter.close(child)
```

The executor runs only after the child session returns `PERMIT`. A denial is
signed and returned with `executed=False`. The adapter persists only operation
metadata and the result digest; the raw executor value is returned to the
caller but is not copied into adapter state or governance evidence.

Executor results must contain only bounded JSON values. If result correlation
cannot be serialized after an effect may have occurred, the adapter records a
fixed evidence marker, quarantines the child, and does not refund or replay the
operation.

## Lifecycle and retry behavior

| State | Meaning | Allowed next action |
|---|---|---|
| `spawning` | Opaque intent is durable; proxy authority may be materializing | retry the same request ID or recover |
| `active` | Verified child session is bound to this parent and handle | run or close |
| `quarantined` | Policy/executor/result outcome is uncertain | close only |
| `closing` | Closure disposition is committed; attestation settlement is pending | retry the same close |
| `closed` | Child is attested and complete | idempotent close/evidence export |
| `cancelled` | Child is attested with cancelled disposition | idempotent cancel/evidence export |
| `expired` | Child authority expired; it cannot run | close for final attestation |

Spawn uses a two-phase local intent and the proxy's idempotent delegation
reservation. A restart after durable delegation reconciles the original opaque
handle to the proxy's private child record without persisting a child passport
in adapter state. An expired spawn lease with no materialized proxy child is a
non-authorizing intent and can be removed during bounded bulk cleanup.

Each child permits one in-flight operation. Distinct children can run in
parallel. Shared lineage-budget reservation remains atomic in
`GovernanceProxy`, so parallel spawns cannot oversubscribe the parent's signed
budget.

`close_all(cancelled=True)` is the exception/cancellation cleanup path after
active executors have unwound. It attempts every eligible child before
propagating the first cleanup failure. It never declares an executor cancelled
while the child still has a live operation lease.

## Async execution

Use `arun_tool` when the executor returns an awaitable. Its authorization,
replay, evidence, and quarantine rules are identical to `run_tool`.
`asyncio.CancelledError` after permit is an uncertain outcome: the operation and
child are quarantined, and consumed/reserved authority is not silently
refunded.

## LangGraph runtime context and checkpoints

The reference in `examples/langgraph-quickstart/demo.py` uses a frozen
`GovernedSubagentRuntimeContext` and `ToolRuntime`. LangGraph injects that
context into the tool at invocation time and omits it from the model-visible
tool schema. Its hidden `tool_call_id` becomes the stable spawn/run correlation
key.

The reference compiles with `checkpointer=None`. Applications that enable a
checkpointer may persist framework messages, opaque handles, and their own tool
results. They must not persist the adapter, signer, credentials, governance
sessions, or receipt state. A framework checkpoint is recovery data, not
authority. For independent parallel subagents, use per-invocation persistence;
do not share per-thread child checkpoint state across concurrent tool calls.

These choices follow the current official runtime-context, subagent, and
subgraph/persistence contracts:

- [LangChain runtime context](https://docs.langchain.com/oss/python/langchain/runtime)
- [LangChain subagents](https://docs.langchain.com/oss/python/langchain/multi-agent/subagents)
- [LangGraph subgraphs and persistence](https://docs.langchain.com/oss/python/langgraph/use-subgraphs)
- [LangGraph graph API](https://docs.langchain.com/oss/python/langgraph/graph-api)

The tested optional dependency surface is `langchain >=1.3.13,<2` and
`langgraph >=1.2.9,<2`, available through `pip install -e '.[langgraph]'` from
the `python/` directory.

## Evidence and privacy

`lifecycle_snapshot` returns bounded metadata with child/parent identifiers,
status, timestamps, operation count, and attestation identifiers/digests.
`export_session_evidence` removes passport and attestation tokens.

`export_attestation_evidence` is a trusted offline-bundle assembly API. It
returns signed attestation evidence—not a child passport or executable bearer
credential—and rejects active children. Before returning, it verifies the
signature and correlates the token digest and attestation JTI with durable
closure state. Do not place this signed evidence in a model response or
framework checkpoint.

The adapter state directory is private local state (`0700`; files `0600`) with
an 8 MiB bound, bounded handles/operations, process and file locks, atomic
replacement, and file/directory `fsync`. State contains request/argument/result
digests rather than raw prompts, missions, operation arguments, executor
values, or bearer credentials.

## Security, operability, and cost

- **Blast radius:** compromise of a child handle alone does not reveal its
  passport, but a handle used inside the correct live parent invocation can
  consume that child's remaining authority. Keep parent runtime context private.
- **Fail-closed availability:** corrupt/unavailable state, missing session
  evidence, or uncertain execution blocks further child work. Operators must
  close/quarantine rather than delete evidence and retry effects.
- **Storage:** adapter state is bounded, but governance sessions and signed
  receipt logs have their own retention profile. High tool-call volume can
  increase local/remote log storage and observability ingestion cost.
- **Concurrency:** one active operation per child simplifies replay safety. Use
  multiple strictly attenuated children for safe parallelism; do not widen one
  child merely to increase throughput.
- **Remote policy/evidence sinks:** network calls, cross-region receipt export,
  and high-cardinality telemetry can add latency and egress/ingestion charges.
  The local adapter itself introduces no background scheduler or hosted control
  plane.

## Verification

The focused regression surfaces are:

- `python/tests/test_governed_subagent.py` for lifecycle, privacy, concurrency,
  restart, cancellation, replay, and corruption cases;
- `python/tests/test_governed_subagent_demo_integration.py` for the real demo
  engine, signed denial, credential-free offline bundle, current LangGraph
  runtime injection, and per-invocation isolation;
- `python/tests/test_examples_governance_integration.py` and
  `python/tests/test_examples_smoke.py` for existing demo compatibility.
