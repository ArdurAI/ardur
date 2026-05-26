# OpenAI Agents SDK + Ardur quickstart

Deferred adapter spec. This directory is not a runnable example in the current
release candidate; it records the dependency footprint and expected shape for
the future OpenAI Agents SDK adapter.

## What this example will demonstrate

An agent built on the OpenAI Agents SDK (`openai-agents`) making tool calls through Ardur's governance proxy. The agent runs under an Ardur-issued mission credential, calls a small set of tools (read, write, summarize), and Ardur:

1. Issues a Mission Declaration signed by the local issuer key
2. Verifies the credential on every tool call against the mission's allowed tools, resource scope, and budget
3. Emits an Execution Receipt per call (compliant / violation / insufficient_evidence)
4. Produces a session-end attestation that's offline-verifiable with the issuer's public key

The Agents SDK exposes a `function_tool` decorator and a `Runner` that drives the loop. The proxy hooks the function-tool dispatch, which means handoffs (one agent invoking another) generate nested receipts — the attestation captures the parent/child relationship so a multi-agent run reads as a tree, not a flat sequence.

## Dependencies

- `python/` editable install (this repo, `pip install -e ../python`; CLI is `ardur`, module imports are `vibap`)
- `openai-agents ^0.1.0`
- LLM access: OpenAI API key (the SDK is API-bound; no local-model path)
- Optional: Docker for the recorded asciinema flow

The SDK is still pre-1.0 and breaking changes between minors aren't unusual — the pin is intentionally narrow.

## File layout (when imported)

```
openai-agents-sdk/
├── README.md              # this file
├── run.sh                 # one-line runner
├── src/
│   ├── agent.py           # Agent + Runner setup
│   └── tools.py           # governed demo tools (read, write, summarize)
├── mission.json           # the Mission Declaration the agent runs under
└── expected-receipt.json  # what a clean run produces, for diff-testing
```

## Run (when available)

```bash
cd openai-agents-sdk
export OPENAI_API_KEY=sk-...
./run.sh
# Output:
#   - mission compiled
#   - agent started with passport
#   - tool calls + per-call verdicts
#   - session attestation printed at exit
```

`run.sh` aborts early with a clear message if `OPENAI_API_KEY` isn't set, rather than leaking a less-helpful 401 from the SDK.

## Out of scope for this example

- Multi-agent handoffs — single agent only. Handoff receipts work in the adapter but the example keeps to one agent for a clean attestation diff.
- Real-cluster SPIRE deployment — the example uses local file-based identity.
- Live LLM provider failover — OpenAI only; the SDK is provider-locked.
- Multi-tenant key isolation — single issuer key.

For the protocol-only flow without an LLM, see `examples/missions/`.
