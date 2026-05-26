# Google ADK + Ardur quickstart

Deferred adapter spec. This directory is not a runnable example in the current
release candidate; it records the dependency footprint and expected shape for
the future Google ADK adapter.

## What this example will demonstrate

An agent built on Google's Agent Development Kit (`google-adk`) making tool calls through Ardur's governance proxy. The agent runs under an Ardur-issued mission credential, calls a small set of tools (read, write, summarize), and Ardur:

1. Issues a Mission Declaration signed by the local issuer key
2. Verifies the credential on every tool call against the mission's allowed tools, resource scope, and budget
3. Emits an Execution Receipt per call (compliant / violation / insufficient_evidence)
4. Produces a session-end attestation that's offline-verifiable with the issuer's public key

ADK's `LlmAgent` builds tools from plain Python callables and resolves their schemas via type hints. The proxy attaches at the `BaseTool.run_async` boundary so receipts emit consistently across both function-tools and the `AgentTool` wrapper used for sub-agent invocation.

## Dependencies

- `python/` editable install (this repo, `pip install -e ../python`; CLI is `ardur`, module imports are `vibap`)
- `google-adk ^0.1.0`
- LLM access: Google AI Studio API key (model id supplied via env var, see ADK docs); Vertex AI works too if `GOOGLE_GENAI_USE_VERTEXAI=true`
- Optional: Docker for the recorded asciinema flow

ADK shares a transitive dependency tree with `google-cloud-*` libraries, and `protobuf` version skew has bitten this combination in the past. A clean venv is the path of least resistance.

## File layout (when imported)

```
google-adk/
├── README.md              # this file
├── run.sh                 # one-line runner
├── src/
│   ├── agent.py           # LlmAgent + tool registration
│   └── tools.py           # governed demo tools (read, write, summarize)
├── mission.json           # the Mission Declaration the agent runs under
└── expected-receipt.json  # what a clean run produces, for diff-testing
```

## Run (when available)

```bash
cd google-adk
export GOOGLE_API_KEY=...
./run.sh
# Output:
#   - mission compiled
#   - agent started with passport
#   - tool calls + per-call verdicts
#   - session attestation printed at exit
```

## Out of scope for this example

- Vertex AI deployment — local AI Studio API only. Vertex requires service-account auth and a real GCP project, which is too much setup for a quickstart.
- Sub-agent / `AgentTool` chains — single-agent flow only.
- Real-cluster SPIRE deployment — the example uses local file-based identity.
- Multi-tenant key isolation — single issuer key.

For the protocol-only flow without an LLM, see `examples/missions/`.
