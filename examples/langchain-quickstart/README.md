# LangChain + Ardur quickstart

A LangChain agent making tool calls through Ardur's governance proxy. The agent runs under an Ardur-issued mission credential, calls a small set of tools (read, write, summarize), and Ardur:

1. Issues a Mission Declaration signed by the local issuer key
2. Verifies the credential on every tool call against the mission's allowed tools, resource scope, and budget
3. Emits an Execution Receipt per call (compliant / violation / insufficient_evidence)
4. Produces a session-end attestation that's offline-verifiable with the issuer's public key

The integration point is the LangChain tool callback layer — the proxy wraps `BaseTool.invoke` so verification runs before the underlying tool body, and receipts emit on both success and exception paths.

## File layout

```
langchain-quickstart/
├── README.md              # this file
├── Dockerfile             # for the rahulnutakki/ardur-demo:lang image
└── demo.py                # the LangChain agent + scenarios entrypoint
```

`demo.py` imports framework-agnostic helpers from [`examples/_shared/demo_scenes.py`](../_shared/demo_scenes.py) — provider selection, SVID fetch, Biscuit issuance, governed-session setup, receipt-chain verification, end-of-session attestation. The split keeps each per-framework demo small.

## Dependencies

- Python 3.13 (`biscuit-python==0.4.0` does not support Python 3.14)
- `python/` editable install with the framework extra
  (`pip install -e '../../python[dev,langgraph]'`; the CLI is `ardur`, module
  imports are `vibap`)
- `langchain >=1.3.13,<2` and `langgraph >=1.2.9,<2`; provider adapters
  (`langchain-ollama`, `langchain-openai`, or `langchain-anthropic`) remain
  application-selected
- LLM access: any provider that LangChain supports — local Ollama, an OpenAI-compatible gateway, an Anthropic API key, etc.
- Optional: Docker for the recorded asciinema flow (`rahulnutakki/ardur-demo:lang`)

## Running locally

```bash
# 1. Install the runtime
cd ../../python && pip install -e '.[dev,langgraph]'

# 2. Pick a provider + model id
export ARDUR_PROVIDER=ollama
export OLLAMA_MODEL='<your local model tag>'

# 3. Run the demo from this directory
cd ../examples/langchain-quickstart
PYTHONPATH=../_shared python demo.py
```

`ARDUR_PROVIDER` selects the backend (`ollama` / `openai` / `anthropic`). The matching `*_MODEL` env var is required and tells the demo which model id to drive — no model identifiers are hard-coded in `demo_scenes.py` per the project rule (see [CONTRIBUTING.md](../../CONTRIBUTING.md)). For an OpenAI-compatible gateway, set `OPENAI_BASE_URL` alongside `OPENAI_API_KEY`.

## Building the Docker image

The `Dockerfile` is designed to build from the ardur repo root so the COPY paths resolve cleanly:

```bash
cd ../..   # back to ardur repo root
docker buildx build \
    --platform linux/amd64,linux/arm64 \
    -f examples/langchain-quickstart/Dockerfile \
    -t rahulnutakki/ardur-demo:lang \
    --push .
```

The image installs the LangChain stack and copies `python/vibap`, the `_shared` helpers, and this directory's `demo.py` into `/app/`. No secrets and no model identifiers are baked in; supply them at run time via `--env-file` (preferred — see the cast-recording note below) or per-invocation `-e` flags.

### Recorded-asciinema safety note

When recording demos, NEVER pass provider keys via `docker run -e KEY=VAL` — asciinema captures the subprocess command line, which leaks the key into any `.cast` file produced. Use `--env-file ./.env` instead. This is the discipline that produced the 2026-04-20 leak audit; the recording pipeline at `media/casts/` already honours it.

## Out of scope for this example

- Real-cluster SPIRE deployment — the example uses local file-based identity (the `bringup.sh` helper in `_shared` brings up a local SPIRE on Docker). Cluster identity comes later under `deploy/k8s/spire/`.
- Live LLM provider failover — single provider per run.
- Multi-tenant key isolation — single issuer key.

If you want any of the above, look at [`examples/missions/`](../missions/) for the protocol-only flow and combine it with the deployment material under [`deploy/k8s/spire/`](../../deploy/k8s/spire/).
