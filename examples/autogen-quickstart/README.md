# AutoGen + Ardur quickstart

An AutoGen agent (v0.4+ architecture, `autogen-agentchat`) making tool calls through Ardur's governance proxy. The agent runs under an Ardur-issued mission credential, calls a small set of tools (read, write, summarize), and Ardur:

1. Issues a Mission Declaration signed by the local issuer key
2. Verifies the credential on every tool call against the mission's allowed tools, resource scope, and budget
3. Emits an Execution Receipt per call (compliant / violation / insufficient_evidence)
4. Produces a session-end attestation that's offline-verifiable with the issuer's public key

AutoGen 0.4 is a ground-up rewrite from 0.2, so this adapter only targets the new event-driven runtime. The proxy attaches at the `FunctionTool` boundary inside `AssistantAgent`, before the tool's own pydantic validation runs — that ordering matters because mission violations should short-circuit before argument parsing reports a different error.

## File layout

```
autogen-quickstart/
├── README.md              # this file
├── Dockerfile             # for the rahulnutakki/ardur-demo:autogen image
└── demo.py                # the AutoGen agent + scenarios entrypoint
```

`demo.py` imports framework-agnostic helpers from [`examples/_shared/demo_scenes.py`](../_shared/demo_scenes.py) — provider selection, SVID fetch, Biscuit issuance, governed-session setup, receipt-chain verification, end-of-session attestation. The split keeps each per-framework demo small.

## Dependencies

- Python 3.13 (`biscuit-python==0.4.0` does not support Python 3.14)
- `python/` editable install (this repo, via `./scripts/setup-dev.sh --skip-go`; the CLI is `ardur`, module imports are `vibap`)
- `autogen-agentchat ^0.4.0` plus `autogen-core` (transitive)
- `autogen-ext[ollama,openai,anthropic]` for the multi-provider matrix
- LLM access: local Ollama, an OpenAI-compatible gateway, or an Anthropic API key
- Optional: Docker for the recorded asciinema flow (`rahulnutakki/ardur-demo:autogen`)

**Heads-up:** AutoGen's `protobuf` pin (~=5.29) conflicts with `spiffe-python`'s transitive >=6 requirement. The Docker image works around this by using the official `spire-agent` CLI (production sidecar-fetch pattern) instead of the Python SPIFFE client. For local runs, use a fresh venv and either pin `protobuf<6` or skip the Python SPIFFE workload-API path.

## Running locally

```bash
# 1. Install the runtime (from the repo root)
./scripts/setup-dev.sh --skip-go
source python/.venv/bin/activate

# 2. Pick a provider + model id
export ARDUR_PROVIDER=ollama
export OLLAMA_MODEL='<your local model tag>'

# 3. Run the demo from this directory
cd examples/autogen-quickstart
PYTHONPATH=../_shared python demo.py
```

`setup-dev.sh` defaults to `python3.13` and creates `python/.venv`. For a manual
install instead, use Python 3.10 or newer (`python/pyproject.toml` enforces this),
run `python -m pip install --upgrade pip` first, then
`python -m pip install -e python/`; macOS system Python 3.9 and its bundled pip
are too old for the PEP 660 editable install.

`ARDUR_PROVIDER` selects the backend. The matching `*_MODEL` env var is required — no model identifiers are hard-coded in `demo_scenes.py` per the project rule (see [CONTRIBUTING.md](../../CONTRIBUTING.md)).

## Building the Docker image

The `Dockerfile` builds from the ardur repo root (the COPY paths assume that build context):

```bash
cd ../..   # back to ardur repo root
docker buildx build \
    --platform linux/amd64,linux/arm64 \
    -f examples/autogen-quickstart/Dockerfile \
    -t rahulnutakki/ardur-demo:autogen \
    --push .
```

The image stages the official `ghcr.io/spiffe/spire-agent:1.14.2` binary, installs the AutoGen 0.4 stack, and copies `python/vibap`, the `_shared` helpers, and this directory's `demo.py` into `/app/`. As with the LangChain image: no model identifiers, no API keys are baked in.

### Recorded-asciinema safety note

When recording demos, NEVER pass provider keys via `docker run -e KEY=VAL`. asciinema captures the subprocess command line, which leaks the key into any `.cast` file. Use `--env-file ./.env` instead.

## Out of scope for this example

- Multi-agent group chat (`SelectorGroupChat`, `RoundRobinGroupChat`) — single-agent flow only. Group chat receipts need turn-attribution semantics that aren't settled yet.
- Real-cluster SPIRE deployment — the example uses the in-image `spire-agent` against a local SPIRE server. Cluster identity comes later under `deploy/k8s/spire/`.
- Live LLM provider failover — single provider per run.
- Multi-tenant key isolation — single issuer key.

The protocol-only flow is in [`examples/missions/`](../missions/).
