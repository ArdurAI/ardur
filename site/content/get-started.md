---
title: "Get Started"
description: "Install Ardur and run your first governed AI session in 5 minutes."
weight: 5
maturity: ["public-now"]
claim_types: ["orientation"]
surfaces: ["python", "go", "examples"]
frameworks: ["framework-agnostic", "claude-code", "ollama"]
evidence_levels: ["code-and-doc"]
---

## Pick your path

Ardur works anywhere Python 3.10+ runs. Choose the setup that matches your setup.

---

### Mac (Apple Silicon or Intel)

```bash
# 1. Clone the repo
git clone https://github.com/ArdurAI/ardur.git
cd ardur/python

# 2. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install pyjwt cryptography

# 4. Verify it works
PYTHONPATH=. python -c "from vibap.passport import generate_keypair; generate_keypair()"
```

**Done.** You can now issue mission passports and run the governance proxy.

---

### Linux (Ubuntu / Debian / Fedora)

```bash
# 1. Clone and set up Python
git clone https://github.com/ArdurAI/ardur.git
cd ardur/python
python3 -m venv .venv && source .venv/bin/activate
pip install pyjwt cryptography

# 2. Optional: build the Go AAT engine
cd ../go && go build ./...
```

---

### VM / Sandbox / Remote Server

Same as Linux above. The proxy listens on `127.0.0.1` by default — if you need
remote access, set up an SSH tunnel or reverse proxy. The proxy supports mutual
TLS for production deployments.

---

### Docker (coming soon)

A Docker Compose file and prebuilt images are on the roadmap. For now, clone
the repo and run directly.

---

## Connect your AI agent

### With Ollama (local models)

Ardur works with any model running in Ollama. The proxy is provider-agnostic —
it evaluates tool calls, not model outputs.

```bash
# Start Ollama with a local model
ollama pull <your-model>
ollama serve

# Run the governance proxy
PYTHONPATH=python python -m vibap.cli hub start
```

### With Ollama (cloud models)

For larger models via Ollama's cloud API:

```bash
export OLLAMA_API_KEY="your-api-key"

# Run the full governance test
PYTHONPATH=python python tests/run_cloud_model_test.py "$MODEL_NAME"
```

This runs a real-world test: a cloud model builds a complete web application
while every tool call goes through Ardur's governance check.

### With Claude Code

Ardur ships a native Claude Code plugin:

```bash
# Initialize a mission profile
PYTHONPATH=python python -m vibap.cli profile init

# Protect your Claude Code session
PYTHONPATH=python python -m vibap.cli protect claude-code
```

See the [Claude Code plugin README]({{< relref "/source/plugins/claude-code/README.md" >}}) for the full setup.

### With LangChain / LangGraph / AutoGen

Runnable quickstarts live in the examples directory:

- [LangChain quickstart]({{< relref "/source/examples/langchain-quickstart/readme/" >}})
- [LangGraph quickstart]({{< relref "/source/examples/langgraph-quickstart/readme/" >}})
- [AutoGen quickstart]({{< relref "/source/examples/autogen-quickstart/readme/" >}})

---

## Run your first governed session

Here's the shortest end-to-end path:

```bash
# 1. Start the governance proxy
cd python
PYTHONPATH=. python -m vibap.cli hub start

# 2. In another terminal, issue a mission passport
PYTHONPATH=. python -m vibap.cli issue \
  --agent-id "my-agent" \
  --mission "read files in /tmp and write reports" \
  --allowed-tools read_file write_file \
  --resource-scope /tmp \
  --max-tool-calls 50

# 3. Use the token to start a session
# (The CLI prints the token — copy it)
curl -k -X POST https://127.0.0.1:<port>/session/start \
  -H "Content-Type: application/json" \
  -d '{"token": "<your-token>"}'

# 4. Evaluate tool calls through the proxy
curl -k -X POST https://127.0.0.1:<port>/evaluate \
  -H "Content-Type: application/json" \
  -d '{"session_id": "<session-id>", "tool_name": "read_file", "arguments": {"path": "/tmp/test.txt"}}'
```

Each `/evaluate` call returns PERMIT or DENY with a signed receipt.

---

## Next steps

- [See real-world test results]({{< relref "/proof" >}}) — cloud models governed by Ardur
- [Read the CLI reference]({{< relref "/source/docs/reference/cli/" >}})
- [Understand the security model]({{< relref "/source/docs/security-model/" >}})
- [Browse the examples]({{< relref "/examples" >}})
