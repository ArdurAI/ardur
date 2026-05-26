---
title: "Try It"
description: "The shortest source-backed local path through Ardur today."
weight: 30
maturity: ["public-now"]
claim_types: ["orientation", "runtime-boundary", "evidence-semantics"]
surfaces: ["python", "examples", "docs", "scripts"]
frameworks: ["framework-agnostic", "claude-code"]
evidence_levels: ["code-and-doc"]
---

The fastest current path has two tracks:

1. **No-key confidence check:** run the fresh-user evidence harness. It exercises
   source/local-wheel install, `ARDUR.md`, `ardur protect claude-code`,
   `ardur doctor-claude-code`, simulated Claude Code hook allow/deny receipts,
   and `ardur claude-code-report` without contacting a live LLM provider.
2. **Live Claude Code demo:** if the `claude` binary is already installed and
   authenticated, run one protected local Claude Code session and inspect the
   signed receipt chain.

Start with the one-screen source-backed walkthrough:

- {{< repo-link "docs/guides/claude-code-mvp-quickstart.md" "Claude Code MVP quickstart" >}}
- {{< repo-link "docs/guides/phase1-demo-packet.md" "Phase 1 demo packet" >}}
- {{< repo-link "docs/guides/read-phase1-evidence-bundle.md" "Evidence-bundle reader" >}}

The protocol-only path below remains useful when you just want to check mission
issuance and verification without the Claude Code plugin.

```bash
cd python
pip install -e .
ardur issue \
  --agent-id alice \
  --mission "summarize sales from sales/q1.csv into reports/" \
  --allowed-tools read_file write_report \
  --resource-scope 'sales/*' 'reports/*'
ardur verify --token '<token-from-issue-output>'
```

That path covers mission compilation, passport issuance, signing, and
verification. For local product usage, start with the Personal Hub and Claude
Code plugin docs.

## Next Paths

- {{< repo-link "docs/reference/cli.md" "CLI reference" >}}
- {{< repo-link "docs/guides/ardur-personal-hub.md" "Ardur Personal Hub guide" >}}
- {{< repo-link "plugins/claude-code/README.md" "Claude Code plugin" >}}
- {{< repo-link "examples/langchain-quickstart/README.md" "LangChain quickstart" >}}
- {{< repo-link "examples/langgraph-quickstart/README.md" "LangGraph quickstart" >}}
- {{< repo-link "examples/autogen-quickstart/README.md" "AutoGen quickstart" >}}

## Keep In Mind

OpenAI Agents SDK and Google ADK are currently deferred adapter specs, not
runnable examples. Rerunnable proof media is also not public yet.
