---
title: "Build And Integrate"
description: "Public runtime surfaces, runnable framework quickstarts, the Ardur Personal Hub, the Claude Code plugin, and the deployment material that still needs hardening."
weight: 40
maturity: ["public-now", "in-progress"]
claim_types: ["runtime-boundary", "deployment"]
surfaces: ["python", "go", "examples", "deploy"]
frameworks: ["framework-agnostic", "kubernetes", "spire"]
evidence_levels: ["code-and-doc", "doc-and-manifest"]
---

The public repo is code-bearing today. LangChain, LangGraph, and AutoGen
quickstarts run end-to-end; the Ardur Personal Hub service and Claude Code
plugin ship with signed receipts and a Markdown profile path; dedicated Python
(3.10 + 3.13) and Go CI gate every push. A tagged packaged release with a
regenerated Homebrew formula, runnable OpenAI Agents SDK and Google ADK
adapters, Codex and Claude Desktop integrations, and broader deployment
material remain in the next hardening wave.

Use [Use And Troubleshooting]({{< relref "use-and-troubleshooting.md" >}}) as
the hosted documentation map for README material, quickstarts, deployment
notes, testing, security, limitations, article references, technical
reference pages, and contributor process docs.
