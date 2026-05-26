---
title: "Examples"
description: "Runnable examples, protocol-only fixtures, and deferred adapter specs without mixing their maturity."
weight: 50
maturity: ["public-now", "in-progress"]
claim_types: ["integration", "runtime-boundary"]
surfaces: ["examples", "python", "docs"]
frameworks: ["framework-agnostic", "langchain", "langgraph", "autogen", "claude-code", "openai-agents-sdk", "google-adk"]
evidence_levels: ["code-and-doc", "limitation-backed"]
---

## Runnable Today

{{< resource-grid >}}
{{< resource-card title="Mission files" path="examples/missions/" status="public-now" meta="protocol-only" >}}
JSON mission examples with no framework dependency.
{{< /resource-card >}}
{{< resource-card title="LangChain quickstart" path="examples/langchain-quickstart/README.md" status="public-now" meta="runnable" >}}
Runnable integration path for LangChain agents.
{{< /resource-card >}}
{{< resource-card title="LangGraph quickstart" path="examples/langgraph-quickstart/README.md" status="public-now" meta="runnable" >}}
Runnable integration path for LangGraph workflows.
{{< /resource-card >}}
{{< resource-card title="AutoGen quickstart" path="examples/autogen-quickstart/README.md" status="public-now" meta="runnable" >}}
Runnable integration path for AutoGen examples.
{{< /resource-card >}}
{{< resource-card title="Claude Code plugin" path="plugins/claude-code/README.md" status="public-now" meta="coding agent" >}}
Plugin and hook path for Claude Code lifecycle governance.
{{< /resource-card >}}
{{< resource-card title="Browser extension" path="examples/ardur-personal-extension/README.md" status="public-now" meta="personal" >}}
Ardur Personal browser adapter that talks to the local Hub.
{{< /resource-card >}}
{{< resource-card title="Desktop observe" path="examples/ardur-personal-desktop/README.md" status="public-now" meta="personal" >}}
Local desktop observation adapter for Ardur Personal.
{{< /resource-card >}}
{{< resource-card title="Native host" path="examples/ardur-personal-native-host/README.md" status="public-now" meta="personal" >}}
Browser native-messaging bridge for the local Hub.
{{< /resource-card >}}
{{< /resource-grid >}}

## Adapter Specs

These directories are intentionally not advertised as runnable examples until
code and tests land.

{{< resource-grid >}}
{{< resource-card title="OpenAI Agents SDK adapter spec" path="examples/openai-agents-sdk/README.md" status="planned" meta="adapter spec" >}}
Design notes for a future adapter; not presented as runnable code yet.
{{< /resource-card >}}
{{< resource-card title="Google ADK adapter spec" path="examples/google-adk/README.md" status="planned" meta="adapter spec" >}}
Design notes for a future adapter; not presented as runnable code yet.
{{< /resource-card >}}
{{< /resource-grid >}}

Primary source: {{< repo-link "examples/README.md" >}}.
