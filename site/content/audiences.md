---
title: "Audiences"
description: "Who Ardur is for and which path each visitor should take first."
weight: 81
maturity: ["public-now", "in-progress"]
claim_types: ["orientation", "integration", "runtime-boundary"]
surfaces: ["docs", "python", "go", "examples", "deploy"]
frameworks: ["framework-agnostic", "claude-code", "langchain", "langgraph", "autogen", "kubernetes", "spire"]
evidence_levels: ["code-and-doc", "doc-and-manifest"]
---

## Technical Evaluators

Start with [What Works Now]({{< relref "/what-works-now.md" >}}), then inspect
the [Claim Ledger]({{< relref "/claims/_index.md" >}}), specs, tests, and
known limitations.

## Potential Users

Start with [Try It]({{< relref "/try-it.md" >}}), then read the Ardur Personal
Hub guide and Claude Code plugin README.

## Contributors

Start with [Work In Progress]({{< relref "/work-in-progress.md" >}}), then read
the contributing guide, tests guide, and examples index.

## Platform And Security Engineers

Start with the security model, protocol specs, deployment notes, and limitation
pages before treating any deployment surface as production-complete.

- {{< repo-link "docs/security-model.md" "Security model" >}}
- {{< repo-link "docs/specs/README.md" "Specs" >}}
- {{< repo-link "deploy/README.md" "Deployment overview" >}}
- {{< repo-link "docs/known-limitations.md" "Known limitations" >}}
