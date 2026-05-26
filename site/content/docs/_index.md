---
title: "Docs"
description: "Curated documentation entry points for using, evaluating, and contributing to Ardur."
weight: 40
maturity: ["public-now", "in-progress"]
claim_types: ["orientation", "runtime-boundary", "deployment", "protocol-spec"]
surfaces: ["docs", "python", "go", "deploy", "examples"]
frameworks: ["framework-agnostic", "kubernetes", "spire", "claude-code"]
evidence_levels: ["code-and-doc", "doc-and-manifest", "spec", "limitation-backed"]
---

Use this page before dropping into the full source mirror. Every card opens a
real source-backed document or generated mirror page.

## Use Ardur

{{< resource-grid >}}
{{< resource-card title="CLI reference" path="docs/reference/cli.md" status="public-now" meta="commands" >}}
Command entry points for issuing, verifying, and inspecting Ardur artifacts.
{{< /resource-card >}}
{{< resource-card title="Personal Hub guide" path="docs/guides/ardur-personal-hub.md" status="public-now" meta="local use" >}}
How the local Hub sits behind browser, desktop, and native-host adapters.
{{< /resource-card >}}
{{< resource-card title="Personal Hub API" path="docs/reference/personal-hub-api.md" status="public-now" meta="HTTP" >}}
The current HTTP surface exposed by Ardur Personal.
{{< /resource-card >}}
{{< resource-card title="ARDUR.md profile format" path="docs/reference/ardur-md-profile.md" status="public-now" meta="profile" >}}
The checked-in profile format for project-level mission and tool policy.
{{< /resource-card >}}
{{< resource-card title="Python package" path="python/README.md" status="public-now" meta="runtime" >}}
Python runtime, CLI, proxy, verifier, and policy surfaces.
{{< /resource-card >}}
{{< resource-card title="Go module" path="go/README.md" status="public-now" meta="runtime" >}}
Go verifier and governance code paths that mirror the protocol direction.
{{< /resource-card >}}
{{< /resource-grid >}}

## Evaluate Claims

{{< resource-grid >}}
{{< resource-card title="Status" path="STATUS.md" status="public-now" meta="repo truth" >}}
The current readiness snapshot and known public boundaries.
{{< /resource-card >}}
{{< resource-card title="Known limitations" path="docs/known-limitations.md" status="limitation-backed" meta="limits" >}}
What Ardur does not claim yet, including packaging and deployment maturity.
{{< /resource-card >}}
{{< resource-card title="Security model" path="docs/security-model.md" status="public-now" meta="security" >}}
Mission boundaries, denial semantics, trust assumptions, and failure modes.
{{< /resource-card >}}
{{< resource-card title="Media proof notes" path="MEDIA.md" status="in-progress" meta="proof media" >}}
Archival cast status and why rendered proof media is not claimed yet.
{{< /resource-card >}}
{{< /resource-grid >}}

The public [claim ledger]({{< relref "/claims/_index.md" >}}) ties each site
claim to source paths, tests, specs, or explicit limitations.

## Build And Contribute

{{< resource-grid >}}
{{< resource-card title="Examples index" path="examples/README.md" status="public-now" meta="examples" >}}
Runnable quickstarts, adapter specs, and protocol-only examples.
{{< /resource-card >}}
{{< resource-card title="Testing guide" path="docs/TESTING.md" status="public-now" meta="validation" >}}
Local and CI checks used to keep public claims honest.
{{< /resource-card >}}
{{< resource-card title="Contributing" path="CONTRIBUTING.md" status="public-now" meta="OSS" >}}
Contributor entry point for changes, reviews, and project expectations.
{{< /resource-card >}}
{{< resource-card title="Agent instructions" path="docs/agent-instructions/README.md" status="public-now" meta="agents" >}}
Repo-safe guidance for Conductor, Codex, and Claude contributors.
{{< /resource-card >}}
{{< resource-card title="Deployment overview" path="deploy/README.md" status="in-progress" meta="deployment" >}}
Current deployment manifests and the line between design surface and hardening.
{{< /resource-card >}}
{{< /resource-grid >}}

Full generated mirror: [Source]({{< relref "/source/_index.md" >}}).
