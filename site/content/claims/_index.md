---
title: "Claims"
description: "Each public claim gets metadata, taxonomy terms, and source paths."
weight: 60
maturity: ["public-now", "in-progress"]
claim_types: ["runtime-boundary", "delegation", "evidence-semantics", "proof-media", "protocol-spec", "deployment"]
surfaces: ["docs", "python", "go", "scripts", "media", "deploy", "specs"]
frameworks: ["framework-agnostic", "claude-code", "gemini-cli", "framework-live", "foundation", "kubernetes", "spire"]
evidence_levels: ["code-and-doc", "limitation-backed", "archival-media", "spec", "doc-and-manifest"]
---

Claim pages are generated from curated metadata in `site/data/claims.json`.
The validator fails the build if a claim points at a missing source path.
