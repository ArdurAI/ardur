---
title: "Python And Go Runtime Surfaces"
description: "Curated runtime imports are public; dedicated Python and Go CI run on every push and pull request."
weight: 41
maturity: ["public-now"]
claim_types: ["runtime-boundary"]
surfaces: ["python", "go"]
frameworks: ["framework-agnostic"]
evidence_levels: ["code-and-doc"]
---

{{< claim "mission-boundary" >}}

The Python and Go directories are public runtime surfaces. Dedicated Python
(3.10 + 3.13) and Go test jobs run on every push and pull request via
`.github/workflows/tests.yml`, alongside CodeQL, link-check, secret-scan,
format validation, and the Hugo site build.

## Go AAT Engine

The `go/pkg/aat` package implements the JWT path of the Attenuating
Authorization Token profile:

- **13 constraint types** with full check and subsumption semantics
- **IssueRoot / DeriveChild** with holder binding, depth tracking, and
  cryptographic parent-chain linking
- **BuildPoPJWT / VerifyPoPJWT** with deterministic HTA canonicalization
- **VerifyChain** — the 8-step offline verification algorithm per AAT §7
- **Tests** covering constraint checks, cross-type subsumption, issuance,
  derivation, PoP round-trips, and full chain scenarios

CWT integer claim-key mapping remains pending, so this is not a complete claim
for every AAT serialization profile.

## Verification Boundary

`python/tests/run_cloud_model_test.py` contains the live-provider governance
harness. It routes configured tool requests through the proxy. The redacted
public tree keeps historical aggregate reports but does not ship raw per-model
fixture artifacts, so those reports are not presented as proof for the current
tree.

Current CI covers Python 3.10 and 3.13, Go, CodeQL, package contracts, and the
gated Linux BPF-LSM/seccomp proof harnesses. These checks do not establish
universal capture, provider-hidden visibility, or production kernel support on
macOS and Windows.

Sources: {{< repo-link "python/README.md" >}}, {{< repo-link "go/README.md" >}}, {{< repo-link "python/tests/run_cloud_model_test.py" "Cloud model harness" >}}, aggregate report path `python/tests/comprehensive_test_report.json`, and {{< repo-link ".github/workflows/tests.yml" "tests workflow" >}}.
