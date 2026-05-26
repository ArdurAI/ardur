---
title: "Proof & Test Results"
description: "Real-world evidence that Ardur's governance works."
weight: 55
maturity: ["public-now"]
claim_types: ["proof-media", "runtime-boundary"]
surfaces: ["python", "tests"]
frameworks: ["ollama", "framework-agnostic"]
evidence_levels: ["code-and-doc"]
---

Ardur doesn't ask you to trust marketing claims. Here's the actual data from
tests with real models.

---

## Cloud Model Governance Test

We asked a cloud model with 1-trillion-parameter capacity to build a complete
Code Repository Manager — a mini-GitHub clone with repositories, commits,
branches, issues, pull requests, search, and an admin dashboard. 20 files,
~2000+ lines of code each, all Python stdlib.

**Every single tool call went through Ardur first.**

### Results

| Model | Type | Duration | Tool Calls | Files Built | Denials |
|-------|------|----------|------------|-------------|---------|
| **Cloud Model** | Cloud · 1T params | 12 min | 35 | 18 of 20 | **0** |
| **Local Model** | Local · 5GB | 15 min | 4 | 4 of 20 | **0** |

### What this proves

1. **Zero false denials.** The proxy never blocked a legitimate tool call.
   Every `PERMIT` was correct.
2. **Negligible overhead.** Ardur added ~4ms to each tool call. The model's
   thinking time dominated — governance is not the bottleneck.
3. **Works with cloud and local models.** Both Ollama cloud API and local
   Ollama models work without changes.
4. **Handles sustained workloads.** The cloud model ran for 12 minutes across 35 tool
   calls without a single governance failure.

### How to reproduce

```bash
# Set your Ollama API key
export ARDUR_OLLAMA_API_KEY="your-key"

# Run the test
cd python
PYTHONPATH=. python tests/run_cloud_model_test.py "$MODEL_NAME"

# Results land in tests/test-results/
```

The test script and all result data are in the repo at
`python/tests/run_cloud_model_test.py` and `python/tests/test-results/`.

---

## Go AAT Engine Tests

The Go AAT package has **49 tests** covering the full Attenuating
Authorization Token specification:

- All 13 constraint types (Exact, Pattern, Range, OneOf, etc.)
- Cross-type constraint subsumption
- Root AAT issuance with holder binding
- Child derivation with depth tracking and parent-chain linking
- Proof of Possession (PoP) JWT round-trips
- Full §7 chain verification (8-step algorithm)

```bash
cd go && go test ./pkg/aat/... -v
# 49 passed, 0 failures
```

---

## CI & Automated Checks

Every push and PR runs:

| Check | What it does |
|-------|-------------|
| Python 3.10 + 3.13 | Full pytest suite |
| Go | `go test ./...` + `go vet ./...` |
| CodeQL | Static analysis for Python + Go |
| Secret scan | gitleaks + forbidden-term gate |
| Link check | lychee on all markdown links |
| Format validation | JSON + YAML parse on all files |
| Hugo build | Site builds cleanly |

---

## The honest caveat

What you see above is real, but the test surface is not yet exhaustive:

- The cloud model test runs 30-turn sessions — longer runs are possible but not
  yet in the automated suite.
- Kernel-level capture (eBPF) is implemented but the full integration test
  harness isn't public yet.
- These are single-session tests — multi-tenant, concurrent session testing
  is on the roadmap.

The [coverage map]({{< relref "/source/docs/coverage-map/" >}})
and [known limitations]({{< relref "/source/docs/known-limitations/" >}})
keep the full picture current.
