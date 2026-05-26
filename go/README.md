# Ardur — Go Runtime

Go handles the parts of Ardur where Python falls short: Linux eBPF kernel
capture, Kubernetes control-plane components (operator, admission webhook),
and the AAT (Attenuating Authorization Token) credential-attenuation engine.
The governance proxy, CLI, and Personal Hub live in the Python tree
(`python/vibap/`), which is the primary runtime.

## Module

```
module github.com/ArdurAI/ardur/go
```

## Build

```bash
cd go
go mod tidy
go build ./...
go test -race ./...
```

## Layout

| Path | What lives here |
|---|---|
| `pkg/aat` | AAT credential-attenuation engine — constraint checks, subsumption, JWT issuance/derivation, PoP binding, and full chain verification per AAT §3-7 |
| `pkg/api/v1alpha1` | CRD types for the Kubernetes operator (`AgentPassport`, etc.) |
| `pkg/credential` | Mission credential issuance + verification (SD-JWT-VC types for the K8s operator) |
| `pkg/issuer` | Mission Declaration issuer + signing-key management |
| `pkg/kernelcapture` | Linux eBPF process-exec capture harness (cilium/ebpf) |
| `pkg/policy` | Policy evaluation surface (Cedar bridge) |
| `pkg/profiling` | Performance profiling helpers |
| `pkg/provenance` | Tool-response provenance + Sigstore verification |
| `pkg/spiffe` | SPIFFE/SPIRE identity binding |
| `pkg/transparency` | Transparency-log integration (Rekor) |
| `pkg/trust` | Trust-bundle management and scoring |
| `cmd/operator` | Kubernetes operator (reconciles `AgentPassport` CRs) |
| `cmd/webhook` | Admission webhook for K8s |
| `benchmark/` | Benchmark scenario types + live evaluation harness |

## AAT Package

The `pkg/aat` package implements the full Attenuating Authorization Token
specification:

- **Constraint engine** — 13 constraint types (Exact, Pattern, Range, OneOf,
  NotOneOf, Contains, Subset, Regex, Wildcard, All, Any, Not, CEL) with
  full check and subsumption semantics per AAT §3.4-3.5.
- **Issuance + derivation** — `IssueRoot` creates root AATs with
  `del_depth=0` and `cnf.jwk` holder binding; `DeriveChild` increments
  depth, computes `par_hash` via SHA-256 of the parent signing input, and
  enforces invariants I1-I5 (signer linkage, depth monotonicity, TTL
  monotonicity, capability monotonicity, cryptographic linkage).
- **Proof of Possession** — `BuildPoPJWT` and `VerifyPoPJWT` with JCS-style
  HTA canonicalization per AAT §5.2-5.3.
- **Chain verification** — 8-step offline verification algorithm per AAT
  §7: structural validation → root verification (3a-3n) → link
  verification (4a-4s) → depth match → leaf constraint check → PoP
  verification → verdict.
- **49 tests** covering constraint checks, subsumption cross-types,
  issuance, derivation, PoP round-trips, and full chain verification
  scenarios.

```bash
cd go && go test ./pkg/aat/... -v   # full AAT test suite
```

## Relationship to Python

The Python runtime (`python/vibap/`) is the primary governance surface:
proxy, CLI, Personal Hub, and all HTTP-accessible endpoints live there.
The Go packages here serve two roles:

1. **K8s-native control plane** — `cmd/operator` and `cmd/webhook` reconcile
   `AgentPassport` CRDs and enforce admission policy inside a cluster. The
   operator depends on the full `pkg/` type chain (credential → issuer →
   policy → provenance → spiffe → trust → transparency).

2. **Kernel capture** — `pkg/kernelcapture` uses Linux eBPF (cilium/ebpf) to
   capture process-exec events below the tool-call boundary. This cannot be
   done in pure Python; it requires C eBPF programs and Go's ring-buffer
   management.

The governance proxy, session lifecycle, evaluate/attest endpoints, rate
limiting, kill switch, and Prometheus metrics are all implemented in Python.
No Go equivalent exists for those — Python is the canonical runtime for the
governance HTTP API.

## What's not in this tree

- **Governance HTTP proxy** — lives in `python/vibap/proxy.py`.
- **CLI** — lives in `python/vibap/cli.py`.
- **Personal Hub** — lives in `python/vibap/personal_hub.py`.
- **Benchmark harness binaries** — the `cmd/benchmark*` and `cmd/benchcheck`
  binaries were removed; benchmark scenario types live in `benchmark/`.
- **Vendor-specific telemetry connectors** — stay private.
- **Live benchmark fixtures** — AgentDojo, InjecAgent, R-Judge, STAC remain
  in the internal research tree.

## Stable identifiers (don't drift these)

- Module path: `github.com/ArdurAI/ardur/go`
- Schema `$id` base: `https://ardur.dev/spec/...`
- API GroupName: `vibap.ardur.dev`
- SPIFFE trust domain: `ardur.dev`
- Image refs in tests: `ghcr.io/ardur/...`

## License

MIT — see [../LICENSE](../LICENSE).
