# Known Limitations

This page distinguishes documented product boundaries from implementation bugs.

## Research and foundation surfaces not yet broad runtime claims

- semantic judging is advisory unless a specific runtime policy path consumes
  its verdict
- behavioral templates are the intended deterministic direction, but broad
  marketing claims still require template coverage and L5 evidence
- streaming reconciliation and active revocation primitives exist, but broader
  framework-live proof remains a follow-on for some surfaces
- manual reconciliation is implemented at an API-first foundation layer; richer
  operator UX is follow-on work
- TEE support is not yet a general hardware-rooted production claim until real
  vendor quote verification and proof-of-possession artifacts exist
- nested attestation primitives exist, but framework-level end-to-end evidence
  still needs expansion
- fast HMAC is intentionally not a cross-organization non-repudiation tier

## Evidence limits

If a delegated tool or gateway can hide all relevant side effects and emits no
evidence, Ardur must classify the result as `insufficient_evidence` (resulting
in an `unknown` verdict at the session/verifier level) rather than safe. See
[`coverage-map.md`](coverage-map.md) for the receipt-level evidence taxonomy.

## Product limits

Ardur is not:

- a sandbox by itself
- a universal semantic-safety engine
- a replacement for identity, workload isolation, or network controls

Those controls still matter around Ardur.

## Verifier-contract conformance gaps (reference proxy, 2026-04-28)

The reference Python proxy in `python/vibap/` implements the
**Delegation-Core** profile of `verifier-contract-v0.1`, not the
**MIC-State** or **MIC-Evidence** profiles. When closing these gaps,
update both this document and [`security-model.md`](security-model.md)
in the same PR to prevent drift. The following spec `MUST`
clauses are design-only in the reference implementation today:

- `observed_manifest_digest == MD.tool_manifest_digest` (Section 6.3 #6)
- per-grant `last_seen_receipts` tracking (Section 5.7)
- MIC-Evidence visible-receipt-linkage / hidden-hop detection
  (Section 6.3 #7)
- explicit invocation-envelope signature (Section 6.3 #5) beyond the
  credential JWT

Deployments that need MIC-State or MIC-Evidence conformance MUST add
verifier layers beyond the reference proxy or wait for the hardening
rounds that close these gaps. See `docs/specs/verifier-contract-v0.1.md`
Section 13 for the full conformance map.

## Mission Declaration schema enforcement (2026-04-28 hardening)

After the round-3 hostile re-audit, the MD loader unconditionally
enforces FIVE of the seven audit-flagged v0.1 spec members
(`receipt_policy`, `conformance_profile`, `tool_manifest_digest`,
`revocation_ref`, `governed_memory_stores`). The two omitted members
are intentional, not oversights:

- **`approval_policy`** — absence is treated by the proxy as "no
  approval gate", which is a visible operator choice. Including it in
  the always-required list would force every tool call in deployments
  that don't use approvals to carry an `operator_id`.
- **`probing_rate_limit`** — round-2 audit flagged validate-but-don't-
  enforce theater. The runtime currently has no rate-limiter consuming
  the value, so requiring it without downstream effect is accuracy debt.
  It returns to the always-required list once a per-mission rate-limiter
  actually consumes it.

Both members ARE required under `strict_schema=True`. Full v0.1 schema
validation (including `additionalProperties: false` at the root) is
opt-in via `strict_schema=True` on `load_mission_declaration` /
`fetch_mission_declaration`. Existing producers that mix legacy fields
(`allowed_tools` etc.) with v0.1 MDs will fail strict validation; clean
v0.1 producers should set the flag.

The canonical schema doc at `docs/specs/mission-declaration-v0.1.schema.json`
is mirrored to `python/vibap/_specs/mission_declaration_v01.schema.json`
so the runtime can validate without depending on the docs tree on disk.
The two files are kept byte-identical by the
`spec-schema-sync` job in `.github/workflows/validate-formats.yml`,
which fails the build on drift (FIX-R3-B from round-3 re-audit).

## Bounded JWT iat skew at every verifier (2026-04-28 round-3 + round-4 + round-5)

Round-2 hostile re-audit flagged that FIX-6's bounded-iat-skew gate
only protected receipts; AAT, Mission Declaration, status-list, and
passport JWT loaders all still accepted `iat=year_3000`. Round-3 lifted
the gate into a shared `vibap.passport.assert_iat_in_window` helper
applied at every JWT decode call site. Round-4 and round-5 extended the
gate to the parallel-format and Go verifiers the round-3 prompt missed.

The full set of bounded-iat surfaces is now:

**Python JWT verifiers (assert_iat_in_window helper):**
- `vibap.passport._decode_passport`
- `vibap.aat_adapter.decode_aat_claims`
- `vibap.mission.load_mission_declaration`
- `vibap.mission.mission_is_revoked` (status list)
- `vibap.receipt.verify_receipt`
- `vibap.attestation.verify_attestation` (round-4 FIX-R4-3)
- `vibap.spiffe_identity.verify_jwt_svid` (round-4 FIX-R4-4)
- `vibap.memory.GovernedMemoryStore.read` (round-5 FIX-R5-M3)
- `vibap.tool_response_provenance.verify_tool_response_envelope` (round-5 FIX-R5-M4; uses tighter ±60s future window for short-lived tokens)

**Python parallel-format / non-JWT verifiers:**
- `vibap.biscuit_passport.verify_biscuit_passport` (round-4 FIX-R4-1; round-5 FIX-R5-H5 walks every block, not just leaf)
- `vibap.training_attestation.verify_bundle` (round-5 FIX-R5-H6; future-skew now unconditional, was gated on `max_age_s`)

**Go verifiers (mirrored fail-closed pattern):**
- `go/pkg/credential/verify.go::Verify` (SD-JWT-VC; round-3 FIX-R4-2)
- `go/pkg/credential/delegation.go::VerifyPassport` (round-5 FIX-R5-H3)
- `go/pkg/credential/status.go::ParseStatusListToken` (round-5 FIX-R5-H4)

Default Python window is ±300s future / 30 days past. Each call site
disables PyJWT's stock `verify_iat` (which uses zero leeway and clashes
with cross-node clock drift) in favor of the explicit window. Archival
re-verification can pass `future_skew_s=None`/`past_skew_s=None` per
call. Go uses a tighter 30s default consistent with the SD-JWT-VC
profile's clock-drift tolerance.

## Operator + webhook /metrics endpoints (deployment hardening required)

The `cmd/operator` and `cmd/webhook` binaries expose Prometheus metrics
on `:8080/metrics` via controller-runtime's default `metricsserver`,
without an `AuthorizeFunc` or `FilterProvider`. This is a deliberate
controller-runtime convention: production operators are expected to
gate metrics at the deploy layer with one of:

- a `kube-rbac-proxy` sidecar that requires a Kubernetes `ServiceAccount`
  bearer token with the `metrics.k8s.io` API group,
- a `NetworkPolicy` that limits the metrics port to the cluster's
  Prometheus operator pod, or
- a service-mesh `AuthorizationPolicy` (Istio/Linkerd).

The reference `deploy/k8s/spire/` manifests do NOT ship a metrics-auth
sidecar today. Production deployments MUST configure one. This is
documented here as a known limitation rather than a code-level fix
because the right answer is deployment-environment-specific.

## Bearer-token authentication on Go control-plane services (2026-04-29 round-5)

Round-4 audit flagged that the Go Authority and Governor HTTP services
were unauthenticated — anyone with network reach could mint credentials
or ingest fabricated governance events. Round-5 closes both:

- `go/cmd/authority`: `/sign` and `/status` require
  `Authorization: Bearer <token>` matching `ARDUR_AUTHORITY_TOKEN`
  (≥32 bytes). The binary refuses to start unless the token is set or
  `--no-require-auth` is passed for explicit local-dev opt-out. Public
  endpoints (`/attestation`, `/public-key`, `/healthz`) remain
  unauthenticated since they advertise the trust anchor.
- `go/pkg/governance.NewHandlerWithAuth` wires every `/v1/*` route
  through a constant-time bearer-check. `cmd/governor/main.go` reads
  `ARDUR_GOVERNOR_TOKEN` from env; `Validate()` refuses to start
  without it (or without explicit `ARDUR_GOVERNOR_NO_REQUIRE_AUTH=1`
  opt-out). `/healthz` and `/readyz` stay public for K8s probes.

Both services use `crypto/subtle.ConstantTimeCompare` to defeat timing
side-channel inference of the token. **Round-7+ also SHA-256-normalizes
both presented and expected tokens before the constant-time compare**
(`sha256.Sum256(token)` on each side, comparison over the 32-byte
digests) — this defeats the length oracle that
`subtle.ConstantTimeCompare` short-circuits on length-mismatched
inputs. The Python proxy's `hmac.compare_digest` path does the same
SHA-256 normalization. Production deployments SHOULD also front the
services with mTLS at the ingress / service-mesh layer for
defense-in-depth.

Operator-supplied bearer tokens are `strings.TrimSpace`-ed (Go) /
`.strip()`-ed (Python) at every entry point — env vars
(`ARDUR_AUTHORITY_TOKEN`, `ARDUR_GOVERNOR_TOKEN`, `VIBAP_API_TOKEN`)
and CLI args (`--api-token`) — so YAML-quoted secrets with leading
or trailing whitespace authenticate correctly without operator
debugging time. The bearer-scheme parse is RFC 9110-compliant
case-insensitive (`Bearer`, `bearer`, `BEARER` all accepted).

## `_pinned_urlopen` semantics (2026-04-28 round-3)

The pinned-IP fetch path used by the SSRF-resistant Mission Declaration
and status-list fetchers (`vibap.mission._pinned_urlopen`) explicitly
**rejects HTTP redirects** (any 3xx → `URLError`) instead of following.
Following would re-resolve DNS at each hop and bypass the pinned-IP
guard. Producers that need redirects must reconfigure their server to
serve the final URL directly. Non-2xx response status codes (4xx/5xx)
also raise `HTTPError`, matching the contract `urllib.request.urlopen`
provides — without this, a 500 body would be passed to the JWT decoder
downstream and fail with a noisy parse error rather than a clean fetch
error.

## AAT proof-of-possession default (2026-04-28 hardening)

`material_from_aat_grant` and `GovernanceProxy.start_session_from_aat`
default to `require_pop=True`. A cnf-bearing AAT presented without
`holder_public_key` + `kb_jwt` now fails closed. Bearer-mode AATs
(no `cnf` claim) continue to be accepted; library callers that
legitimately need bearer-style acceptance of a cnf-bearing AAT MUST
opt out explicitly with `require_pop=False` so the security choice is
visible at the call site.

The HTTP `/sessions` endpoint plumbs `require_pop`,
`holder_public_key_pem`, and `kb_jwt` through the request body, with
the same fail-closed default.

## Revocation fail-closed (2026-04-28 hardening, FIX-1)

`go/pkg/credential.Verify` no longer fail-opens when a credential
carries a status claim and no `StatusClient` is configured. Callers
must either provide a `StatusClient` or set `opts.SkipStatusCheck=true`
explicitly. The Python loader has always fetched the status list when
present; this fix brings the Go path to the same posture.
