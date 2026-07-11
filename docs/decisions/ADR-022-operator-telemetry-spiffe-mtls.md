# ADR-022: SPIFFE mTLS identity for operator telemetry

- Status: Accepted
- Date: 2026-07-11
- Decision owners: Ardur Kubernetes operator and trust telemetry

## Context

The operator's `POST /telemetry/signal` endpoint changes an agent's runtime
trust score and may cause a NetworkPolicy tier transition. PR #55 added a
shared bearer token after review found the endpoint unauthenticated. That
blocked anonymous callers, but any valid token holder could still choose an
arbitrary payload `agent_id`, `source`, signal type, and severity.

The intended producers are monitoring workloads such as Tetragon, Kubescape,
and Ardur verifiers. They are collectors that may report on many target agents,
so the authorization boundary is the producer's asserted `source`, not an
incorrect equality check between the collector identity and every target
`agent_id`.

## Decision

1. The live telemetry endpoint uses TLS 1.3 mutual authentication with SPIFFE
   X.509-SVIDs obtained from the SPIFFE Workload API.
2. Each enabled source has one explicit command-line binding in
   `source=spiffe://trust-domain/path` form. Duplicate source names and duplicate
   SPIFFE IDs are configuration errors.
3. The mTLS handshake accepts only the configured SPIFFE IDs. After decoding a
   request, the handler also requires the authenticated peer ID to equal the ID
   bound to the payload's exact `source` value.
4. Source names are bounded ASCII identifiers. Unicode confusables are not
   accepted at this authorization boundary.
5. With no source bindings, the operator does not open the telemetry listener.
   If bindings are present but the Workload API, SVID, trust bundle, or listen
   socket cannot be initialized, operator startup fails instead of falling back
   to shared-token or unauthenticated ingestion.
6. The server identity and trust bundles remain rotation-aware through
   `workloadapi.X509Source`. The telemetry server is managed with the operator
   lifecycle and shuts down when the controller manager stops.

## Alternatives

### Shared bearer token

Rejected as the production boundary. It authenticates possession of one
cluster-wide secret but does not identify a producer or prevent a valid holder
from claiming another source. Provisioning and rotation also become an
application-specific secret-management burden.

### JWT-SVID

Not selected for this direct workload-to-workload channel. JWT-SVIDs are bearer
credentials and remain replayable if intercepted; the SPIFFE specification
recommends short expirations, narrow audiences, confidential transport, and
optional replay tracking. X.509-SVID mTLS already provides peer authentication,
channel confidentiality, integrity, and automatic rotation for this topology.

### Kubernetes ServiceAccount TokenReview

Not selected as the primary mechanism. It would provide audience-bound,
short-lived Kubernetes workload identity, but every credential remains a bearer
token, requires API-server availability or carefully bounded caching, and ties
the endpoint to Kubernetes. SPIFFE matches Ardur's existing cross-environment
identity layer and `go-spiffe` dependency.

### Require producer identity to equal target agent ID

Rejected because the trusted producers are multi-agent collectors. This would
make Tetragon, Kubescape, and verifier integrations impossible without creating
false per-agent identities for shared monitoring workloads.

## Consequences

- A deployment that enables live telemetry must run a SPIFFE Workload API,
  register the operator and each producer, mount the Workload API socket, and
  configure exact source bindings.
- A valid producer cannot impersonate another configured source, and an unknown
  workload cannot complete the TLS handshake.
- A compromised producer can still falsify observations within its assigned
  source and can target any registered agent. Preventing that requires stronger
  source-native evidence or hardware/producer attestation; mTLS cannot prove an
  observation's truth.
- Offline imported evidence is unchanged. It remains operator-supplied input
  with explicit source-assurance limits, not live authenticated sensor traffic.
- SPIRE deployment and rotation add operational cost, but they replace a
  manually distributed long-lived secret with short-lived workload identity.

## Verification

- Unit tests cover binding parsing, duplicate and Unicode-confusable rejection,
  missing/malformed identity, unknown identity, and cross-source forgery.
- An in-memory CA and synthetic X.509-SVIDs exercise a real mTLS handshake:
  configured identity succeeds, cross-source assertion returns `403`, and an
  unknown SPIFFE ID fails the handshake.
- Affected operator and trust packages run under the Go race detector.

## References

- [SPIRE mTLS use case](https://spiffe.io/docs/latest/spire-about/use-cases/)
- [SPIFFE X.509-SVID concepts](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/)
- [go-spiffe TLS configuration](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig)
- [JWT-SVID security considerations](https://spiffe.io/docs/latest/spiffe-specs/jwt-svid/)
