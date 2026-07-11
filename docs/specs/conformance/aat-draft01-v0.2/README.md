# Ardur AAT Draft-01 DG v0.2 Fixture

`fixture.json` is a deterministic Ardur implementation self-test for
`ardur.dg.aat-draft-01.v0.2`. It contains an organically signed
root/child/grandchild chain, a proof-of-possession JWT bound to an enforcement
audience, and only public verification keys.

Regenerate it from the Go module:

```bash
go run ./cmd/aat-draft01-fixture > ../docs/specs/conformance/aat-draft01-v0.2/fixture.json
```

The generator self-verifies the chain before writing output, and its unit test
requires byte-for-byte equality with the committed artifact.

## Claim Boundary

This is Ardur-generated implementation evidence. It is not an independent
fixture, IETF conformance evidence, or proof of interoperability. The
draft-author Tenuo repository currently exposes a different CBOR warrant
fixture rather than a draft-01 JWT fixture, so Ardur records independent
interoperability as not demonstrated.
