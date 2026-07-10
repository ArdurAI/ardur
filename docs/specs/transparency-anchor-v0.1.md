# Ardur Transparency Anchor v0.1

## 1. Status

This document defines the portable transparency sidecar emitted for Ardur
Execution Receipts. The schema identifier is:

```text
ardur.transparency_anchor.v0.1
```

The normative JSON Schema is
[`transparency-anchor-v0.1.schema.json`](./transparency-anchor-v0.1.schema.json).
The executable golden bundle and trust material are:

- [`fixtures/transparency-anchor-v0.1-local.json`](./fixtures/transparency-anchor-v0.1-local.json)
- [`fixtures/transparency-anchor-v0.1-receipt-public.pem`](./fixtures/transparency-anchor-v0.1-receipt-public.pem)
- [`fixtures/transparency-anchor-v0.1-log-public.pem`](./fixtures/transparency-anchor-v0.1-log-public.pem)

## 2. Why the proof is a sidecar

An Ardur v0.2 Execution Receipt is an immutable compact JWS. Asynchronous log
registration learns an inclusion proof only after that JWS has been signed, so
writing the proof back into the receipt would invalidate both its signature and
the action-receipt hash chain.

The anchor bundle therefore carries:

1. the exact signed receipt JWT;
2. a SHA-256 subject digest over those exact compact-JWS bytes;
3. an explicit `pending` or `anchored` state; and
4. after registration, the log body, inclusion path, and signed checkpoint.

This separation follows the SCITT architecture's distinction between a Signed
Statement and a later Transparency Service Receipt. Ardur's v0.1 JSON/JWS
sidecar is **SCITT-aligned architecture**, not an RFC 9943 / RFC 9942 COSE wire
implementation. It must not be advertised as SCITT-conformant.

## 3. State machine

```text
receipt persisted -> pending sidecar -> backend submission -> anchored sidecar
                                      \-> retryable pending state on failure
```

Receipt sinks perform only the first local, idempotent queue write. They never
contact a transparency service. A queue failure cannot alter a PERMIT, DENY, or
the already-persisted receipt. `ardur anchor` drains pending work in a separate
process and atomically promotes successful bundles.

The default backend hint is `unconfigured`. This records honestly that the
receipt is not yet anchored without silently sending data to a public service.

## 4. Subject binding

`subject.digest.value` is lowercase hexadecimal:

```text
SHA-256(ASCII(compact_receipt_jws))
```

Verification recomputes this digest before evaluating any log evidence. A
different signature byte, payload byte, or compact-JWS separator fails subject
binding even if the surrounding sidecar is otherwise well formed.

## 5. Backend profiles

### 5.1 Rekor v1

The `rekor-v1` backend submits `hashedrekord` `0.0.1`:

- `data.hash` is the exact receipt-JWT SHA-256;
- `signature.content` is an ECDSA signature over that digest using the receipt
  issuer key; and
- `signature.publicKey.content` is that key's PEM SubjectPublicKeyInfo.

Submission requires the existing receipt issuer private key in `--keys-dir`.
The anchor command never generates replacement key material: a missing,
symlinked, loosely permissioned, or non-EC private key fails before transport.

The full receipt JWT is not uploaded. The public log still learns the digest,
issuer public key, signature, and registration timing, which can be sensitive
metadata.

Offline verification requires all of the following:

1. the receipt JWS verifies under the configured issuer key;
2. the hashedrekord digest matches the exact JWS bytes;
3. the detached hashedrekord signature verifies under the same issuer key;
4. the RFC 6962 inclusion path reaches the proof root;
5. the proof root and tree size match the signed checkpoint; and
6. the Rekor Signed Entry Timestamp verifies under the configured log key.

Rekor v1 is in maintenance mode while Sigstore transitions to tile-backed Rekor
v2. The backend name is intentionally versioned; Rekor v2 must use a separate
adapter and bundle profile rather than changing these semantics in place.

### 5.2 Self-hosted signed log

The `c2sp-local-v1` backend appends a canonical JSON statement containing only
the receipt subject and integration time. It builds an RFC 6962 Merkle tree and
returns an inclusion proof bound to a C2SP signed checkpoint.

The log key must be a separately administered Ed25519 key. Reusing the receipt
issuer key would turn the supposed witness into another self-attestation. The
implementation can run on an air-gapped operator host, but independence is an
operational property: the operator must keep the log key and storage outside
the governed agent's authority.

The current self-hosted writer requires POSIX advisory file locking and fails
explicitly if that facility is unavailable. Ardur's broader runtime also uses
POSIX locking, so this profile does not claim Windows runtime support.

## 6. Time semantics

A transparency log proves that exact bytes existed **no later than** their
integration time. It does not prove that the receipt's internal `iat` was
truthful. RFC 9943 likewise warns that registration order need not equal
issuance order and that registration does not make issuer statements accurate.

Ardur therefore evaluates a separate maximum-registration-delay policy:

```text
integrated_time - receipt.iat <= max_registration_delay_s
```

The CLI default is 86,400 seconds. Deployments that require stronger
anti-backdating guarantees should shorten this window and monitor pending queue
age. A longer window improves outage tolerance but weakens freshness evidence.

## 7. Failure behavior

Verification fails closed for:

- unknown schema versions, states, or anchored backend identifiers;
- a receipt digest or issuer key mismatch;
- malformed base64, JSON, signed notes, or checkpoints;
- an invalid receipt, detached, checkpoint, or SET signature;
- a missing, extra, incorrectly ordered, or wrong-length Merkle sibling;
- disagreement between entry index, proof index, tree size, root, or checkpoint;
- disagreement between the receipt digest, `anchor_id`, backend log id,
  `anchored_at`, and the corresponding evidence fields;
- integration before the claimed issue time beyond clock tolerance; or
- registration after the configured maximum delay.

`pending` is not a verification success. It is an explicit statement that no
accepted third-party inclusion proof is available yet.

## 8. Trust and residual risks

- A verifier must obtain the receipt issuer key and transparency-log key from
  trusted, separate channels.
- One valid signed checkpoint proves inclusion in the tree committed by that
  checkpoint. It does not alone detect log equivocation or split views.
- Production deployments should retain prior checkpoints, verify consistency
  proofs, and use independent checkpoint witnesses where available.
- The local backend is intentionally small and self-hostable. It is not a
  replacement for a monitored, replicated transparency service.
- Queue and log storage are append-growing operational data. Operators must set
  retention, backup, disk alerts, and privacy controls appropriate to receipt
  volume.

## 9. CLI

Queueing occurs automatically next to current receipt logs. Drain a local log:

```bash
ardur anchor \
  --receipt-log <receipts.jsonl> \
  --backend c2sp-local-v1 \
  --local-log <operator-log.jsonl> \
  --log-private-key <log-private.pem> \
  --origin <operator.example/ardur-receipts>
```

Verify the resulting bundle without network access:

```bash
ardur verify \
  --anchor-bundle <anchored-bundle.json> \
  --keys-dir <receipt-issuer-keys> \
  --transparency-log-key <log-public.pem> \
  --max-registration-delay-s 86400
```

## 10. Primary references

- RFC 9943, *An Architecture for Trustworthy and Transparent Digital Supply
  Chains*: https://www.rfc-editor.org/rfc/rfc9943.html
- RFC 9942, *COSE Receipts*: https://www.rfc-editor.org/rfc/rfc9942.html
- RFC 6962, *Certificate Transparency*: https://www.rfc-editor.org/rfc/rfc6962.html
- C2SP Transparency Log Checkpoints: https://c2sp.org/tlog-checkpoint
- C2SP Signed Notes: https://c2sp.org/signed-note
- Sigstore Rekor overview: https://docs.sigstore.dev/logging/overview/
- Rekor source and version posture: https://github.com/sigstore/rekor
