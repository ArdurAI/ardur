# DRP v0.1 Portable Implementation Fixtures

This directory contains public Ardur DRP Profile v0.1 implementation fixtures
pinned to DRP draft-10. These are **not** IETF conformance vectors and do not
demonstrate independent interoperability.

## Files

- `bundle.json` - signed scenarios, public trust/context, fixed actions and
  times, expected decisions, and explicit external implementation status.
- `report.json` - deterministic output from running the exact bundle with the
  Ardur verifier.
- [`../../drp-conformance-bundle-v0.1.schema.json`](../../drp-conformance-bundle-v0.1.schema.json)
  - closed bundle schema.
- [`../../drp-implementation-fixture-report-v0.1.schema.json`](../../drp-implementation-fixture-report-v0.1.schema.json)
  - closed deterministic report schema.
- [`../../ardur-drp-implementation-interop-v0.1.md`](../../ardur-drp-implementation-interop-v0.1.md)
  - support matrix, evidence boundary, and interoperability ledger.

The bundle stores public keys only. Synthetic URLs are evidence identifiers;
the runner performs no network access.

## Run

```sh
cd python
python -m vibap.drp_conformance \
  --bundle ../docs/specs/conformance/drp-v0.1/bundle.json \
  --output "${TMPDIR:-/tmp}/ardur-drp-fixture-report.json"
```

The output is successful only when every actual decision, reason code, and
receipt ID matches its expected value.

## Add or change a scenario safely

1. Edit `scripts/generate-drp-implementation-fixtures.py`; do not hand-edit a
   signed receipt or expected report.
2. Give the scenario one risk class and one stable expected failure reason.
   Re-sign semantic mutations so the intended policy check, not signature
   validation, produces the denial.
3. Generate `bundle.json` and `report.json` with an EXTENDED or otherwise
   disposable temporary directory configured for Python caches.
4. Confirm the generated diff contains `BEGIN PUBLIC KEY` material only and
   no private keys, credentials, live endpoints, or mutable current times.
5. Run `python -m pytest tests/test_drp_conformance.py -q`, then the full test,
   package, documentation, and secret gates.
6. Record any external verifier only by immutable revision and attach its raw
   report. Never replace `not-demonstrated` with a compatibility claim based
   on an Ardur self-test.

The generator holds ephemeral P-256 private keys in process memory only. It
persists the signed receipts and public keys, then reloads the public bundle
through the normal runner before accepting the report.
