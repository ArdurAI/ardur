# Agentic Policy Conformance Fixtures v0.1

This directory contains Ardur's public, no-network runtime-policy self-test.
It covers one safe baseline and seven modeled risk classes. Every scenario is
re-evaluated through the production native-policy or delegation-attenuation
path, and its committed receipt is verified against the same action, arguments,
decision, reason code, and grant.

This is implementation evidence, not an independent security certification.
The indirect-prompt and untrusted-artifact cases label the provenance that
caused a modeled tool request. They prove that Ardur governs the resulting
request; they do not claim that Ardur semantically detects malicious text or
artifact contents.

## Run

From `python/`:

```bash
python -m vibap.policy_conformance \
  --bundle ../docs/specs/conformance/policy-v0.1/bundle.json \
  --output /tmp/ardur-policy-conformance-report.json
```

The command exits `0` when every expected decision and receipt binding passes,
`1` when a scenario regresses, and `2` when the bundle or output contract is
invalid. It requires no provider key and performs no network access.

## Add A Scenario Safely

1. Add a compact scenario template to
   `scripts/generate-policy-conformance-fixtures.py`. Do not add raw secrets,
   realistic confidential data, prompt payloads, or exploit strings.
2. Choose `native` for action policy or `derive_child_passport` for authority
   narrowing. Do not simulate a production path with a label-only stub.
3. State the expected `PERMIT` or `DENY` decision and stable public reason code.
4. Regenerate the bundle and report. The generator uses an ephemeral P-256 key
   and persists only the public key and signed receipts.
5. Run `python -m pytest tests/test_policy_conformance.py -q`, then the full
   Python suite and source-doc sync check.

```bash
PYTHONPATH=python python scripts/generate-policy-conformance-fixtures.py \
  --bundle docs/specs/conformance/policy-v0.1/bundle.json \
  --report docs/specs/conformance/policy-v0.1/report.json
```

Never hand-edit a receipt JWT. A changed action or expectation must produce a
new signed public fixture through the generator.
