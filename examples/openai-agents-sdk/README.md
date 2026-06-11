# OpenAI Agents SDK + Ardur no-key fixture

Runnable today without an OpenAI API key. This directory contains an offline
proof fixture for the OpenAI Agents SDK visible function-tool dispatch boundary.
It does not call OpenAI or install the provider SDK; it simulates the tool-call
shape that Ardur can observe at the adapter boundary, then proves Ardur's local
policy/receipt path end to end.

## What this fixture demonstrates

The fixture loads a checked-in Ardur mission template, issues a local mission
passport, evaluates three provider-visible function-tool calls, emits signed
Execution Receipts, and verifies the receipt chain locally:

1. `read_file` is allowed by the mission and native policy.
2. `write_file` is denied by the mission boundary.
3. `provider_opaque_tool` returns `insufficient_evidence` because the visible
   tool schema is not mappable enough for Ardur to make a safe claim.

The generated report records `receipt_chain_verified: true`, verdict counts,
receipt IDs, and explicit non-claims.

## Run

From the repository root:

```bash
OUT="$(mktemp -d "${TMPDIR:-/tmp}/ardur-openai-agents-sdk-fixture.XXXXXX")"
examples/openai-agents-sdk/run.sh --out-dir "$OUT"
python3 -m json.tool "$OUT/report.json" >/dev/null
printf 'report: %s\n' "$OUT/report.json"
```

The command writes:

```text
$OUT/report.json                    # redacted/shareable fixture report
$OUT/receipts.jsonl                 # signed local Execution Receipt chain
$OUT/passport.claims.redacted.json  # redacted local mission-passport claims
$OUT/keys/                          # local fixture signing keys
```

`run.sh` accepts `--mission PATH` if you want to point at another compatible
mission template. The default is
`examples/missions/provider-adapter-no-key-mission.json`. The runner honors
`PYTHON` when set; otherwise it prefers `python/.venv/bin/python`, then
`python3.13`/`python3.12`/`python3.11`/`python3.10`, and fails clearly if the
selected interpreter is below Ardur's Python 3.10 minimum or lacks Ardur's
package dependencies. Run `./scripts/setup-dev.sh` or set `PYTHON` to a prepared
environment such as `python/.venv/bin/python`.

## Optional future live-provider path

A future live adapter can wrap the real OpenAI Agents SDK `function_tool` /
`Runner` path and feed the same visible tool-dispatch records into Ardur before
execution. That path would require the provider SDK and an OpenAI key supplied by
the operator at runtime. This no-key fixture is deliberately the first CI-safe
slice: it proves Ardur's mission/passport, native policy, signed receipt, and
chain-verification behavior without credentials.

## Non-claims

This fixture does not claim:

- live provider API enforcement;
- provider-hidden reasoning visibility;
- server-side tool-call capture inside OpenAI;
- kernel, subprocess, or network side-effect capture;
- multi-agent handoff coverage;
- production adapter hardening.

For protocol-only mission examples, see `examples/missions/`.
