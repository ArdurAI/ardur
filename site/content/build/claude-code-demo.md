---
title: "Claude Code + Ardur — Archival Live Session Recording"
description: "A historical Claude Code recording under Ardur supervision, with the current Phase 1 proof path linked separately."
weight: 42
maturity: ["in-progress"]
claim_types: ["demo", "evidence", "limitation"]
surfaces: ["python", "examples"]
frameworks: ["claude-code"]
evidence_levels: ["archival-media", "code-and-doc"]
---

{{< proof-status state="archival" label="Archival recording, not the canonical Phase 1 proof" source="MEDIA.md" >}}
This page preserves a real Claude Code walkthrough captured on **2026-05-06**.
Use it as product-context media, not as the primary readiness artifact. The
current re-runnable Phase 1 path is the no-key evidence harness and
`bundle.redacted.json` reader linked below; live Claude Code evidence is a
separate optional run on a host that already has an authenticated `claude`
binary.
{{< /proof-status >}}

Start here for fresh evidence:

- {{< repo-link "docs/guides/claude-code-mvp-quickstart.md" "Claude Code MVP quickstart" >}} — source checkout, no-key fresh-user harness, and optional live-Claude path.
- {{< repo-link "docs/guides/read-phase1-evidence-bundle.md" "Read the Phase 1 evidence bundle" >}} — how to interpret `bundle.redacted.json`, redaction checks, and supported/non-supported claims.

## What this recording shows

The recording demonstrates the Ardur Claude Code plugin guarding a real,
non-synthetic Claude Code session against the Anthropic API as it existed at the
time of capture. The saved media shows:

1. **Profile.** A plain-Markdown `ARDUR.md` declares `read only` mode scoped to
   `/private/tmp/ardur-bench`, with Read + Search allowed and Bash/Edit/Write
   blocked.
2. **Activation.** `ardur protect claude-code --profile ARDUR.md` compiles the
   profile into a Mission Passport and prints a `claude` command that pairs the
   plugin with the active passport.
3. **Live session.** A `claude --plugin-dir plugins/claude-code …` invocation
   uses tool calls exposed to local Claude Code hooks.
4. **Receipt report.** `ardur claude-code-report` summarises the local receipt
   chain: 9 receipts, 3 Glob, 6 Read, 8 compliant verdicts, and **1 violation**.
5. **Per-receipt decode.** Each receipt is decoded; signatures verify against
   the public key; `parent_receipt_hash` of receipt N matches `receipt_hash` of
   receipt N–1.

{{< asciinema src="/casts/ardur-claude-code.cast"
              poster="/casts/ardur-claude-code.gif"
              cols="80" rows="24"
              idle-time-limit="1" >}}

## The violation in the recording

Receipt #1 carried a `violation` verdict. The model's first Glob targeted
`/tmp/ardur-bench/**/*.txt`, but the active scope was
`/private/tmp/ardur-bench` (macOS resolves `/tmp` to `/private/tmp`, while this
scope check matched the canonical absolute path). Ardur denied the call, recorded
the violation receipt, and Claude Code retried with the in-scope path. The second
Glob landed `compliant`, and the rest of the session completed normally.

This remains useful context for the product story: Ardur is meant to preserve the
allowed/denied evidence trail, not just produce a chat transcript. It is not a
claim that this specific recording is the current release gate.

## Reproduce the current Phase 1 path instead

For a fresh no-key readiness check, run the current harness from the quickstart:

```bash
python3 scripts/run-rwt-phase1-fresh-user.py \
  --expected-origin-dev "$(git rev-parse --short=12 origin/dev)" \
  --output-dir /tmp/ardur-rwt-phase1

python3 -m json.tool /tmp/ardur-rwt-phase1/bundle.redacted.json | less
```

That path uses temporary HOME, project, Ardur home, evidence, and wheel-build
state. It does not log in to Claude Code, call an external provider, mutate your
real global Claude config, start a privileged daemon, or publish anything.

For a fresh live Claude Code run, use the live-demo section in the
{{< repo-link "docs/guides/claude-code-mvp-quickstart.md" "MVP quickstart" >}}.
Keep its evidence separate from the no-key bundle: a live run can support a local
Claude Code tool-boundary claim for that tested host/session, but it still does
not prove provider-hidden reasoning, server-side actions, or side effects below
the local tool boundary.

## Cost and timing from the archival capture

The original recording compared two single-shot Claude Code runs from the same
period:

| Run | Wall | API ms | Cost | Tool calls | Result |
|---|---:|---:|---:|---:|---|
| Without Ardur | 76.19 s | 59,100 ms | $0.418 | 4 | 153 (off by 3) |
| With Ardur | 44.18 s | 22,970 ms | $0.397 | 5 (1 deny + retry) | **150** (correct) |

Do not treat this table as a causal performance benchmark. The second run hit a
warm prompt cache that the first run created. For current performance claims,
use the repository's gated latency benchmarks and their explicit claim boundary.

## What not to claim from this page

This page does **not** prove:

- current package-manager release readiness;
- live-Claude success on a different host/session;
- provider-hidden reasoning or server-side tool-call visibility;
- subprocess, kernel, filesystem, or network side-effect capture below the
  Claude Code tool boundary;
- production Linux eBPF, macOS Endpoint Security Framework, or universal CLI
  capture readiness.

## Where the code lives

- Hook entrypoints: {{< repo-link "plugins/claude-code/hooks/" "plugins/claude-code/hooks/" >}}
- Hook adapter: {{< repo-link "python/vibap/claude_code_hook.py" "python/vibap/claude_code_hook.py" >}}
- Telemetry mapper: {{< repo-link "python/vibap/claude_code_telemetry.py" "python/vibap/claude_code_telemetry.py" >}}
- Receipt chain primitives: {{< repo-link "python/vibap/receipt.py" "python/vibap/receipt.py" >}}
- Plugin README: {{< repo-link "plugins/claude-code/README.md" "Claude Code plugin README" >}}
