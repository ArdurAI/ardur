# Phase 1 Demo Packet

Use this packet after the [Claude Code MVP quickstart](claude-code-mvp-quickstart.md)
when you need a compact, bounded handoff for the current Phase 1 source-checkout
path.

This is not a tagged release, package-manager install, or universal agent demo.
It is a way to show what the current `dev` branch can prove today without
mixing the no-key harness, optional live Claude Code evidence, and archival
recordings.

## 1. State the scope up front

Say this before showing artifacts:

> This demo proves the source-checkout Claude Code MVP path at the local tool
> boundary. It shows setup, allow/deny hook receipts, chain verification, and
> redaction checks. It does not claim package release readiness, provider-hidden
> reasoning visibility, subprocess/kernel/network side-effect capture, or
> universal CLI support.

## 2. Run the no-key proof path

From a clean checkout of the current `dev` branch:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e python/

python3 scripts/run-rwt-phase1-fresh-user.py \
  --expected-origin-dev "$(git rev-parse --short=12 origin/dev)" \
  --output-dir /tmp/ardur-rwt-phase1

python3 -m json.tool /tmp/ardur-rwt-phase1/bundle.redacted.json | less
```

The bundle is the primary shareable proof artifact for a no-key run. Read it
with [Read The Phase 1 Evidence Bundle](read-phase1-evidence-bundle.md) before
copying any claim into a demo note, launch draft, or issue response.

Required no-key signals:

- `status` is `PASS`.
- `RWT-1` is `PASS` for source/local-wheel install, `ARDUR.md`, protection, and
  doctor checks.
- `RWT-2` is `PASS` for simulated Claude Code hook allow/deny receipts and
  `ardur claude-code-report` verification.
- `redaction.secret_scan_hits` is `0`.
- `redaction.raw_secret_values_copied` is `false`.
- `claim_mapping.supports_claims` contains the claim you intend to make.

`RWT-3` is `SKIP_GATED` or `SKIP_UNSUPPORTED` in no-key/autonomous mode; it can
be `BLOCKED` when local Claude preflight fails. A skip is acceptable for a
no-key confidence check; it is not a live-Claude pass.

## 3. Optional live Claude Code proof

Only add live-Claude evidence if `claude` is already installed and authenticated
locally. Ardur does not log in, change accounts, or provision provider access.

Use the live section of the [quickstart](claude-code-mvp-quickstart.md), then
attach the output of:

```bash
ardur claude-code-report --home "$VIBAP_HOME"
```

Keep this output separate from the no-key bundle. A live run can support a
local, session-scoped Claude Code tool-boundary claim for the tested host. It
still does not prove provider-hidden reasoning or side effects below the local
tool boundary.

## 4. Attach exactly these artifacts

For a clean Phase 1 handoff, include:

| Artifact | Required? | Why it is included |
|---|---:|---|
| Tested git commit or `origin/dev` short SHA | Yes | Anchors the evidence to a source tree. |
| `bundle.redacted.json` | Yes | Primary no-key proof bundle and claim ledger. |
| Redacted command transcript | Recommended | Shows the exact commands without exposing local secrets. |
| `ardur claude-code-report` output | Only for live-Claude claims | Verifies the local hook receipt chain from a real Claude Code session. |
| Archival cast link | Optional context only | Useful product history, not rerunnable proof. |

Do not attach raw secret-bearing files, unredacted provider prompts, local key
material, `.vibap` private state, `.context` private state, or absolute paths
that reveal more about the host than the demo needs.

## 5. Use this claim ledger

| Works now from the packet | Not claimed by the packet | Coming soon |
|---|---|---|
| Source-checkout install and Python package import. | PyPI/Homebrew/OCI release readiness. | Tagged package-manager release after packaging gates. |
| `ARDUR.md` creation and Claude Code protection setup. | Account login, provider setup, or hosted service deployment. | Friendlier installer and proof viewers. |
| Simulated Claude Code hook allow/deny receipts with chain verification. | Provider-hidden reasoning or server-side tool calls. | More host adapters with the same evidence boundary. |
| Redacted no-key `bundle.redacted.json` with explicit claim mapping. | Subprocess, kernel, filesystem, or network capture below the tool boundary. | Filesystem snapshot and Linux eBPF capture phases. |
| Optional live-Claude report when the local binary is already authenticated. | Universal CLI support across Codex, Gemini, Kimi, or future tools. | Tool-agnostic CLI/kernel capture work. |

If the bundle is not `PASS`, or if the claim you want is listed under
`claim_mapping.does_not_support_claims`, stop and rerun or reword the claim.

## 6. One-minute talk track

1. "Ardur does not ask you to trust a chat transcript; it gives you a signed,
   verifier-backed receipt chain."
2. "The no-key harness proves the current source-checkout path without touching
   an LLM provider account."
3. "When Claude Code is available, the live report stays separate and only proves
   the local tool boundary for that session."
4. "Anything below the tool boundary — subprocess trees, kernel events, network
   side effects — remains explicitly out of the Phase 1 claim."
5. "That separation is the product: allowed, denied, unknown, and not claimed are
   all visible instead of being flattened into marketing copy."
