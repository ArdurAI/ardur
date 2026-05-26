# Ardur — Python Reference Implementation

The public Python runtime for Ardur lives here: a runtime governance and evidence layer for AI agents that issues signed mission passports, enforces them at execution time, and records receipts you can verify after the fact.

A note on names: the eventual PyPI package is `ardur`, but the internal Python module is still `vibap`. That's a technical-lineage thing — VIBAP is the original research-era name for the protocol, not a product codename, and renaming the import path would have churned every test and example for no real benefit. Treat `vibap` as an implementation detail; everything user-facing speaks `ardur`.

## Quickstart (no API keys required)

```bash
# from the ardur repo root
cd python
pip install -e .

# Issue a passport for a mission
ardur issue \
  --agent-id alice \
  --mission "summarize sales from sales/q1.csv into reports/" \
  --allowed-tools read_file write_report \
  --resource-scope 'sales/*' 'reports/*'

# Verify a passport (the issue command prints a JSON object containing "token")
ardur verify --token <token-from-issue-output>
```

That walks through key generation, mission compilation, ES256-signed passport issuance, and verification — all local, no LLM calls.

## Ardur Personal Hub

The regular-user path uses the same package dependencies and CLI:

```bash
pip install -e .
ardur profile init --template read-only --path ARDUR.md
ardur protect claude-code --profile ARDUR.md
ardur doctor-claude-code
```

The Hub is available when you want browser/desktop evidence and local receipt
exports:

```bash
ardur setup
ardur hub
ardur status
```

Browser, desktop, and CLI adapters send observations to the Hub. The Hub uses
the existing `GovernanceProxy` and Execution Receipt path, so adapters do not
create their own policy authority.

`ardur run -- <command>` remains available for simple non-interactive commands,
but Claude Code is the first-class RC path. Interactive Codex and Claude
Desktop packaging are intentionally not presented as complete in this release
candidate.

A heads-up on the CLI name: `ardur` is the canonical entrypoint going forward. `ardur-proxy` still works as a deprecated alias so existing scripts don't break, but new code should use `ardur`.

## What's here

```
python/
├── vibap/                  # Core runtime package
│   ├── attestation.py           # Per-session attestation issuance + verify
│   ├── backends/                # Policy-engine adapters (Cedar, native, forbid-rules)
│   ├── biscuit_passport.py      # Biscuit AAT/DG implementation
│   ├── claude_code_hook.py      # Claude Code PreToolUse/PostToolUse adapter
│   ├── claude_code_telemetry.py # Claude Code tool → declared-telemetry mapper
│   ├── cli.py                   # ardur CLI entrypoint
│   ├── mission.py               # Mission Declaration parsing + cache
│   ├── passport.py              # Passport issuance + verify
│   ├── personal_hub.py          # Local Ardur Personal Hub service + adapter API
│   ├── policy_backend.py        # PolicyBackend protocol
│   ├── proxy.py                 # Governance proxy + session lifecycle
│   ├── receipt.py               # Execution Receipt issuance + verify
│   └── ...
└── tests/                  # Curated test set (~23 files)
```

A couple of pinned dependencies worth flagging: `biscuit-python==0.4.0` (the Biscuit token format we use for delegated capabilities) and `spiffe>=0.2,<0.3` (workload identity). These pins are deliberate — both libraries have had breaking minor releases, so we hold them until we explicitly retest.

## Protocol identifier rename

This implementation is a **clean break** on protocol identifiers — v0.1 receipts, passports, and attestations only emit and accept the new Ardur type strings. There is no dual-type backward-compat shim. If you have artifacts produced before the rename, they won't validate against this code, and that's intentional.

Full reasoning is in [`docs/specs/README.md`](../docs/specs/README.md) under "Protocol identifier rename."

## What's not here yet

A few things are documented gaps right now rather than oversights:

- **Live LLM tests** — the semantic-judge and behavioral-fingerprint test lanes need real API keys, so the default test run uses local test doubles. To opt in, set `ARDUR_SEMANTIC_JUDGE=anthropic` and `ANTHROPIC_API_KEY`.
- **Corpus-heavy benchmark tests** — AgentDojo, InjectAgent, R-Judge, STAC, and the telemetry-ablation harness stay in the private research tree. The cleaner subset that backs the public claims is what's curated here.
- **Docker images** (`rahulnutakki/ardur-demo:lang`, `:autogen`) and re-recorded asciinema casts — these need a maintainer with Docker Hub credentials and an `asciinema record` session, neither of which an automated process can do.

One more caveat: the package imports cleanly and the AST parses. If something import-time looks off, file an issue.

## License

MIT — see [LICENSE](../LICENSE).
