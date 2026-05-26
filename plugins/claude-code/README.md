# Ardur Claude Code Plugin

## What it does

This plugin protects Claude Code at the local tool boundary. `PreToolUse` runs
before a Claude Code tool executes: the adapter loads the active Ardur profile,
maps the tool input to declared telemetry, evaluates the Mission Passport, and
emits a signed receipt. If Ardur denies the call, the hook returns Claude Code's
current `hookSpecificOutput.permissionDecision = "deny"` response.

For the one-screen source-checkout walkthrough, including the no-key evidence
harness and live-Claude demo path, start with
[`docs/guides/claude-code-mvp-quickstart.md`](../../docs/guides/claude-code-mvp-quickstart.md).

On permit, Ardur emits evidence only. It does not return
`permissionDecision=allow`, so Claude Code's normal permission prompts and user
approval flow remain in charge.

## Easiest Setup

Install Ardur with its Python dependencies, then create a plain Markdown
guardrail file:

```bash
cd <ardur-repo>
pip install -e python/
ardur profile init --template read-only --path ARDUR.md
```

Open `ARDUR.md` in any text editor:

```markdown
# Ardur Guardrails
Mode: read only
Mission: Review this project without changing files or running commands.
Protect folder: .
Max tool calls: 100
Duration: 1d

## Allow
- Read files
- Search files

## Block
- Run shell commands
- Edit files
- Write files
```

Turn protection on:

```bash
ardur protect claude-code --profile ARDUR.md
```

Start Claude Code with the exact command printed by Ardur. It includes
`VIBAP_HOME=...` so the hook can find the active passport and the Python
environment where Ardur is installed. It will look like:

```bash
VIBAP_HOME=/path/to/.vibap claude --plugin-dir /path/to/plugins/claude-code
```

## Low-latency PreToolUse path

`ardur protect claude-code` also tries to build a native PreToolUse daemon
client at `$VIBAP_HOME/claude-code-pre_tool_use` when a local C compiler is
available. The hook wrapper attempts the fast path first, then falls back to
Python handling when no daemon is listening, the native client is missing, or
the daemon response is invalid.

To use the daemon path, start the daemon from the same Python environment where
Ardur is installed before launching Claude Code:

```bash
VIBAP_HOME=/path/to/.vibap python -m vibap.claude_code_daemon
```

By default, the Unix socket lives at:

```text
$VIBAP_HOME/daemon/claude-code-hook-daemon.sock
```

The daemon creates the `daemon/` directory as `0700` and the socket as `0600`.
If the socket path already contains a non-socket file, Ardur fails closed rather
than deleting it.

Operational toggles:

- `ARDUR_CC_HOOK_DAEMON=0` disables daemon-first dispatch.
- `ARDUR_CC_HOOK_DAEMON_SOCKET=/path/to/socket` uses a custom socket path.
- `ARDUR_CC_HOOK_DAEMON_TIMEOUT_MS=5` changes the daemon client timeout.
- `ARDUR_CC_HOOK_STRICT_NATIVE=1` forces the wrapper to use only the native
  client when benchmarking or diagnosing the fast path; do not use it if you
  want Python fallback behavior.

Claim boundary: the gated release test targets the native daemon-client path.
Shell wrapper latency is recorded as telemetry because `/bin/bash` startup and
workstation scheduler tails can dominate p95 even when the native hot path is
fast.

## Built-In Options

- `ardur profile init --template read-only`: safest first run. Allows reading
  and searching only.
- `ardur profile init --template safe-coding`: allows local file edits inside
  the selected folder, but blocks shell commands.
- `ardur protect claude-code --scope . --mode read-only`: same behavior without
  a Markdown profile.
- `ardur protect claude-code --scope . --mode safe-coding`: flag-based setup
  for technical users.

Advanced users can still use `ardur issue`, `ARDUR_MISSION_PASSPORT`,
`ARDUR_CC_HOOK_DIR`, and custom Mission Passport fields directly. The Markdown
profile is a friendly layer over the same capabilities, not a replacement.

## What happens when a tool is called

1. `PreToolUse` fires.
2. Ardur maps the Claude Code tool input into declared telemetry.
3. Ardur checks the active Mission Passport: allowed tools, forbidden tools,
   resource scope, cwd, and relevant policy backends.
4. If permitted, Ardur appends a compliant receipt and lets Claude Code continue
   its normal permission flow.
5. If denied, Ardur appends a violation receipt and returns
   `hookSpecificOutput.permissionDecision = "deny"`.
6. `PostToolUse` records the SHA-256 digest of permitted tool responses as a
   chained evidence receipt.
7. `SubagentStart` / `SubagentStop` record signed lifecycle receipts and append
   per-trace subagent registry events. Tool receipts are attributed only when
   Claude Code exposes an exact agent id or when transcript evidence binds one
   child; otherwise they remain trace-level and are reported as unattributed.

## Where receipts live

Receipts are written to:

```text
$ARDUR_CC_HOOK_DIR/<trace_id>/receipts.jsonl
```

Default when `ARDUR_CC_HOOK_DIR` is not set:

```text
~/.vibap/claude-code-hook/<trace_id>/receipts.jsonl
```

Subagent lifecycle observations for the same trace are also written to:

```text
$ARDUR_CC_HOOK_DIR/<trace_id>/subagents.jsonl
```

## Verify a receipt chain

```bash
PYTHONPATH=python python3 -c "
from pathlib import Path
from vibap.receipt import verify_chain
from vibap.passport import load_public_key
jwts = Path('~/.vibap/claude-code-hook/<trace>/receipts.jsonl').expanduser().read_text().splitlines()
jwts = [j.strip() for j in jwts if j.strip()]
pk = load_public_key()
verify_chain(jwts, pk)
print('chain ok:', len(jwts), 'receipts')
"
```

## Boundaries

This plugin captures at the **tool-call boundary** — every Claude Code tool
invocation (`Read`, `Edit`, `Write`, `Bash`, `WebFetch`, `WebSearch`,
`Task`, MCP tools) is signed and chained.

What is **not** captured today:

- **Side effects of shell commands.** A `Bash("rm foo")` is recorded as the
  command string; the actual `unlink` syscall is invisible.
- **Subprocess trees** spawned by a tool call (e.g. by `Bash("./run.sh")`).
- **Network connections** initiated by tool-spawned processes.
- **Filesystem changes** outside the typed file tools.
- **Provider-side reasoning, hidden state, server-side tool calls** — out
  of scope by definition for any local tool.

The roadmap closes these gaps in phases: v0.2 adds filesystem snapshots,
v0.5 adds Linux eBPF kernel-level capture, v1.0 adds macOS Endpoint
Security Framework. See [`docs/coverage-map.md`](../../docs/coverage-map.md)
for the full per-tool audit.

Other notes:

- Ardur is not a sandbox. Use it with Claude Code's normal permissions and OS
  filesystem controls.
- Codex and Claude Desktop are not first-class in this RC. They remain separate
  next-cycle integrations.

## Troubleshooting

**"ardur: no active mission passport found"**

Run:

```bash
ardur protect claude-code --profile ARDUR.md
```

**Plugin validation fails**

Run:

```bash
claude plugin validate plugins/claude-code
```

The plugin should contain `.claude-plugin/plugin.json` and `hooks/hooks.json`.

**Receipts are not appearing**

Confirm `python3` is on PATH for Claude Code and that
`~/.vibap/claude-code-hook/` is writable.
