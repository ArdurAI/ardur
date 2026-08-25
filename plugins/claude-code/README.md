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
./scripts/setup-dev.sh --skip-go
source python/.venv/bin/activate
ardur profile init --template read-only --path ARDUR.md
```

`setup-dev.sh` defaults to `python3.13` and creates `python/.venv`. For a manual
install instead, use Python 3.10 or newer (`python/pyproject.toml` enforces this),
run `python -m pip install --upgrade pip` first, then
`python -m pip install -e python/`; macOS system Python 3.9 and its bundled pip
are too old for the PEP 660 editable install.

To see the conservative personal flow before configuring Claude Code, run:

```bash
ardur personal-firewall demo
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

Child delegation is disabled by default. To govern Claude Code child agents,
create a private operator registry:

```json
{
  "schema_version": "ardur.claude_code.child_policies.v1",
  "agent_types": {
    "Explore": {
      "child_agent_id": "claude-code:explore",
      "mission": "Read project evidence needed for the assigned question.",
      "allowed_tools": ["Glob", "Grep", "Read"],
      "resource_scope": ["/path/to/project", "/path/to/project/*"],
      "max_tool_calls": 20,
      "ttl_s": 900
    }
  }
}
```

Then validate and enable exactly one delegation level:

```bash
chmod 600 ./claude-code-child-policies.json
ardur protect claude-code \
  --scope /path/to/project \
  --child-policy-file ./claude-code-child-policies.json
```

The printed launch command includes `ARDUR_CC_CHILD_POLICY_FILE` with the
resolved registry path. Setup rejects symlinks, non-regular or group/world
accessible files, malformed/empty registries, nested `Agent`/`Task` authority,
wildcard child tool authority, parent/child budget conflicts, and profiles that
explicitly forbid `Agent`.
Do not place credentials, prompts, or user data in this registry.

## Low-latency PreToolUse path

`ardur protect claude-code` also tries to build a native PreToolUse daemon
client at `$VIBAP_HOME/claude-code-pre_tool_use` when a local C compiler is
available. The hook wrapper attempts the fast path first, then falls back to
Python handling when no daemon is listening, the native client is missing, or
the daemon response is invalid.

When `ARDUR_CC_CHILD_POLICY_FILE` is set, Ardur deliberately bypasses the
parent-only daemon and uses the binding-aware Python path for every pre-hook.
This avoids trading child reservation and `agent_id` enforcement for latency.

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

Claim boundary — per-platform numbers:

- **In-process compute** (passport validation + scope check + receipt emit,
  no IPC): p95 **<10ms**. Gated by `test_claude_code_daemon_hot_path_latency_target`.
- **Full native daemon-client path** (native binary exec + Unix-socket
  send/recv + response parse): p95 **<20ms**, measured ~15-17ms on Apple
  Silicon macOS. Gated by `test_claude_code_native_daemon_client_latency_target`.
- **Shell wrapper path**: latency recorded as telemetry only. `/bin/bash`
  startup and workstation scheduler tails can dominate p95 even when the
  native hot path is fast; enforcing a gate here would measure shell overhead,
  not Ardur overhead.

## Built-In Options

- `ardur profile init --template personal-firewall`: workspace-scoped reads
  and edits, common secret-like argument blocks, no shell/network tools, and a
  signed 40-action session cap.
- `ardur profile init --template read-only`: safest first run. Allows reading
  and searching only.
- `ardur profile init --template safe-coding`: allows local file edits inside
  the selected folder, but blocks shell commands.
- `ardur protect claude-code --scope . --mode read-only`: same behavior without
  a Markdown profile.
- `ardur protect claude-code --scope . --mode safe-coding`: flag-based setup
  for technical users.
- `ardur protect claude-code --scope . --mode personal-firewall`: the same
  native capability defaults without a Markdown profile; use the profile when
  you also want its secret-like argument rules.

The action cap is enforced in governed tool calls. Ardur does not infer a
dollar cost when Claude Code supplies no trusted signed billing telemetry.

Advanced users can still use `ardur issue`, `ARDUR_MISSION_PASSPORT`,
`ARDUR_CC_HOOK_DIR`, and custom Mission Passport fields directly. The Markdown
profile is a friendly layer over the same capabilities, not a replacement.

## What happens when a tool is called

1. `PreToolUse` fires.
2. Ardur maps the Claude Code tool input into declared telemetry.
3. Ardur checks the active Mission Passport: allowed tools, forbidden tools,
   resource scope, cwd, and relevant policy backends. Absolute local scope
   paths are canonicalized so an in-scope symlink that resolves outside is
   denied. This pre-dispatch check cannot distinguish hard-link aliases or
   prevent path replacement before the tool's later filesystem operation.
4. If permitted, Ardur appends a compliant receipt and lets Claude Code continue
   its normal permission flow.
5. If denied, Ardur appends a violation receipt and returns
   `hookSpecificOutput.permissionDecision = "deny"`.
6. `PostToolUse` records the SHA-256 digest of permitted tool responses as a
   chained evidence receipt.
7. For a configured `Agent` call, the blockable pre-hook reserves a strictly
   narrower child grant before dispatch. Unknown agent types, insufficient
   parent budget, missing operation ids, and attenuation failures are denied.
8. `SubagentStart` binds Claude's `agent_id` to one pending opaque reservation.
   Because Claude does not provide the originating `tool_use_id` to this hook,
   concurrent children of the same type are interchangeable only when their
   normalized policies are identical. Any policy ambiguity, missing agent id,
   stop-before-start sequence, or state uncertainty quarantines authority.
9. Bound child `PreToolUse` calls are evaluated against the child grant; there
   is no fallback to the parent passport. `PostToolUse` settles the exact
   operation once. `PostToolUseFailure` hashes the failure evidence and
   quarantines the child so an uncertain effect cannot be replayed.
10. `SubagentStop` closes the exact bound handle and records a signed lifecycle
    receipt. Reports attribute tools to a child only through the opaque
    `agent_id` binding; otherwise they honestly report trace-only coverage.

The durable binding registry stores opaque handles, hashes, policy
fingerprints, states, and expiry timestamps only. It never uses prompt text,
model output, platform event timestamps, transcript paths, or transcript
contents as child identity. Agent dispatch receipt telemetry records only the
agent type and argument hash, never prompt or description text. Private
adapter/proxy state is kept under the trace's mode-0700
`.child-authority/` directory; binding files use mode 0600. Recovery after a
hook-process restart preserves pending/bound/closed/quarantined/expired state
and fails closed on uncertain operations.

The platform contract behind this design is documented by Anthropic's primary
references: [Hooks reference](https://code.claude.com/docs/en/hooks) and
[Subagents](https://code.claude.com/docs/en/sub-agents). `PreToolUse` can block;
`SubagentStart`, `SubagentStop`, and post hooks are evidence/reconciliation
points after the relevant platform event.

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
`Agent`, MCP tools) is signed and chained.

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
