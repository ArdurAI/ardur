# Claude Code + Ardur

The runnable Claude Code integration now lives in
[`../../plugins/claude-code/`](../../plugins/claude-code/).

Use this example directory as a compatibility pointer only; it is not a second
implementation and it does not contain mock hook code.

## Run

```bash
cd ../..
pip install -e python/
ardur profile init --template read-only --path ARDUR.md
ardur protect claude-code --profile ARDUR.md
ardur doctor-claude-code
# Run the exact VIBAP_HOME=... claude --plugin-dir ... command printed above.
```

The plugin uses Claude Code `PreToolUse` and `PostToolUse` hooks, signs real
Ardur Execution Receipts, and can block disallowed local tool calls. The
receipt-chain smoke test is:

```bash
PYTHONPATH=python python3 plugins/claude-code/scripts/smoke.py
```
