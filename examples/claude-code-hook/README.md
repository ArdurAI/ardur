# Claude Code + Ardur

The runnable Claude Code integration now lives in
[`../../plugins/claude-code/`](../../plugins/claude-code/).

Use this example directory as a compatibility pointer only; it is not a second
implementation and it does not contain mock hook code.

## Run

```bash
cd ../..
./scripts/setup-dev.sh --skip-go
source python/.venv/bin/activate
ardur profile init --template read-only --path ARDUR.md
ardur protect claude-code --profile ARDUR.md
ardur doctor-claude-code
# Run the exact VIBAP_HOME=... claude --plugin-dir ... command printed above.
```

`setup-dev.sh` defaults to `python3.13` and creates `python/.venv`. For a manual
install instead, use Python 3.10 or newer (`python/pyproject.toml` enforces this),
run `python -m pip install --upgrade pip` first, then
`python -m pip install -e python/`; macOS system Python 3.9 and its bundled pip
are too old for the PEP 660 editable install.

The plugin uses Claude Code `PreToolUse` and `PostToolUse` hooks, signs real
Ardur Execution Receipts, and can block disallowed local tool calls. The
receipt-chain smoke test is:

```bash
PYTHONPATH=python python3 plugins/claude-code/scripts/smoke.py
```
