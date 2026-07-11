# Tool-Server Preflight Fixtures

These strict JSON fixtures exercise Ardur's static, non-executing preflight
scanner before a local MCP or other tool server is enabled.

```bash
ardur preflight tool-server \
  --config examples/tool-server-preflight/closed-vscode.json \
  --format markdown

ardur preflight tool-server \
  --config examples/tool-server-preflight/risky-gemini.json \
  --format json \
  --fail-on high
```

`closed-vscode.json` declares an exact-version-pinned package, a bounded workspace
read scope, and one read-only tool. `risky-gemini.json` is intentionally unsafe:
it requests shell execution, a broad filesystem root, confirmation bypass,
secret-like environment access, and a write/network tool with instruction-like
metadata.

The scanner does not start either server, import its code, resolve packages,
read referenced environment variables, or contact configured endpoints. A
clean report is not a safety certification; it means only that the supported
static indicators did not match the supplied document.
