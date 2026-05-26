# Ardur Personal Browser Extension

This extension is a thin browser adapter for the local Ardur Personal Hub. It
does not issue Ardur policy decisions or receipts itself. It captures
browser-visible observations from user-enabled origins and forwards them to the
Hub at `http://127.0.0.1:8765`, where the Python Ardur runtime issues standard
Execution Receipts and Session Reviews.

## Run Locally

Start the Hub:

```bash
ardur setup
ardur hub
```

Load the extension:

1. Open `chrome://extensions`.
2. Enable developer mode.
3. Load this directory as an unpacked extension.
4. Open Claude, ChatGPT, Grok, Codex web, Kimi, or another AI website.
5. Paste the local Hub token printed by `ardur setup`.
6. Enable the current site in the popup.
7. Optional: enable **Capture visible text** for readable Session Review excerpts.

After a site is enabled, the extension injects on page load and on manual
**Observe**. The Hub receives digests by default. Text excerpts are sent only
after per-origin visible-text consent is enabled.

## Evidence Boundary

The extension observes local browser DOM state. The Hub signs what the adapter
observed, applies local policy, and labels evidence gaps. Hidden provider-side
reasoning, server-side tool calls, and provider logs are not visible to the
extension and must be labeled `insufficient_evidence` when relevant.
