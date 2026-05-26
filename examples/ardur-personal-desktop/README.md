# Ardur Personal Desktop Adapter

Desktop capture is mediated by the local Hub. The current Mac adapter records
frontmost application identity and window title through AppleScript when
available. If the user explicitly provides text with `--text`, the Hub stores a
consented excerpt in the Session Review.

Start the Hub:

```bash
PYTHONPATH=python python3 -m vibap.cli hub
```

Observe the current foreground app:

```bash
PYTHONPATH=python python3 -m vibap.cli desktop-observe
```

Observe with explicit visible-text consent:

```bash
PYTHONPATH=python python3 -m vibap.cli desktop-observe \
  --app "Claude" \
  --title "Planning session" \
  --text "Visible excerpt the user explicitly chose to record"
```

macOS may require Accessibility permission for Terminal or the installed
`ardur` binary before app/window detection works. Screen Recording or OCR is
not enabled by this adapter; hidden provider-side actions remain outside local
evidence and are labeled accordingly.
