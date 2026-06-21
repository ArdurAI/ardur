# Ardur Personal Native Messaging Bridge

The preferred browser path is direct loopback HTTP to the local Hub. This
native-host bridge is available for browser deployments that require Native
Messaging. It forwards messages to the Hub instead of creating an independent
receipt path.

Generate a Chrome manifest:

```bash
PYTHONPATH=python python3 -m vibap.cli personal-native-manifest \
  --host-path examples/ardur-personal-native-host/ardur-personal-host \
  --extension-id <extension-id> \
  --browser chrome
```

`--host-path` must point to an existing executable Native Messaging host file,
not an empty value, directory, missing path, or non-executable file. Invalid host
paths and invalid extension ids fail closed with parseable JSON on stdout,
placeholder-only `next_steps`, a non-zero exit, and empty stderr. This validates
local/no-key manifest inputs only; it is not browser-store deployment proof or
Native Messaging installation proof.

Install the generated JSON at:

```text
~/Library/Application Support/Google/Chrome/NativeMessagingHosts/dev.ardur.personal.json
```

The Hub must be running:

```bash
PYTHONPATH=python python3 -m vibap.cli hub
```

If the Hub has not been set up yet, run setup first, then start the Hub and
check the local setup:

```bash
PYTHONPATH=python python3 -m vibap.cli setup --home <ardur-home>
PYTHONPATH=python python3 -m vibap.cli hub --home <ardur-home>
PYTHONPATH=python python3 -m vibap.cli doctor --home <ardur-home> --hub-url <hub-url>
```

`--once-json` is the development/smoke path; browser Native Messaging receives
the same JSON response payload inside its length-prefixed native-host response
framing. Hub-unavailable or Hub-token/setup failures return deterministic local
`next_steps` in that JSON response. These hints are local/no-key recovery
guidance only and use placeholders such as `<ardur-home>`, `<hub-url>`,
`<hub-token>`, and `<native-message.json>`.

Placeholder-safe smoke form:

```bash
PYTHONPATH=python python3 -m vibap.cli personal-native-host \
  --once-json <native-message.json> \
  --home <ardur-home> \
  --hub-url <hub-url> \
  --hub-token <hub-token>
```
