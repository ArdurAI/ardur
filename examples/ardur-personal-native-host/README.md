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

Install the generated JSON at:

```text
~/Library/Application Support/Google/Chrome/NativeMessagingHosts/dev.ardur.personal.json
```

The Hub must be running:

```bash
PYTHONPATH=python python3 -m vibap.cli hub
```
