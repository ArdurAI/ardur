# `ardur` CLI Reference

The `ardur` console entry point ships with the Python package. After
`pip install -e python/`, run `ardur --help` to see this list at runtime.

The CLI splits into two groups:

- **Protocol path** — `start`, `issue`, `verify`, `attest`. Used by builders
  who want to issue Mission Passports and run a governance proxy directly.
- **Personal path** — `hub`, `setup`, `status`, `doctor`, `doctor-claude-code`,
  `uninstall`, `run`, `desktop-observe`, `personal-native-host`,
  `personal-native-manifest`, `profile init`, `protect claude-code`,
  `claude-code-hook`, `claude-code-report`, `gemini-cli-hook`,
  `gemini-cli-fixture`, `gemini-cli-report`, `codex-app-server-event`,
  `codex-app-server-fixture`, `codex-app-server-report`, `posture scan`,
  `posture report`. Used by the local Ardur Personal product shape.

Source: [`python/vibap/cli.py`](../../python/vibap/cli.py).

## Protocol Path

### `ardur start`

Start the local governance proxy HTTP service. Optionally issue a Mission
Passport from a JSON mission file and start a session immediately.

```text
ardur start [--host HOST] [--port PORT] [--mission FILE]
            [--keys-dir DIR] [--state-dir DIR] [--log-path FILE]
            [--require-auth | --no-require-auth]
            [--tls-cert FILE] [--tls-key FILE] [--no-tls]
```

Defaults: bind `127.0.0.1:8080`. Auth required by default.

TLS setup is local loopback proxy configuration. By default Ardur can create
local self-signed TLS material; `--tls-cert` and `--tls-key` select explicit
certificate and private-key PEM files, and `--no-tls` disables TLS only for
plain-HTTP loopback development. This is not a production TLS, release, or
hosted-website visibility claim.

Invalid explicit TLS material fails closed before keys, state files, audit logs,
sessions, or the proxy startup path are created. If either `--tls-cert` or
`--tls-key` is provided, both values must point to existing files unless TLS is
disabled for loopback development with `--no-tls`. Missing paths, one-sided
cert/key inputs, or directory inputs exit non-zero and write parseable stdout
JSON with `ok: false`, stable `condition`/`error`/`error_code` values of
`start_tls_material_invalid`, a message, a detail, and placeholder-only
`next_steps`. The failure path keeps stderr empty, emits no traceback, does not
echo raw local paths, JWTs, private keys, or certificate material, and leaves no
key, state, log, or session artifacts behind.

Invalid `--port` values outside the TCP range `0..65535` fail closed before
keys, state files, audit logs, sessions, or the proxy startup path are created.
They exit non-zero and write parseable stdout JSON with `ok: false`, stable
`condition`/`error`/`error_code` values of `start_port_invalid`, a message, a
detail, and placeholder-only `next_steps`. The failure path keeps stderr empty,
emits no traceback, does not echo raw local paths or secrets, and leaves no
key, state, log, or session artifacts behind. Valid `--port 0` remains the
ephemeral-port path, where the operating system chooses an available local port;
it is not a standalone server-readiness claim.

Invalid `--host` values fail closed after port range validation and before TLS,
key, state, audit log, session, or proxy startup work begins. Host values must
be plain bindable host names or IP addresses; empty or whitespace-only values,
URL-shaped values, values with schemes, ports, paths, queries, fragments, or
hosts that cannot be bound locally return parseable stdout JSON with `ok: false`
and stable `condition`/`error`/`error_code` values of `start_host_invalid`. The
failure path keeps stderr empty, emits no traceback, does not echo raw local
paths, malformed URLs, socket errors, or secrets, and leaves no key, state, log,
or session artifacts behind. If `--port` and `--host` are both invalid, the
existing `start_port_invalid` contract remains the first failure.

State directory security: `--state-dir` is local secret state. Persisted
sessions and passport state can contain bearer credentials, including parent
`passport_token` values and delegated child replay tokens. The proxy creates or
hardens the state and `sessions/` directories to `0700` and writes JSON state
files as `0600`; do not point this option at a shared or world-readable
location.

Mission-file input failures fail closed after port, host, and TLS material
validation but before key, state, audit log, session, or proxy startup work
begins. A missing mission file returns `start_mission_file_missing`; malformed
JSON or invalid UTF-8 JSON returns `start_mission_file_malformed_json`;
unreadable files return `start_mission_file_unreadable`; and directories or
mission JSON that does not match the schema return `start_mission_file_invalid`.
These failures exit non-zero and write stdout JSON with `ok: false`, stable
`condition`/`error`/`error_code` values, a message, a detail, and
placeholder-only `next_steps`. The failure path keeps stderr empty, emits no
traceback, does not echo raw local paths or file contents, and leaves no key,
state, log, or session artifacts behind. Valid mission-file session-start
behavior remains unchanged.

Invalid start write targets fail closed after port, host, TLS material, and
mission-file validation but before key generation, state initialization, audit
log creation, session creation, or proxy startup. An existing non-directory
`--state-dir` returns `state_dir_not_directory`; an existing non-file
`--log-path` returns `log_path_not_file`. These failures keep stdout parseable
as JSON with `ok: false`, stable `condition`/`error`/`error_code` values, and
placeholder-only `next_steps`, keep stderr empty, emit no traceback, do not echo
raw local paths or secrets, and leave no Mission Passport signing keys, state,
log, or session artifacts behind.

### `ardur kill-switch`

Activate or deactivate the emergency kill switch on a running governance proxy.

```text
ardur kill-switch [--deactivate] [--proxy-url URL] [--api-token TOKEN]
```

If the local proxy cannot be reached, TLS/scheme setup looks wrong, or the
proxy rejects the bearer token, the JSON output preserves `ok: false` and adds
deterministic `next_steps`. The hints are local/no-key recovery guidance only:
start the loopback governance proxy, match the `<proxy-url>` scheme/host/port,
supply or rotate `<api-token>`, then rerun `ardur kill-switch`. They use
placeholders such as `<proxy-url>`, `<proxy-port>`, and `<api-token>` rather
than copying raw tokens, URL credentials, or private paths. Successful
activate/deactivate responses preserve the proxy response shape and omit
remediation noise.

### `ardur issue`

Issue an ES256-signed Mission Passport JWT.

```text
ardur issue --agent-id ID --mission TEXT
            [--allowed-tools NAME ...] [--forbidden-tools NAME ...]
            [--resource-scope PATTERN ...]
            [--max-tool-calls N] [--max-duration-s N]
            [--delegation-allowed] [--max-delegation-depth N]
            [--ttl-s N] [--keys-dir DIR]
```

Prints `{"token": "...", "claims": {...}}` to stdout.

Invalid budget flags fail closed before key generation or signing:
`--max-duration-s` and `--ttl-s` must be positive integers,
`--max-tool-calls` must be zero or a positive integer, and
`--max-delegation-depth` must be zero or a positive integer. Non-integer budget
values and invalid numeric ranges such as `--max-duration-s <= 0`,
`--ttl-s <= 0`, `--max-tool-calls < 0`, or `--max-delegation-depth < 0` exit
non-zero and write stdout JSON with `ok: false`, stable `condition`/`error`
values, a message, a detail, and placeholder-only `next_steps`. The stable
conditions are `issue_budget_max_duration_invalid`,
`issue_budget_max_tool_calls_invalid`, `issue_budget_max_delegation_depth_invalid`,
and `issue_budget_ttl_invalid`. The failure path keeps stderr empty, emits no
traceback, does not create or print a token or private key, and does not copy
local paths or secret material. `--max-tool-calls 0` remains valid.

### `ardur verify`

Verify a Mission Passport signature and decode its claims.

```text
ardur verify --token JWT [--keys-dir DIR]
```

### `ardur attest`

Issue a behavioral attestation for a saved session, summarising the receipt
chain.

```text
ardur attest --session SESSION_ID
             [--keys-dir DIR] [--state-dir DIR] [--log-path FILE]
```

Invalid attest state and audit-log write targets fail closed before Mission
Passport key generation, state/session or log artifacts, and attestation token
issuance. An existing non-directory `--state-dir` returns
`state_dir_not_directory`; a `--state-dir` whose parent is an existing
non-directory, including a dangling symlink, returns
`state_dir_parent_not_directory`. An existing non-file `--log-path` returns
`log_path_not_file`; a `--log-path` whose parent is an existing non-directory,
including a dangling symlink, returns `log_path_parent_not_directory`. These
local/no-key CLI failures keep stdout parseable as JSON with `ok: false`, stable
`condition`/`error`/`error_code` values, and placeholder-only `next_steps`, keep
stderr empty, emit no traceback, do not echo raw local paths or secrets, and
leave no Mission Passport signing keys, state, session, audit-log, or
attestation artifacts behind. This documents the local CLI contract only; it is
not a release, package, public-readiness, hosted-service, or universal capture
claim.

## Personal Path

### `ardur hub`

Start the local Ardur Personal Hub HTTP service.

```text
ardur hub [--host HOST] [--port PORT] [--home DIR]
```

If `--home` points to an existing file instead of a directory, `ardur hub`
fails closed before starting a server. The command exits `1` and writes
parseable stdout JSON with `ok: false`, stable `condition`/`error` values, and
`error_code: path_not_directory`; stderr stays empty, no traceback is
emitted, `next_steps` uses placeholders such as `<ardur-dir>`, and the failure
does not copy raw local paths or tokens into the output.

See [Personal Hub HTTP API](personal-hub-api.md) for the endpoints exposed.

### `ardur setup`

Configure Ardur Personal on this machine. Generates a Hub token (or reuses an
existing one), writes the local config, prints the token once for setup, and
on macOS installs a per-user LaunchAgent plist at
`~/Library/LaunchAgents/dev.ardur.personal-hub.plist` so the Hub can be
managed via `launchctl` or `brew services`. Run `ardur uninstall` to remove
the plist.

```text
ardur setup [--host HOST] [--port PORT] [--home DIR]
            [--rotate-token] [--extension-path DIR]
```

`--rotate-token` forces a new token even if one already exists.
`--extension-path` selects which browser-extension directory the setup output
points users to (default: `examples/ardur-personal-extension`).

If `--home` points to an existing file instead of a directory, `ardur setup`
fails closed before writing setup state, generating or printing a token, or
installing launch files. The command exits `1` and writes parseable stdout JSON
with `ok: false`, stable `condition`/`error` values, and
`error_code: path_not_directory`; stderr stays empty, no traceback is
emitted, `next_steps` uses placeholders such as `<ardur-dir>`, and the failure
does not copy raw local paths or tokens into the output.

### `ardur status`

Show Hub status — current sessions, latest receipt, adapter availability.

```text
ardur status [--hub-url URL] [--hub-token TOKEN] [--home DIR]
```

When the local Hub cannot be reached, returns a local token/auth setup error, or
the supplied `--hub-url` is malformed/unsupported, the JSON output keeps the
failing status response and adds a deterministic `next_steps` array. These hints
are local-only setup guidance: correct the `<hub-url>` when the condition is
`hub_url_invalid`, run setup if needed, start the loopback Hub, supply or rotate
the Hub token, then re-run `ardur status` or `ardur doctor`. They use
placeholders such as `<ardur-home>`, `<hub-url>`, and `<hub-token>` and do not
copy raw invalid file URLs, local paths, tokens, or provider data into shared
logs. Healthy Hub responses preserve the existing response shape and omit
actionable remediation.

### `ardur doctor`

Health-check the local Ardur Personal setup: config presence, Hub
reachability, key material, write permissions.

```text
ardur doctor [--home DIR] [--hub-url URL] [--hub-token TOKEN]
```

The JSON output preserves the `ok` and `checks` fields and includes a
machine-readable `next_steps` array when core setup checks fail. These local
remediation hints cover missing setup/config/token state, malformed or
unsupported `--hub-url` values reported as `hub_url_invalid`, starting or
checking the loopback Hub, and re-running `ardur doctor`; they use placeholders
such as `<ardur-home>`, `<hub-url>`, and `<hub-token>` rather than copying raw
local paths, invalid file URLs, or tokens. When the core setup is healthy,
`next_steps` is an empty array.

### `ardur doctor-claude-code`

Verify the Claude Code plugin and active passport setup. Reports missing
plugin files, missing `claude` binary, missing or stale `active_mission.jwt`,
and machine-readable `next_steps` remediation hints when a check fails.

```text
ardur doctor-claude-code [--home DIR] [--plugin-dir DIR]
```

The command is local-only: it inspects files, PATH, and Claude Code plugin
validation state, but does not run a live Claude prompt or call a provider API.
Use failed `next_steps` entries to recover the setup, then re-run the doctor
before claiming the local Claude Code path is ready.

### `ardur uninstall`

Remove Ardur Personal launch files (the macOS LaunchAgent plist installed by
`ardur setup`) without deleting the home directory by default.

```text
ardur uninstall [--home DIR] [--remove-data] [--dry-run]
```

`--remove-data` also deletes the local Ardur Personal evidence and key
material under the home directory.

Use `--dry-run` to print deterministic JSON showing the local LaunchAgent and,
when `--remove-data` is also set, the Ardur Personal home directory that would
be removed. Dry-run mode does not delete launch files or data.

Dry-run JSON also includes a placeholder-safe `next_steps` array so users can
interpret the preview before running a destructive command. The hints point to
reviewing `would_remove`, unloading only the local Ardur Personal LaunchAgent if
it is running, backing up/exporting `<ardur-home>` to `<backup-location>` before
`--remove-data`, and rerunning `ardur uninstall` intentionally without
`--dry-run` only after the preview matches intent. The guidance uses placeholders
instead of raw local homes, temp paths, Hub tokens, evidence files, or key
material.

### `ardur run -- COMMAND ...`

Run a CLI command through the local Hub. Non-interactive only.

```text
ardur run [--hub-url URL] [--hub-token TOKEN] [--home DIR] -- <command>
```

If no command is supplied after `--`, `ardur run` exits `2`, leaves stdout empty,
does not execute a child process, and prints placeholder-safe `Next steps:`
guidance showing the `ardur run -- <command>` form. If the local Hub cannot be
reached, or session start/policy setup fails before `<command>` runs because
local Hub auth/token state is missing or invalid, `ardur run` preserves the
existing setup-failure exit code (`127`) and prints a placeholder-safe
`Next steps:` section to stderr. The remediation text points to local setup, Hub
startup, Hub token supply/rotation, and `ardur doctor` using `<ardur-home>`,
`<hub-url>`, `<hub-token>`, and `<command>` placeholders rather than copying raw
temp homes or tokens. Blocked commands still exit `126` with a receipt when
policy evaluation succeeds; successful commands preserve stdout, stderr, and
child exit-code streaming without remediation noise.

### `ardur desktop-observe`

Record a desktop observation against the Hub. On macOS, autodetects the
foreground app and window title via the Accessibility API when `--app` and
`--title` are omitted.

```text
ardur desktop-observe [--hub-url URL] [--hub-token TOKEN] [--home DIR]
                      [--session-id ID] [--app NAME] [--title TEXT]
                      [--text EXCERPT]
```

`--text` is an explicit-consent visible text excerpt to include in the
session review; omit it to record an app/title-only observation.

When the local Hub cannot be reached or returns a local token/auth setup error,
`desktop-observe` preserves the failing `ok: false` / `error_code` JSON response
and adds deterministic `next_steps`. The hints are local/no-key recovery
guidance only: run setup if needed, start the loopback Hub, supply or rotate the
Hub token, run `ardur doctor`, then re-run `ardur desktop-observe --app
<app-name> --title <window-title> --home <ardur-home> --hub-url <hub-url>
--hub-token <hub-token>`. They use placeholders such as `<ardur-home>`,
`<hub-url>`, `<hub-token>`, `<app-name>`, and `<window-title>` rather than
copying raw local paths, temp homes, URL credentials, or tokens. This does not
claim live provider/API behavior, provider-hidden action visibility, browser
store/native-host installation proof, release readiness, or public metadata
readiness; successful observations preserve the Hub response shape without
remediation noise.

### `ardur personal-native-host`

Run the browser native-messaging host that bridges the browser extension to
the local Hub. Invoked by Chrome/Firefox via the manifest, not by users
directly.

```text
ardur personal-native-host [--hub-url URL] [--hub-token TOKEN] [--home DIR]
                           [--once-json FILE]
```

`--once-json` is the development/smoke path: process one JSON message file and
exit with the native-host JSON response. Browsers do not pass this flag; they
use Native Messaging length-prefix framing, but Hub setup/auth failures carry
the same JSON response payload inside that framing.

Malformed Native Messaging framed input is also answered inside the same
length-prefix framing with `ok: false`, a stable `condition`, concise
non-secret detail, and placeholder-only `next_steps` guidance. The response does
not echo raw malformed payload bytes, raw Hub tokens, or local filesystem paths.

Malformed or unsupported Hub URL setup inputs supplied with `--hub-url` fail
closed before any Hub forwarding with parseable JSON for `--once-json` and the
same payload inside Native Messaging framing: `ok: false`, `error_code` /
`condition: "hub_url_invalid"`, deterministic placeholder-only `next_steps`, a
non-zero exit, and empty stderr without Python/urllib traceback text. This
validation does not echo raw invalid URL strings, URL credentials, local paths,
Hub tokens, or native-message payloads. It is distinct from syntactically valid
HTTP(S) Hub URLs where the loopback Hub is unavailable or rejects local auth;
those remain `hub_unavailable` or Hub token/setup responses with their own local
recovery guidance. This is local/no-key setup validation only and does not prove
browser-store deployment, native-host installation, live provider/API behavior,
provider-hidden action visibility, release readiness, package publishing, main
promotion, or public metadata/social readiness.

When the local Hub cannot be reached or returns a local token/auth setup error,
`personal-native-host` preserves the failing `ok: false` / `error_code` response
and adds a deterministic `next_steps` array. The hints are local/no-key recovery
guidance only: run setup if needed, start the loopback Hub, supply or rotate the
Hub token, run `ardur doctor`, then re-run `ardur personal-native-host
--once-json <native-message.json> --home <ardur-home> --hub-url <hub-url>
--hub-token <hub-token>`. They use placeholders such as `<ardur-home>`,
`<hub-url>`, `<hub-token>`, and `<native-message.json>` and do not claim browser
store deployment proof, live provider/API behavior, provider-hidden action
visibility, native-host installation proof, release readiness, or public
metadata readiness.

### `ardur personal-native-manifest`

Emit a browser native-messaging manifest JSON for installation under the
browser's `NativeMessagingHosts/` directory.

```text
ardur personal-native-manifest --host-path PATH --extension-id ID
                               [--browser chrome|chrome-for-testing|chromium|edge|firefox]
```

`--host-path` must identify an existing executable Native Messaging host file.
Empty values, whitespace-only values, directories, missing files, and
non-executable files fail closed before a manifest is emitted with parseable JSON
on stdout: `ok: false`, `error`/`condition:
"personal_native_manifest_host_path_invalid"`, concise non-secret
`message`/`detail`, placeholder-only `next_steps`, a non-zero exit, and empty
stderr. For Chrome-family browsers (`chrome`, `chrome-for-testing`, `chromium`,
and `edge`), `--extension-id` must be exactly 32 lowercase characters using only
letters `a` through `p`. For Firefox, the add-on id must be non-empty; Ardur does
not otherwise constrain legitimate non-empty Firefox ids. Invalid ids fail closed
before a manifest is emitted with the same output shape and `error`/`condition:
"personal_native_manifest_extension_id_invalid"`. This is local/no-key setup
validation only; it does not prove browser-store deployment, Native Messaging
installation, live provider/API behavior, or release readiness.

### `ardur profile init`

Write a starter `ARDUR.md` profile from a built-in template.

```text
ardur profile init --template TEMPLATE
                   [--path PATH] [--force] [--json]
```

Templates: `read-only`, `safe-coding`. Default path: `./ARDUR.md`.

If the target profile already exists and `--force` is omitted, the command
fails closed instead of overwriting local guardrails. JSON output includes
`ok: false`, `error: "profile_exists"`, `condition: "profile_exists"`, and
deterministic `next_steps`; human output prints the same recovery guidance under
"Next steps". The placeholder-only local recovery commands are
`ardur profile init --path ARDUR.md --force` when you intend to replace the
profile, or `ardur protect claude-code --profile ARDUR.md` to use the existing
profile.

If `--force` is supplied but `--path` is not a writable Markdown file, the
command still fails closed before writing a profile. Directory targets return
JSON with `ok: false`, `error: "profile_path_invalid"`,
`condition: "profile_path_invalid"`, and the message `Profile path is not a
writable Markdown file.` Other protected or unwritable targets use the same
placeholder-only recovery shape with a path-write failure condition. Human
output prints the same guidance under "Next steps". The local recovery commands
use placeholders only: `ardur profile init --path <profile-file> --force` to
choose a writable Markdown profile path, then
`ardur protect claude-code --profile <profile-file>` to use that profile. This
is local/no-key setup recovery guidance; it does not prove live Claude/provider
behavior, release readiness, or universal filesystem validation.

### `ardur protect claude-code`

Compile a Mission Passport (from an `ARDUR.md` profile or from CLI flags) and
write `active_mission.jwt` for the Claude Code plugin to read. Prints the
exact `claude` invocation that pairs the plugin with the active passport.

```text
ardur protect claude-code [--scope DIR] [--profile PATH]
                          [--mode read-only|safe-coding]
                          [--json] [--home DIR] [--plugin-dir DIR]
                          [--keys-dir DIR] [--agent-id ID]
                          [--mission TEXT]
                          [--max-tool-calls N] [--max-duration-s N]
                          [--ttl-s N]
                          [--forbid-rules FILE]
                          [--cedar-policy FILE]
                          [--cedar-entities FILE]
```

Profile mode and CLI mode set the same Mission Passport — the Markdown
profile is a friendly layer over the same capability set.

If neither `--scope` nor a profile `Protect folder:` value is available, the
command exits nonzero without configuring Claude Code. JSON output includes
`ok: false`, `error: "missing_scope"`, `condition: "missing_scope"`, and
local `next_steps`; human output prints the same recovery guidance under a
"Next steps" section with placeholders such as `<your-project>`.

If the selected Claude Code plugin directory is missing or incomplete, the
command also exits nonzero without writing `active_mission.jwt`. JSON output
includes `ok: false`, `error: "claude_code_plugin_incomplete"`,
`condition: "claude_code_plugin_incomplete"`, stable `missing_checks`, and
placeholder-only `next_steps` such as
`ardur doctor-claude-code --plugin-dir <claude-code-plugin> --home <ardur-home>`;
human output prints the same recovery guidance without a Python traceback or raw
local temp paths.

If the selected plugin directory is present but local plugin-content validation
fails, the command exits nonzero before writing `active_mission.jwt`, keys, or
hook artifacts. JSON output includes `ok: false`,
`error: "claude_code_plugin_invalid"`,
`condition: "claude_code_plugin_invalid"`, stable `invalid_checks` such as
`plugin_manifest`, and placeholder-only `next_steps`; human output prints the
same recovery guidance without a traceback or raw local temp paths. This is
local/no-key validation of the supplied plugin directory only; it does not prove
live Claude provider behavior or complete plugin schema parity.

Policy input flags are local setup inputs for additional policy backends:
`--forbid-rules FILE` loads forbid-rules JSON, `--cedar-policy FILE` loads a
Cedar policy, and `--cedar-entities FILE` optionally loads Cedar entities JSON.
If any policy input is missing, unreadable, or invalid, `ardur protect
claude-code` fails closed before generating or writing an active passport. JSON
output uses `ok: false`, `error: "protect_policy_input_invalid"`, stable
`condition` and `policy_input` fields, and placeholder-only `next_steps`; human
output prints the same recovery guidance under "Next steps". stderr stays empty
with no traceback, and Ardur does not echo raw temp paths, local homes, tokens,
or policy contents. This validates local/no-key setup only; it is not live
Claude or provider proof.

### `ardur claude-code-hook`

Implements the Claude Code hook executable invoked by
`plugins/claude-code/hooks/`. Not intended for human invocation; called by
Claude Code with hook-specific stdin payloads (`pre`, `post`, `subagent-start`,
`subagent-stop`).

```text
ardur claude-code-hook pre --keys-dir <keys-dir> < <claude-code-hook-event-json-file>
```

If stdin is malformed JSON or parses to a non-object JSON value, the command
fails closed with exit code `1` and prints a JSON response with `ok: false`,
matching `error` and `condition` fields, a concise `detail`, and
placeholder-only `next_steps`. The recovery hints point to local commands such
as `ardur protect claude-code --scope <your-project> --home <ardur-home>` and
`ardur claude-code-hook pre --keys-dir <keys-dir> < <claude-code-hook-event-json-file>`.
They do not call Claude, contact a provider, claim visibility into
provider-hidden actions, or require copying sensitive values or local private paths
into shared logs.

### `ardur claude-code-report`

Read a Claude Code receipt chain and emit a human or JSON summary of allow,
deny, and chain-verification outcomes.

```text
ardur claude-code-report [--home DIR] [--chain-dir DIR] [--keys-dir DIR]
                         [--verify-expiry] [--json]
```

`--verify-expiry` also enforces short receipt expiry windows during chain
verification (off by default so reports work on archived chains).

When no local Claude Code hook receipts are present, the JSON report includes a
`next_steps` array and the human output prints a concise "Next steps" section:
configure `ardur protect claude-code`, run the printed
`claude --plugin-dir ...` command, then rerun `ardur claude-code-report`. These
hints use placeholders such as `<your-project>`, `<ardur-home>`, and
`<claude-code-plugin>`; they do not call Claude, contact a provider, or imply
visibility into provider-hidden actions.

### `ardur gemini-cli-fixture`

Write a local-only Gemini CLI settings/context fixture and print a redacted
shareable context document with digests for the generated files.

```text
ardur gemini-cli-fixture [--home DIR] [--project-dir DIR]
                         [--chain-dir DIR] [--keys-dir DIR]
```

The fixture writes `settings.json`, `extensions/ardur-local/gemini-extension.json`,
and `GEMINI.md` under the selected local directories. It is a proof harness for
visible Gemini CLI hook/tool-boundary events; it is not a live-provider or
server-side enforcement claim.

### `ardur gemini-cli-hook`

Run the local-only Gemini CLI pre-tool-call hook adapter. The hook reads one
JSON object from stdin, evaluates the active Mission Passport from
`ARDUR_MISSION_PASSPORT`, appends a signed receipt under
`ARDUR_GEMINI_HOOK_DIR` (or the default Ardur home), and prints a JSON result.

```text
ardur gemini-cli-hook [pre|--phase pre] [--keys-dir DIR]
```

If stdin is malformed JSON or parses to a non-object JSON value, the command
fails closed with exit code `1` and prints a JSON response with `ok: false`,
matching `error` and `condition` fields, a concise `detail`, and
placeholder-only `next_steps`. The recovery hints point to local commands such
as `ardur gemini-cli-fixture --project-dir <your-project>` and
`ardur gemini-cli-hook pre --keys-dir <keys-dir> < <gemini-hook-event-json-file>`.
They do not call Gemini, contact a provider, claim visibility into
provider-hidden actions, or require copying raw tokens or local private paths
into shared logs.

If stdin is a valid JSON object but no active Mission Passport is available,
the command also fails closed with exit code `2` and stdout JSON containing
`status: "deny"`, `block: true`, matching `condition`/`error` fields set to
`gemini_cli_hook_missing_active_passport`, and a `claim_boundary` stating that
no receipt was emitted because no valid Mission Passport was available. The
response emits no receipt before a valid passport exists, keeps stderr empty,
emits no traceback, and includes placeholder-only `next_steps` for issuing a
local Mission Passport, setting `ARDUR_MISSION_PASSPORT`, and rerunning
`ardur gemini-cli-hook pre --keys-dir <keys-dir> < <gemini-hook-event-json-file>`.
This missing-passport recovery path is local/no-key guidance only; it does not
call Gemini, contact a provider, or claim provider-hidden visibility.

`status=allow` means Ardur recorded evidence and left Gemini/user permission
flow authoritative. `status=deny` and `status=unknown` return a blocking result
for wrappers that fail closed. Unknown results are used for unmapped Gemini tool
schemas or other coverage gaps instead of silently treating insufficient
evidence as safe success.

### `ardur gemini-cli-report`

Verify Gemini CLI hook receipt chains and emit a redacted local observability
report with allow/deny/unknown counts, chain verification status, coverage gaps,
and the explicit non-claims for provider-hidden reasoning/server-side tool calls.

```text
ardur gemini-cli-report [--home DIR] [--chain-dir DIR] [--keys-dir DIR]
                        [--verify-expiry] [--json]
```

When no local Gemini CLI hook receipts are present, the JSON report includes a
`next_steps` array and the human output prints a concise "Next steps" section:
create a local fixture with `ardur gemini-cli-fixture --project-dir <your-project>`,
configure Gemini CLI to use the generated local hook/settings, run a local
Gemini CLI command that triggers a hook, then rerun `ardur gemini-cli-report`.
These hints use placeholders such as `<your-project>`, `<ardur-home>`, and
`<chain-dir>`; they do not call Gemini, contact a provider, or imply visibility
into provider-hidden actions.

### `ardur codex-app-server-fixture`

Write a local-only Codex app-server config/schema/context fixture and print a
redacted shareable context document with digests for the generated files.

```text
ardur codex-app-server-fixture [--home DIR] [--project-dir DIR]
                               [--chain-dir DIR] [--keys-dir DIR]
```

By default the fixture writes under isolated Ardur local state, not the caller's
real `~/.codex`. It writes `config.json`, `ardur-host-event.schema.json`, and
`CODEX.md` under the selected local directories. This is an adoption/proof
harness for visible local Codex app-server or host-event-style fields only.

### `ardur codex-app-server-event`

Read one representative Codex app-server/host-event JSON object from stdin,
evaluate the active Mission Passport from `ARDUR_MISSION_PASSPORT`, append a
signed receipt under `ARDUR_CODEX_APP_SERVER_DIR` (or the default Ardur home),
and print a JSON result.

```text
ardur codex-app-server-event [--keys-dir DIR]
```

If stdin is a valid JSON object but no active Mission Passport is available,
the command fails closed with exit code `2` and stdout JSON containing
`status: "deny"`, `block: true`, matching `condition`/`error` fields set to
`codex_app_server_event_missing_active_passport`, and a `claim_boundary` stating
that no receipt was emitted because no valid Mission Passport was available. The
response emits no receipt before a valid passport exists, keeps stderr empty,
emits no traceback, and includes placeholder-only `next_steps` for issuing a
local Mission Passport, setting `ARDUR_MISSION_PASSPORT`, and rerunning
`ardur codex-app-server-event --keys-dir <keys-dir> < <event-json-file>`. This
missing-passport recovery path is local/no-key guidance only; it does not call
Codex, contact a provider, prove live Codex cloud behavior, or claim
provider-hidden visibility.

`status=allow` means Ardur recorded local evidence and left Codex/user
permission flow authoritative. `status=deny` and `status=unknown` return a
blocking result for wrappers that fail closed. Unknown results are used for
unmapped Codex host-event schemas or other coverage gaps instead of treating
insufficient evidence as safe success.

### `ardur codex-app-server-report`

Verify Codex app-server receipt chains and emit a redacted local observability
report with allow/deny/unknown counts, chain verification status, coverage gaps,
and the explicit non-claims for live Codex cloud enforcement, provider-hidden
reasoning, sandbox isolation, universal CLI/eBPF/kernel capture, or production
enforcement.

```text
ardur codex-app-server-report [--home DIR] [--chain-dir DIR] [--keys-dir DIR]
                              [--verify-expiry] [--json]
```

When no local Codex app-server receipts are present, the JSON report includes a
`next_steps` array and the human output prints a concise "Next steps" section:
create a local fixture with `ardur codex-app-server-fixture --project-dir <your-project>`,
feed a local Codex app-server host-event JSON object through
`ardur codex-app-server-event --keys-dir <keys-dir> < <event-json-file>`, then
rerun `ardur codex-app-server-report`. These hints use placeholders such as
`<your-project>`, `<ardur-home>`, `<keys-dir>`, and `<event-json-file>`; they do
not call Codex, contact a provider, prove live Codex cloud behavior, or imply
visibility into provider-hidden actions.

### `ardur posture scan`

Derive a local posture-index document from receipt chains, an optional
`ARDUR.md` profile, and an optional redacted no-key evidence bundle. The scan is
read-only: it does not write receipts, rotate keys, mutate profiles, or create
missing signing material. It reports only what local Ardur artifacts can support.

```text
ardur posture scan --receipts DIR_OR_JSONL
                    [--keys-dir DIR] [--profile ARDUR.md]
                    [--evidence-bundle bundle.redacted.json]
                    [--verify-expiry]
                    [--format json|markdown]
```

The JSON output uses `positioning=derived_local_evidence`. This is an honest
boundary label: the posture index summarizes signed local tool-call evidence,
chain status, policy verdict counts, unknown boundaries such as Bash subprocess
effects, profile digests, and redacted bundle metadata. It is not live
enterprise-wide discovery, provider-hidden visibility, kernel/process capture,
or proof of effects outside the captured tool-call boundary.

Credential-like values are emitted as `[REDACTED]`; local absolute paths are
replaced with stable `<PATH:...>` placeholders so reports can be shared without
leaking private workstation paths.

When receipt evidence is missing, unverified because public keys are unavailable,
or broken by failed chain verification, the JSON output includes a `next_steps`
array and Markdown output prints a concise `## Next steps` section. These hints
use placeholders such as `<ardur-home>`, `<chain-dir>`, `<keys-dir>`, and
`<your-project>` to guide local recovery without leaking workstation paths. The
hints point users at local receipt production, key selection, and posture-scan
reruns; they do not call live providers, prove provider-hidden actions, repair or
reconstruct missing evidence, perform asset inventory, or claim kernel/process
capture.

### `ardur posture report`

Render a posture JSON document from `ardur posture scan --format json` as a
concise Markdown report, or re-emit it as formatted JSON.

```text
ardur posture report --input posture.json [--format markdown|json]
```

If `--input` is missing, unreadable, a directory, malformed JSON, or JSON that
is not an object, the command fails closed with exit code `1`. JSON output
returns `ok: false`, matching `error` and `condition` fields, a human-readable
`message` and `detail`, and a `next_steps` array. Markdown output prints
`Error:`, `Detail:`, and a concise `Next steps:` section.

The recovery hints are local-only and placeholder-only. They tell the user to
create a posture JSON document with
`ardur posture scan --receipts <chain-dir> --keys-dir <keys-dir> --format json > <posture-json>`,
then rerun `ardur posture report --input <posture-json> --format json`. The
placeholders (`<chain-dir>`, `<keys-dir>`, and `<posture-json>`) are deliberate:
the report path does not print local absolute paths, raw tokens, private keys, or
provider credentials, and the hints do not call live providers, create missing
evidence, reconstruct private keys, prove provider-hidden behavior, or claim
kernel/process capture.

## Where to look next

- [`../guides/ardur-personal-hub.md`](../guides/ardur-personal-hub.md) — the
  end-to-end Personal Hub walkthrough.
- [`../../python/README.md`](../../python/README.md) — install + protocol
  quickstart.
- [`../../plugins/claude-code/README.md`](../../plugins/claude-code/README.md) —
  the Claude Code plugin's own README, including receipt verification.
