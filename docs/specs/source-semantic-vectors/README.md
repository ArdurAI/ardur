# Host adoption/governance source-semantic vectors

These vectors are no-key, source-semantic fixtures. They encode what Ardur can safely carry from current host adoption and governance source signals without running Codex, Claude Code, Gemini CLI, ToolHive, MCP proxies, GitHub Actions, or any live provider.

Each JSONL row is a bounded evidence example:

- `policy_input` for host rules, permission grammar, parser behavior, tool configuration, and retention policy.
- `session_context` for imported or nested context digests, project binding, workflow/config version, and config-migration state.
- `host_runtime_event` for host-semantic events such as import, delete, and `@` file-reference resolution requests.
- `cloud_agent_run` for GitHub Action invocation/config surfaces and output digests.
- `deployment_context` for MCP/control-plane proxy/auth topology and limits.
- `unknown` for anything not proved by Ardur-owned capture or this no-key fixture.

The fixture deliberately does not prove live host behavior, provider-hidden behavior, action-runner side effects, live file reads, credentials, attachment contents, ToolHive/MCP enforcement, universal CLI capture, or public readiness. It is a reviewable bridge from the private source matrix into schema-backed public-safe example rows.

Files:

- `host-adoption-governance-v0.1.schema.json` — JSON Schema for each row.
- `host-adoption-governance-v0.1.jsonl` — the starter no-key rows.

The persisted rows use placeholders and digests only. They must not contain local absolute paths, account identifiers, secrets, imported conversation bodies, attachment payloads, or unredacted file bodies.
