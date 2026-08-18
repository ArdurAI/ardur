# ADR-028: Claude Code child authority binding

**Status:** Accepted

**Date:** 2026-07-15

## Context

Ardur can block a Claude Code `Agent` call in `PreToolUse`, whose hook input
contains `tool_use_id`, the requested subagent type, and prompt/description
fields. Claude later emits `SubagentStart` with `agent_id` and `agent_type`, but
that lifecycle hook cannot block and does not include the originating Agent
`tool_use_id`. Tool hooks executed inside the child carry the common
`agent_id`. `SubagentStop` and post-tool hooks occur after execution.

This platform contract creates a correlation gap between the blockable parent
dispatch and the provider-assigned child id. Prompt equality, transcript
paths, timing proximity, and model output are not stable authority identifiers.
They can contain private content, collide, change independently, or be forged
by untrusted input.

Primary references:

- [Anthropic Claude Code hooks reference](https://code.claude.com/docs/en/hooks)
- [Anthropic Claude Code subagents](https://code.claude.com/docs/en/sub-agents)

## Decision

1. Child delegation is disabled unless the operator supplies a private mode-0600
   regular JSON registry keyed by exact Claude agent type. Setup validates the
   full registry before issuing a delegation-enabled parent passport.
2. A permitted `Agent` pre-hook atomically reserves a strictly narrower Ardur
   child grant and parent budget. A child policy cannot include nested `Agent`
   or `Task` authority, directly or through a wildcard, in this profile.
3. `SubagentStart` binds the provider `agent_id` to one pending reservation of
   the same type. Multiple pending reservations of one type are bindable only
   when their normalized policy fingerprints are byte-equivalent; selection is
   deterministic by hashed request key. Mixed policies, missing ids, unknown
   types, stop-before-start, and inconsistent state quarantine rather than
   guess.
4. Every bound child tool pre-hook is evaluated with the child grant. It never
   falls back to the parent passport. Permit is persisted before the platform
   executes; success settles exactly once, while failure or missing outcome
   quarantines the child. Restarts reconcile durable leases fail closed.
   Child-enabled traces bypass the parent-only native daemon until that daemon
   implements the same reservation and binding contract.
5. Binding state contains only opaque handles, hashes, agent type, policy
   fingerprints, states, expiry, and terminal codes. Prompt text, model output,
   provider event timestamps, platform ids, resource paths, credentials,
   transcript paths, and transcript contents are excluded from durable
   authority state.
6. Lifecycle receipts expose binding state and policy fingerprint. Reports
   claim exact child attribution only when the tool hook's `agent_id` resolves
   through the opaque binding. All other tool evidence remains trace-only.
   Agent dispatch receipt telemetry keeps only the agent type and argument
   digest, not prompt or description text.

## Consequences

- A configured child receives fewer tools, no wider resource scope, a smaller
  action budget, a shorter lifetime, and at most the parent's remaining
  delegation depth.
- An operator must maintain the agent-type registry and budget headroom. A bad
  registry fails setup; a runtime mismatch denies or quarantines the lane.
- Concurrent same-type children are supported only when their authority is
  interchangeable. The system intentionally sacrifices permissiveness when
  the provider does not expose a unique dispatch-to-start correlation key.
- Local state adds small filesystem and signature overhead. It avoids external
  infrastructure and provider API cost; monetary provider spend remains
  unavailable without trusted signed billing telemetry.
- Ardur governs the local tool-call boundary, not provider reasoning,
  subprocess effects, or hidden server-side actions.

## Alternatives considered

- **Match prompt or description text.** Rejected because content is untrusted,
  privacy-sensitive, mutable, and not a platform identity guarantee.
- **Read child transcripts and search for tool ids.** Rejected because paths
  and contents are private evidence, file access is race-prone, and the match
  occurs after authority should already have been decided.
- **Let every child inherit the parent passport.** Rejected because it widens
  authority by omission and defeats least privilege and independent budgets.
- **Deny all parallel same-type children.** Rejected as unnecessarily strict
  when every pending child policy is byte-equivalent; deterministic binding is
  safe because the authorities are interchangeable.
- **Allow unbound children and report them later.** Rejected because
  observation is not enforcement. Missing correlation must fail closed before
  the child's tool executes.