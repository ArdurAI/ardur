---
title: "How It Works"
description: "The simple idea behind Ardur: declare, enforce, prove."
weight: 8
maturity: ["public-now"]
claim_types: ["orientation", "runtime-boundary"]
surfaces: ["python", "docs"]
frameworks: ["framework-agnostic"]
evidence_levels: ["code-and-doc"]
---

Ardur does three things. Here's each one, explained without jargon.

---

## 1. You declare what the agent can do

Create a file called `ARDUR.md` in your project. It looks like this:

```markdown
# Mission Profile

## Mission
Build and test a REST API for user management

## Allowed Tools
- read_file
- write_file
- search_files

## Forbidden Tools
- delete_file
- execute_shell

## Resource Scope
- ./src/
- ./tests/

## Max Tool Calls
200
```

That's it. No JSON, no YAML, no custom language. Ardur compiles this into a
signed Mission Passport — a JWT that cryptographically binds the agent to
these rules.

## 2. Ardur enforces the rules at runtime

Every time the agent tries to call a tool, Ardur checks:

- **Is this tool allowed?** If it's not in the allowed list, deny.
- **Is it forbidden?** Some tools are never OK, regardless.
- **Is the target in scope?** If the agent tries to read outside `./src/`, deny.
- **Has the budget been exceeded?** Too many calls or too long running? Deny.
- **Do the policy backends agree?** Cedar rules, forbid-rules, custom checks.

All of this happens before the tool runs. The agent never touches resources
it shouldn't.

## 3. You get signed proof of everything

Every decision produces an Execution Receipt — a JWT signed with the issuer's
private key. Each receipt links to the previous one by SHA-256 hash. The chain
is tamper-evident: change any receipt and every receipt after it fails
verification.

A session receipt chain gives you:

- **A complete timeline** — what happened and when
- **The verdict** — PERMIT or DENY for each tool call
- **The reason** — which rule triggered a denial
- **Cryptographic integrity** — proof the chain hasn't been modified

## Where Ardur sits

```
┌─────────────────────────────────────────┐
│  Your AI agent (Claude Code, LangChain,  │
│  AutoGen, custom, ...)                   │
└──────────────────┬──────────────────────┘
                   │ every tool call
                   ▼
┌─────────────────────────────────────────┐
│            Ardur Governance Proxy         │
│                                          │
│  ┌──────────┐  ┌────────┐  ┌─────────┐ │
│  │ Mission   │  │ Policy  │  │ Receipt  │ │
│  │ Passport  │  │ Engine  │  │ Chain    │ │
│  │ Verify    │  │ Eval    │  │ Sign     │ │
│  └──────────┘  └────────┘  └─────────┘ │
│                                          │
│  Returns: PERMIT with receipt            │
│        or DENY with reason               │
└──────────────────┬──────────────────────┘
                   │ only if PERMIT
                   ▼
┌─────────────────────────────────────────┐
│        Your tools & resources            │
│  (filesystem, terminal, APIs, DBs)      │
└─────────────────────────────────────────┘
```

The proxy is the enforcement point. No bypass, no direct access, no "oops I
forgot to turn it on."

## What Ardur does NOT do

Honesty matters. Ardur is not:

- **A sandbox** — it governs at the tool-call boundary, not the kernel level (yet)
- **A model guard** — it doesn't inspect or filter what the model says, only what tools it calls
- **A replacement for OS security** — use it with, not instead of, file permissions and access controls

See the [coverage map]({{< relref "/source/docs/coverage-map/" >}})
for a precise audit of what's captured and what's on the roadmap.
