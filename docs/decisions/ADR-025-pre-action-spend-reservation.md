# ADR-025: Pre-action spend reservation and conservative settlement

**Status:** Accepted

**Date:** 2026-07-14

## Context

Ardur already enforces governed tool-call counts and reserves descendant call
authority. A provider or metered tool call has a different budget lifecycle:
the final output quantity is unknown before execution, price depends on an
operator-approved quote, and actual usage arrives only after the action. A
post-call cost field cannot prevent an over-budget call.

Mutable provider prices, provider-returned model labels, and caller-supplied
rates are not authorization authority. Fetching current prices during policy
evaluation would also add network availability and latency to a fail-closed hot
path. Binary floating-point arithmetic is unsuitable for exact budget gates.

The existing local lineage ledger establishes Ardur's reference durability
model: process-local coordination plus an exclusive file lock, a temporary
state file, and atomic replacement. Python documents `flock(LOCK_EX)` as the
exclusive advisory-lock primitive and `os.replace()` as atomic on POSIX when
successful. RFC 8785 defines the invariant JSON representation Ardur already
uses for signed and hashed data.

Primary references:

- [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
- [Python `fcntl.flock` documentation](https://docs.python.org/3/library/fcntl.html#fcntl.flock)
- [Python `os.replace` documentation](https://docs.python.org/3/library/os.html#os.replace)

## Decision

1. Spend authority is an optional signed Mission Passport claim distinct from
   call counts. It declares exact metered tools, a currency, and integer token
   and currency-micro ceilings for session, agent, and delegation-lineage
   scopes.
2. Root issuance binds spend authority to the root passport JTI. Derived child
   passports inherit the complete spend policy and lineage identifier; they
   cannot change currency, metered tools, or ceilings.
3. Operators load immutable, validity-bounded quote snapshots into the proxy.
   A caller supplies only quote ID, model ID, request ID, known maximum input
   tokens, and configured maximum output tokens. The quote supplies rates,
   currency, tool binding, model binding, and validity. No authorization-path
   network fetch occurs.
4. Authorization uses non-negative integers no larger than the interoperable
   JSON safe-integer bound. Monetary rates are currency micro-units per million
   tokens; multiplication and ceiling division use integers only.
5. One file-locked transaction reserves both token and monetary upper bounds
   across all three scopes before `evaluate_tool_call()` can return `PERMIT`.
   A duplicate active request is denied rather than permitting a potentially
   duplicated provider execution. Close operations must present the session
   identity bound into the reservation; one sibling cannot settle, release, or
   quarantine another sibling's authority.
6. Trusted settlement recomputes actual money from the originally bound quote.
   Usage within the reservation consumes actual amounts and refunds only the
   proven unused portion. Missing, invalid, or oversized usage is
   quarantined with the conservative reservation retained.
7. Stale reservations can be moved to quarantine by their owning session and
   later reconciled with trusted usage. There is no automatic timeout refund.
   A session cannot finalize while it has an active reservation, and spend
   lifecycle APIs cannot append evidence after session finalization.
8. Reservation decisions and settlement lifecycle operations emit separate,
   signed, hash-linked receipts. Existing receipts are immutable. Public
   evidence contains bounded amounts, remaining scopes, currency, quote and
   request hashes, and reason codes; it excludes prompts, responses, raw quote
   documents, account identifiers, credentials, request IDs, and host paths.
9. Metrics use only bounded operation/outcome/unit labels. The reference ledger
   is local to one shared state directory; distributed deployments require an
   external transactional implementation of the same ledger interface.
10. An exception after durable reservation but before authorization returns
    triggers an idempotent release. If that compensation cannot be persisted,
    evaluation fails with `spend_compensation_failed` and retains the full
    reservation. A failure in receipt construction can prevent signed evidence
    for that internal compensation, so the durable ledger remains the
    fail-closed source of truth for recovery.

## Consequences

- A metered action cannot start after any declared scope is exhausted.
- Conservative output reservation can temporarily reject work that would have
  fit after actual settlement. This is an intentional availability-for-safety
  trade-off.
- Crashes and missing usage retain authority, so operators need stale
  quarantine monitoring and a trusted reconciliation path.
- Adapters are in the trusted computing base for usage evidence. The ledger
  prevents replay and oversubscription but cannot prove a provider's usage
  report independently.
- Credentials without `spend_budget` retain existing call-count behavior.
- The reference implementation does not perform provider billing
  reconciliation, chargeback, or cross-host consensus.

## Alternatives considered

- **Record provider cost after the call.** Rejected because it observes an
  overspend after the external side effect and cannot enforce a pre-action cap.
- **Fetch live prices during evaluation.** Rejected because mutable remote data
  would become authorization authority and introduce a network fail point.
- **Let the caller submit a rate or provider-selected model.** Rejected because
  an untrusted caller could select a cheaper quote and widen effective spend.
- **Reuse the call-count lineage ledger.** Rejected because calls, tokens, and
  currency have different units and settlement semantics.
- **Automatically release stale reservations.** Rejected because a timeout
  does not prove that the provider call did not execute or incur cost.
- **Permit an active duplicate request idempotently.** Rejected because the
  proxy cannot guarantee the downstream provider will deduplicate execution.
