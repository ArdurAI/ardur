# Pre-action spend budgets

Ardur's Python library can reserve token and monetary authority before a
metered tool or provider call. This surface is separate from
`max_tool_calls`: call counts, token quantities, and money are never converted
implicitly.

## Policy claim

Pass `spend_budget` when constructing a `MissionPassport`:

```python
from vibap import MissionPassport

mission = MissionPassport(
    agent_id="report-agent",
    mission="Generate the approved report",
    allowed_tools=["llm_generate"],
    resource_scope=["**"],
    spend_budget={
        "version": 1,
        "currency": "USD",
        "metered_tools": ["llm_generate"],
        "ceilings": {
            "tokens": {
                "session": 100_000,
                "agent": 200_000,
                "lineage": 500_000,
            },
            "currency_micros": {
                "session": 2_000_000,
                "agent": 4_000_000,
                "lineage": 10_000_000,
            },
        },
    },
)
```

All amounts must be non-negative integers no greater than
`9007199254740991`. `currency_micros` means one millionth of the declared
three-letter uppercase currency. Issuance adds `lineage_id`; mission authors
must not invent a different lineage identity for a child. Derived children
inherit the exact policy and share the root lineage ceiling.

Only tools named in `metered_tools` require a spend request. Supplying a spend
request for an unmetered tool fails closed so an adapter cannot mistakenly
believe an unenforced request was reserved.

## Operator quote snapshots

Quotes are immutable local configuration. They bind a quote ID to one exact
tool, model, currency, validity interval, and integer input/output rates:

```python
import time

from vibap import GovernanceProxy, SpendQuote, StaticSpendQuoteStore

now = int(time.time())
quote_store = StaticSpendQuoteStore([
    SpendQuote(
        quote_id="approved-model-2026-07",
        tool_name="llm_generate",
        model="approved-model-v1",
        currency="USD",
        input_micros_per_million_tokens=1_000_000,
        output_micros_per_million_tokens=2_000_000,
        valid_from=now,
        valid_until=now + 86_400,
    )
])

proxy = GovernanceProxy(spend_quote_store=quote_store)
```

The values above demonstrate the contract; they are not provider prices.
Operators own price sourcing, review, rotation, and validity intervals. Ardur
does not fetch pricing over the network and does not accept a rate or currency
from the caller or provider response.

## Reserve before execution

The adapter provides bounded usage intent, not pricing authority:

```python
from vibap import Decision, SpendReservationRequest

request = SpendReservationRequest(
    request_id="adapter-idempotency-key",
    quote_id="approved-model-2026-07",
    model="approved-model-v1",
    max_input_tokens=4_000,
    max_output_tokens=2_000,
)

decision, reason = proxy.evaluate_tool_call(
    session,
    "llm_generate",
    {"input_digest": "adapter-owned-bounded-reference"},
    spend_request=request,
)

if decision != Decision.PERMIT:
    # Do not invoke the provider.
    raise PermissionError(reason)

response = provider.generate(...)
```

The ledger atomically checks token and money at session, agent, and lineage
scopes. A request exceeding any scope is denied before `PERMIT`. Reusing an
active request ID with the same fingerprint is also denied to prevent a second
provider execution; reusing it with different semantics is a conflict. Every
close operation is bound to the session that created the reservation, so a
sibling session cannot settle or quarantine it.

If evaluation raises after the ledger accepted a reservation but before
returning, the proxy attempts an idempotent internal release. A failed release
raises `spend_compensation_failed` and deliberately retains the reservation;
operators must treat that state as unresolved rather than assuming authority
was refunded.

For tools governed by both `risk_budget` and `spend_budget`, the proxy runs the
typed risk preflight first, then reserves spend. Every non-`PERMIT` result and
every evaluation exception uses the same idempotent compensation path to
release whichever reservations were acquired. A signed decision event may
therefore contain both a spend `budget_delta` and typed risk remaining-budget
evidence; neither gate's evidence replaces the other.

## Settle or quarantine

After a trusted adapter verifies provider usage, settle against the originally
bound quote:

```python
result = proxy.settle_spend(
    session,
    request_id=request.request_id,
    actual_input_tokens=3_700,
    actual_output_tokens=1_250,
    usage_proof_digest="a" * 64,
)
```

The digest is a bounded reference to trusted usage evidence; raw provider
responses and usage documents do not enter the signed receipt. Settlement
recomputes cost using the quote selected at reservation. It consumes actual
usage and refunds only the verified remainder.

If trusted usage is missing, quarantine explicitly:

```python
proxy.quarantine_spend(
    session,
    request_id=request.request_id,
    reason_code="spend_settlement_evidence_missing",
)
```

`quarantine_stale_spend()` moves old active reservations to quarantine without
refunding them. It scans only reservations owned by the supplied governance
session. A later trusted `settle_spend()` reconciles a quarantined reservation.
Usage beyond the reserved input/output bounds remains quarantined; a
post-action observation cannot retroactively authorize an overspend.

Every active reservation must be settled, released, or quarantined before
`end_session()` or attestation finalization. Once finalized, the proxy rejects
all spend lifecycle changes so the signed receipt chain cannot be extended
after its terminal summary. Reconcile quarantined usage before finalization if
the resulting settlement must appear in that session's signed evidence.

## Evidence and metrics

Metered action receipts carry a spend-shaped `budget_delta` with operation,
requested/reserved/actual/refunded amounts, scope-level remaining authority,
currency, quote digest, reservation hash, and stable reason code. Settlement
and quarantine append separate signed receipt-chain links.

The runtime emits:

- `ardur_spend_events_total{operation,outcome}`
- `ardur_spend_amount_total{operation,unit}`

These labels never include agent, session, lineage, quote, model, request, or
account identifiers.

## Failure modes and deployment boundary

- Missing, unknown, not-yet-valid, expired, mismatched, or unavailable quote
  data fails closed.
- Missing trusted settlement retains the reservation. Conservative retention
  can reduce availability and must be monitored.
- Exceptional evaluation compensates accepted reservations when possible. If
  durable compensation cannot be proven, the reservation remains active and
  session finalization fails closed.
- Closed records are retained through the passport lifetime for replay
  protection. Expired terminal records may be pruned; settled amounts remain
  archived in aggregate scope accounting. Active and quarantined reservations
  are never age-refunded.
- The reference ledger coordinates processes that share one local state
  directory. It is not a distributed consensus mechanism. Multi-host proxies
  need a transactional `SpendBudgetLedger` implementation with equivalent
  atomic and idempotent semantics.
- Quote configuration and trusted usage adapters are part of the operator's
  trusted computing base.
- This surface does not reconcile cloud bills, implement chargeback, or prove
  provider metering independently.

The design rationale is recorded in
[ADR-025](../decisions/ADR-025-pre-action-spend-reservation.md).
