# Proof Media That Actually Means Something

> Article 05 of the Ardur journey-log series. Date: 2026-04-29.
> Prerequisite reading: none. Cross-references:
> [`MEDIA.md`](../../MEDIA.md),
> [`media/selected-assets.json`](../../media/selected-assets.json),
> [`docs/specs/verifier-contract-v0.1.md`](../specs/verifier-contract-v0.1.md),
> [`docs/known-limitations.md`](../known-limitations.md).

## The problem

Most security-software demos are recordings of someone running a
command, the command printing something hopeful, and the recording
ending. The viewer is invited to assume the command did what its
output claimed. That works as marketing. It doesn't work as evidence.

The gap between "demo" and "proof" is small but load-bearing. A demo
shows that the software can be run. A proof shows that running it
produced an artifact whose contents an independent verifier can check
against a stated claim. The difference is whether anyone can argue
with what they just watched.

This article is about the shape we picked for proof media in this
repo, why each piece of the shape carries weight, and what's still in
development.

## The shape: command → artifact → verifier → result

Every cast in `media/casts/` follows the same four-step shape:

1. **Command** — a specific invocation, with all flags, recorded
   verbatim. The metadata header on each cast carries the command
   string, so you don't have to read the recording to know what was
   run.
2. **Artifact** — the command writes outputs that are not the
   terminal text. Mission declarations, signed receipts, denial logs,
   status lists. The terminal is the medium, not the proof.
3. **Verifier** — a separable script
   (`run_live_core_capability_proof.py`, for the casts in this
   pack) reads the artifacts and emits a verdict. The verifier's
   logic is the load-bearing claim, not the command.
4. **Result** — the verifier's exit code and structured output. A
   recording is a proof only if the verifier exited cleanly *and*
   its output makes a claim a reader can independently re-check by
   running the same verifier on the same artifacts.

Take ARDUR-CAP-001 (mission declaration and binding) as the example.
Its cast metadata header carries:

| Field | Value |
|---|---|
| `command` | `python docs/scripts/run_live_core_capability_proof.py --capability ARDUR-CAP-001` |
| `verifier` | `run_live_core_capability_proof.py --capability ARDUR-CAP-001` |
| `proof_scope` | `framework-live` |
| `exit_code` | `0` |
| `elapsed_s` | `229.941` |
| `evidence_note` | `Recorded command must exit 0; proof semantics come from the verifier output.` |

The whole shape is in those six fields. Command is named. Verifier
is named. Scope is declared (`framework-live` means the run hit a
real agent-framework integration, not just a unit-test harness).
Exit code is asserted. Wall-clock time is given so the cost of the
proof is visible. And the `evidence_note` is the explicit boundary:
the *recording* doesn't carry proof semantics on its own — the
*verifier output inside the recording* does.

If a viewer wants to argue with the cast, the metadata tells them
what to argue with: re-run the named verifier on the artifacts the
named command produced, see whether it still exits 0 with the same
output.

## Why sanitized ≠ hidden

Each cast's metadata also carries:

```json
"redaction": "known secret environment values and token-like patterns redacted"
```

This is the part that's most often misunderstood. *Sanitized* in
this repo doesn't mean "we cut the parts we didn't want you to
see." It means "we replaced known-secret values (env vars holding
API keys, JWT bearer tokens that would otherwise persist beyond
their intended lifetime, capability JSON containing
operator-identifying paths) with placeholders that preserve the
*shape* of the data while removing the *content* that has external
meaning."

The shape stays. The bytes change.

Why this matters for proof:

- A redacted JWT is still a JWT — header + payload + signature, three
  base64url segments separated by dots. A reader can see the *type
  signature* of what flowed without seeing the bytes that would
  re-authenticate.
- A redacted API token is still 40 characters of `[A-Za-z0-9]`. A
  reader can see the call site received "a token of the right
  shape," not "a token whose bytes are recoverable from the
  recording."
- The metadata's `redaction` field makes this disclosure explicit.
  No reader has to guess whether anything was cut.

This is the inverse of the old "blurred screenshot" pattern, where
a demo author covers parts of the output with black bars and leaves
the viewer wondering what was hidden. Here the algorithm is
published, the redaction targets are enumerated in metadata, and
the shape of the data is preserved so the proof of *control flow*
remains inspectable.

## What's in the pack today

Four casts ship in this first wave. Each carries the same metadata
header shape; the differences are in `proof_scope` and runtime cost.

| ID | Title | `proof_scope` | Wall-clock |
|---|---|---|---|
| `ARDUR-CAP-001` | Mission declaration and binding | `framework-live` | 229.9 s |
| `ARDUR-CAP-002` | Tool allow and deny enforcement | `framework-live` | 233.2 s |
| `ARDUR-CAP-003` | Resource scope enforcement | `framework-live` | 240.9 s |
| `ARDUR-CAP-014` | Active revocation | `foundation` | (shorter) |

The first three exercise the protocol against a real agent-framework
integration — `framework-live` means the agent and the verifier ran
in the same process tree against the same network surface, not in a
benchmark harness. The cost is real: roughly four minutes of
wall-clock per capability at this scope. ARDUR-CAP-014 is at
`foundation` scope: just the core revocation primitive, no
framework. Smaller numerator, smaller runtime, scope explicit.

The metadata header tells you the scope. The article doesn't have
to.

## The gap: archival vs re-runnable

Here's the part that has to be said clearly: **none of these casts
are re-runnable by you, today, from this repo alone.**

The casts capture terminal sessions executed against the runtime
*before* the public code lift was complete. Internally they
reference scripts
(`docs/scripts/run_live_core_capability_proof.py`, the artifact
paths under `docs/proof/*`, example wiring in
`examples/live-governance/*`) that have not yet been imported into
this public repo. You can watch the cast and inspect its metadata.
You can read the verifier's output as it scrolls past. What you
cannot do *yet* is `git clone`, `python docs/scripts/...` and
produce the same artifacts on your own machine.

We chose to ship the casts anyway, with
[`MEDIA.md`](../../MEDIA.md) calling this gap out as
*archival walkthroughs, not re-runnable proofs* on its first page.
The reasoning:

- The casts show the proof *shape* — command, artifact, verifier,
  result, exit code — even when re-run hasn't landed. A reader can
  evaluate the shape independently of the runnability.
- The
  [`media/selected-assets.json`](../../media/selected-assets.json)
  ledger declares each cast as
  `asset_class: archival_walkthrough`, not `proof`. The schema
  reserves the word "proof" for media that lands after the code
  lift, when the verifier scripts and artifact paths are public and
  the runs are reproducible.
- Hiding the gap until then would have been the wrong call. A repo
  that quietly inflates "demo" to "proof" loses credibility the
  first time someone tries to run the demo and finds the script
  isn't there.

The re-runnable proof path lands when the scripts and artifact paths
referenced in these casts are public. At that point the casts will
be re-recorded against the imported runtime — same metadata shape,
same verifier names, but now the command on screen really is the
command in your terminal — and the *archival walkthroughs* caveat
is removed.

Article 11 (the rigged-tests audit, in the queue) goes deeper into
the self-referential failure mode where a "proof" looks like a
proof, exits 0, and is actually testing nothing — and how we caught
ourselves doing it. Pre-flight reading for that article: this one.

## What this means for users

Two practical points:

1. **The metadata is load-bearing.** When you read a cast, read the
   header first. Title, command, verifier, scope, exit code,
   elapsed time, redaction note. Each of those is a claim. If a
   future cast ships without that header — or with a header that
   doesn't match the recording inside — file an issue. That's a
   regression on the contract, not a stylistic glitch.
2. **Naming the gap is the discipline.** When the re-runnable proof
   path lands, the casts will say so in their metadata
   (`asset_class: proof` instead of `archival_walkthrough`). Until
   that field flips, treat the casts as walkthroughs that show
   *what the protocol does*, not as reproducers that prove *the
   protocol does it on your machine*.

Proof media is one of the easier places to fake quality. A
twenty-second GIF with green checkmarks and a hopeful tagline reads
as "proof" to a casual scroller. We want to be the repo where proof
media isn't that, and where the gap between "looks like proof" and
"is proof" is declared in metadata rather than left for the reader
to infer.

---

*Article 05 — Proof Media That Actually Means Something. Part of the
Ardur journey-log series. Cast files at
[`media/casts/`](../../media/casts/), inventory at
[`media/selected-assets.json`](../../media/selected-assets.json),
contract framing at
[`docs/specs/verifier-contract-v0.1.md`](../specs/verifier-contract-v0.1.md).
Comments and corrections via GitHub Discussions.*
