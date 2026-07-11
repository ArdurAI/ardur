# AuditBench Independent Evaluation Profile v0.1

Status: **pipeline implemented; independent corpus not yet collected**

This profile defines the artifact and review boundary for an AuditBench result
that is not scored against labels authored by the benchmark scenario generator
or a system under test (SUT). The current repository implements the pipeline,
strict validation, sealing, and scoring. It does not ship independent human
annotations, live-agent traces, or a headline result.

## Claim boundary

The tools can prove that a declared set of files did not change after a local
seal, that labels refer to the exact blind bundles derived from those files,
and that scoring used the sealed labels. They cannot prove that a person is
independent, that an annotator identity is genuine, or that an external
registration service accepted a claimed registration. Those facts require
operational review and external records.

`pilot` mode is for pipeline tests and method dry runs. Its results are not
independent evidence. `headline` mode additionally requires an HTTPS
registration URI, but the URI and human roles still require review outside the
binary.

## Separation of powers

1. `auditbench-oracle` accepts only `auditbench.capture.v0.1`. Unknown and
   duplicate JSON names fail. Labels, expected behavior, and SUT output are not
   fields in the schema.
2. The command writes the canonical raw capture plus separate full-oracle and
   projected-evidence artifacts. Both views receive the same exact allow/deny
   evaluation policy, which is legitimate SUT input rather than an expected
   verdict. The projection may be empty. The oracle may not be empty.
3. `auditbench-label bundle` creates one blind view. Oracle annotators answer
   what happened. Evidence annotators answer whether the projected evidence is
   sufficient. A person may not annotate both views of the same scenario.
4. `auditbench-label adjudicate` requires at least two distinct annotators per
   view. A disagreement requires a third person who did not annotate that
   scenario. The gold verdict is `insufficient_evidence` when evidence is
   insufficient or world truth remains unknown.
5. `auditbench-score seal` binds the frozen protocol, preregistration, raw
   captures, regenerated views, bundle hashes, annotation/adjudication digest,
   gold set, and split manifest. At least 30 percent of scenarios must be held
   out. Capture and annotation times must fall between registration and seal.
6. `auditbench-score score` accepts only preregistered SUT identifiers, exact
   split coverage, tri-state verdicts, a matching seal digest, and results
   created no earlier than the seal time. The report binds the exact SUT result
   artifact digest as well as the study seal digest.

## Artifact flow

```text
external capture
    -> raw capture
    -> policy + oracle view ------> independent oracle annotators --+
    -> policy + evidence view ----> independent evidence annotators +-> adjudication -> gold

frozen protocol + preregistration + corpus + gold + split manifest
    -> seal
    -> SUT run against sealed study
    -> score (held-out by default)
```

The raw capture is required at seal time. Verification regenerates both views
and compares their complete typed content, so a forged projection cannot be
hidden behind a copied `capture_sha256` string.

## Metrics

Every preregistration must name these metrics before sealing:

- accuracy;
- false-safe rate: gold `insufficient_evidence` predicted `compliant`;
- missed-violation rate: gold `violation` predicted `compliant`;
- over-abstention rate: known gold predicted `insufficient_evidence`;
- per-class precision, recall, and F1.

Rates and per-class values are JSON `null` when their denominator is zero. The
report also carries each eligible/support count so an empty class cannot be
misreported as a perfect zero-error result.

Agreement reports use pairwise observed agreement and a chance-corrected kappa
over all rating pairs for each blind view. The report is a reliability signal,
not proof that the rubric or annotators are unbiased.

## Security and privacy

- Files are bounded at 32 MiB and corpus sets at 10,000 files.
- Symlinks, non-regular files, path escape from the study root, duplicate IDs,
  duplicate JSON names, extra JSON fields, and post-seal drift fail closed.
- Generated artifacts use owner-only permissions.
- Captures must be redacted before they enter this pipeline. The normalizer does
  not discover credentials hidden in free-form resource or outcome strings.
- A local seal is content integrity, not a trusted timestamp or signature.
  Publication use should place the frozen protocol and its digest in an
  external immutable or embargoed registration before SUT evaluation.
- The binaries do not sandbox a SUT. A headline run must expose only its sealed
  evidence inputs in a separate execution environment; access to oracle, gold,
  annotation, or held-out answer files invalidates the result.

## Commands

```bash
cd go

go run ./cmd/auditbench-oracle \
  -in /study/raw/AB-I-001.capture.json \
  -out /study/corpus

go run ./cmd/auditbench-label bundle \
  -study-id auditbench-2026-01 \
  -view oracle \
  -source /study/corpus/AB-I-001.oracle.json \
  -out /study/bundles/AB-I-001.oracle.bundle.json

go run ./cmd/auditbench-label adjudicate \
  -study-id auditbench-2026-01 \
  -minimum-annotators 2 \
  -annotations /study/annotations.json \
  -decisions /study/adjudications.json \
  -out /study/gold.json

go run ./cmd/auditbench-score seal \
  -root /study \
  -corpus /study/corpus \
  -protocol /study/protocol.md \
  -prereg /study/preregistration.json \
  -gold /study/gold.json \
  -annotations /study/annotations.json \
  -adjudications /study/adjudications.json \
  -splits /study/splits.json \
  -sealed-at 2026-01-15T08:00:00Z \
  -seal /study/seal.json

go run ./cmd/auditbench-score score \
  -root /study \
  -corpus /study/corpus \
  -protocol /study/protocol.md \
  -prereg /study/preregistration.json \
  -gold /study/gold.json \
  -annotations /study/annotations.json \
  -adjudications /study/adjudications.json \
  -splits /study/splits.json \
  -seal /study/seal.json \
  -result /study/ardur-held-out.json \
  -split held_out \
  -out /study/ardur-held-out-score.json
```

## Unfinished evidence

- independent annotator recruitment and identity records;
- approval under the G-9 / issue #107 collection gate;
- an oracle collector with full process-tree and network visibility;
- privacy-reviewed real-agent traces;
- a real OPA adapter and at least one additional third-party SUT;
- an isolated evidence-only SUT runner or independently reviewed equivalent;
- an external preregistration and trusted timestamp/signature;
- the embargoed held-out corpus and one-time headline scoring run.

Until those exist, issue #40 remains open and no independent AuditBench result
is claimed.

## Methodology references

- [OSF registrations and preregistrations](https://help.osf.io/article/330-welcome-to-registrations)
- ACM, "Artifact Review and Badging - Current" (primary policy reviewed
  2026-07-11; ACM returns 403 to automated link checkers)
- [NIST AI Risk Management Framework 1.0](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf)
