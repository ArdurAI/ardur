# AuditBench Pilot Protocol v0.1

This file is an example frozen protocol for exercising the independent
evaluation pipeline. It is not a preregistered study and must not be used to
support a headline benchmark claim.

## Study design

- Use at least two systems under test.
- Keep oracle and evidence annotator pools disjoint for each scenario.
- Require at least two annotators per view and a separate adjudicator for any
  disagreement.
- Assign at least 30 percent of scenarios to the held-out split before any SUT
  result is produced.
- Score accuracy, false-safe rate, missed-violation rate, over-abstention rate,
  and per-class precision/recall/F1 exactly once on the held-out split.

## Claim rule

Pilot artifacts validate the pipeline only. They do not establish independent
annotation, generalization, product superiority, or publication readiness.
