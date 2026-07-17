# Technical Reference

Flat technical reference pages for the public Ardur surface. These describe
*what* a surface accepts and emits, not *how* to use it day-to-day. For task
walkthroughs see [`../guides/`](../guides/); for protocol semantics see
[`../specs/`](../specs/).

## Pages

- [CLI Reference](cli.md) — every `ardur` subcommand, its flags, and what it
  emits
- [Personal Hub HTTP API](personal-hub-api.md) — endpoints exposed by
  `ardur hub`, auth model, request and response shapes, error codes
- [`ARDUR.md` Profile Format](ardur-md-profile.md) — the plain-Markdown
  guardrail format that compiles into a Mission Passport
- [Proxy OCI Image Contract](proxy-oci-image.md) — canonical image name,
  immutable release gates, runtime hardening, state, TLS, auth, scan, and cost
  boundaries without claiming current registry availability
- [Kernel Capture Daemon Operations](kernel-capture-daemon.md) —
  control-plane-only mode, capture-loss semantics, and malformed-record
  response
- [Advisory AI Controls](advisory-ai-controls.md) — semantic-judge and
  behavioral-fingerprint defaults, non-authoritative status, failure policy,
  cost, and integration requirements
- [Pre-action Spend Budgets](spend-budgets.md) — signed token/currency policy,
  operator quote snapshots, atomic reserve/settle/quarantine semantics,
  evidence, metrics, and deployment limits
- [Agent Recognition Evaluation](agent-recognition-evaluation.md) — versioned
  maintained corpus, deterministic metrics, Wilson intervals, CI thresholds,
  and claim boundaries

## When To Update These Pages

These pages mirror the public source. When the underlying surface changes
(`python/vibap/cli.py`, `python/vibap/personal_hub.py`,
`python/vibap/ardur_profile.py`, `go/cmd/ardur-kernelcaptured`,
`go/cmd/ardur-agent-recognition-eval`,
`go/pkg/kernelcapture/agent_recognition.go`,
`go/pkg/kernelcapture/agent_recognition_evaluation.go`,
`go/pkg/kernelcapture/testdata/agent_recognition_corpus.json`,
`go/pkg/kernelcapture/testdata/agent_recognition_thresholds.json`,
`python/vibap/semantic_judge.py`, `python/vibap/behavioral_fingerprint.py`,
`Dockerfile.proxy`, or its release workflow), update the matching page in the
same change. They are deliberately mechanical so the diff is easy to review.
