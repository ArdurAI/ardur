# Cloud Model Governance Test — Comparison Summary

Run date: 2026-05-14

## Results

| Model | Duration | Tool Calls | Files (of 20) | Denials | Exceptions | Clean? |
|-------|----------|------------|---------------|---------|------------|--------|
| Cloud Model (1T) | 12.1m | 35 | 18 | 0 | 0 | YES |
| Local Model (8B) | 15.2m | 4 | 4 | 0 | 0 | YES |

**Best performer:** Cloud Model (1T) — 18 files, 35 tool calls

## Per-Model Breakdown

### Cloud Model (1T params, Ollama cloud)
- 18 of 20 planned files created
- Files built: __init__, schema, models, db, auth, repos, commits,
  branches, issues, pulls, search, activity, router, server, main,
  index.html, style.css, app.js
- Missing (turn limit): tests/test_repohub.py, README.md
- 7 phases completed, steady progress throughout
- All 35 tool calls PERMIT through Ardur proxy
- ~4.3ms avg proxy evaluation overhead

### Local Model (8B, ~5GB)
- 4 of 20 files created
- Files built: schema.py, models.py, db.py, repos.py
- Model gave up after turn 4 (returned empty response)
- All 4 tool calls PERMIT through Ardur proxy
- Very slow inference (~6 min for first tool call)
- Not suitable for large-scale code generation tasks

## Key Takeaways

1. **Ardur governance proxy enforced policy across all models with zero unauthorized tool calls.**
   Every tool invocation went through evaluate → attest → receipt.

2. **Cloud models are the only viable option** for large-scale code generation
   under governance. Local models are too slow and lack the capacity for
   sustained multi-turn tool-calling workflows.

3. **30 turns is the limiting factor** for both models — the cloud model consistently hits the turn
   limit before completing all 20 files. The governance overhead adds ~4-5ms per call
   which is negligible compared to model inference time.

## Raw Results

- `cloud-model-1t.json` — full session data for Cloud Model (1T)
- `local-model-8b.json` — full session data for Local Model (8B)
