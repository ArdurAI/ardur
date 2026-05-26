========================================================================
ARDUR PHASE 2 — ADVANCED ADVERSARIAL RESULTS
========================================================================
Tests run: 22  |  PASS: 22  |  FAIL: 0
Duration:  0s

┌─ Approval Policy  (2/2 passed)
│  [PASS] approval-no-operator: operator_id required but not supplied
│  [PASS] approval-fatigue: approval fatigue threshold exceeded

┌─ Delegation  (1/1 passed)
│  [PASS] delegation-tool-escalation: child uses tool not in parent scope

┌─ Memory Governance  (2/2 passed)
│  [PASS] memory-fix8-write: FIX-8: actor_private_key_pem rejected on memory write
│  [PASS] memory-fix8-read: FIX-8: verifier_public_key_pem rejected on memory read

┌─ Token Replay  (1/1 passed)
│  [PASS] token-replay-jti: JTI replay on session start rejected

┌─ Kill Switch  (2/2 passed)
│  [PASS] kill-switch-evaluate: kill switch blocks /evaluate with 503
│  [PASS] kill-switch-session: kill switch blocks /session/start with 503

┌─ Per-Class Budget  (2/2 passed)
│  [PASS] per-class-budget: per-class budget exhausted for internal_write
│  [PASS] side-effect-class: side_effect_class not in allowed list rejected

┌─ CWD Confinement  (2/2 passed)
│  [PASS] cwd-absolute-escape: absolute path outside CWD rejected
│  [PASS] cwd-path-traversal: path traversal escape from CWD rejected

┌─ Policy Backends  (1/1 passed)
│  [PASS] forbid-rules-block: ForbidRules backend blocks targeted tool

┌─ Tool Scope  (1/1 passed)
│  [PASS] forbidden-tool-deny: forbidden tool directly denied

┌─ Resource Scope  (1/1 passed)
│  [PASS] resource-scope-violation: write outside resource_scope denied

┌─ Budget  (1/1 passed)
│  [PASS] budget-exhaustion: main budget exhausted after max_tool_calls

┌─ Session Lifecycle  (2/2 passed)
│  [PASS] ended-session-rejects: ended session rejects evaluate
│  [PASS] multiple-sessions: multiple independent sessions coexist

┌─ Token Validation  (2/2 passed)
│  [PASS] invalid-token-rejected: invalid JWT rejected on session start
│  [PASS] nonexistent-session: evaluate with fake session_id rejected

┌─ Input Sanitization  (1/1 passed)
│  [PASS] unicode-confusable: unicode confusable path handled correctly

┌─ Infrastructure  (1/1 passed)
│  [PASS] health-endpoint: health endpoint returns ok

VERDICT: All enforcement points operating correctly.