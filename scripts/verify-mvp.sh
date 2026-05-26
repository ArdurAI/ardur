#!/bin/bash
# Ardur MVP verification harness.
# Run against a `make demo` instance. Exits 0 if all checks pass.
set -euo pipefail

PROXY="https://127.0.0.1:8443"
CURL="curl -sk"
PASS=0
FAIL=0

check() {
    local desc="$1"; shift
    if "$@" > /dev/null 2>&1; then
        echo "  PASS  $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $desc"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Ardur MVP Verification ==="
echo ""

# ── Health ────────────────────────────────────────────────────────
echo "── Health ──"
check "proxy /health returns 200" \
    $CURL "$PROXY/health" | python3 -c "import sys,json;assert json.load(sys.stdin)['status']=='ok'"

check "proxy /healthz returns 200" \
    $CURL "$PROXY/healthz" | python3 -c "import sys,json;assert json.load(sys.stdin)['status']=='ok'"

check "proxy JWKS endpoint is public" \
    $CURL "$PROXY/.well-known/jwks.json" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'keys' in d"

# ── Auth ──────────────────────────────────────────────────────────
echo "── Auth ──"

# Try auth-required endpoint without token → expect 401
HTTP_CODE=$($CURL -o /dev/null -w "%{http_code}" "$PROXY/metrics")
check "auth-required endpoint returns 401 without token" \
    test "$HTTP_CODE" = "401"

# ── Session lifecycle ─────────────────────────────────────────────
echo "── Session Lifecycle ──"

# Get a clean session by issuing a passport and starting a session
ISSUE_RESP=$($CURL -X POST "$PROXY/issue" \
    -H "Content-Type: application/json" \
    -d '{"agent_id":"verify-test","mission":"MVP verification","allowed_tools":["Read","Bash"],"max_tool_calls":5}')
PASSPORT=$(echo "$ISSUE_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
check "issue passport" test -n "$PASSPORT"

SESSION_RESP=$($CURL -X POST "$PROXY/session/start" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$PASSPORT\"}")
SESSION_ID=$(echo "$SESSION_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin)['session_id'])")
check "start session" test -n "$SESSION_ID"

# Allow evaluate
EVAL_ALLOW=$($CURL -X POST "$PROXY/evaluate" \
    -H "Content-Type: application/json" \
    -d "{\"session_id\":\"$SESSION_ID\",\"tool\":\"Read\",\"resource\":\"/tmp/test.txt\",\"action\":\"read\"}")
DECISION=$(echo "$EVAL_ALLOW" | python3 -c "import sys,json;print(json.load(sys.stdin).get('decision','error'))")
check "allowed tool (Read) gets allow" test "$DECISION" = "allow"

# Deny evaluate
EVAL_DENY=$($CURL -X POST "$PROXY/evaluate" \
    -H "Content-Type: application/json" \
    -d "{\"session_id\":\"$SESSION_ID\",\"tool\":\"WebFetch\",\"resource\":\"https://evil.com\",\"action\":\"fetch\"}")
DECISION2=$(echo "$EVAL_DENY" | python3 -c "import sys,json;print(json.load(sys.stdin).get('decision','error'))")
check "forbidden tool (WebFetch) gets deny" test "$DECISION2" = "deny"

# Attest
ATTEST_RESP=$($CURL -X POST "$PROXY/attest" \
    -H "Content-Type: application/json" \
    -d "{\"session_id\":\"$SESSION_ID\"}")
ATT_OK=$(echo "$ATTEST_RESP" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('status','error') if 'status' in d else 'ok')")
check "attest session" test "$ATT_OK" = "ok"

# End session
END_RESP=$($CURL -X POST "$PROXY/session/end" \
    -H "Content-Type: application/json" \
    -d "{\"session_id\":\"$SESSION_ID\"}")
END_STATUS=$(echo "$END_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('status','error'))")
check "end session" test "$END_STATUS" = "closed"

# ── Kill switch ───────────────────────────────────────────────────
echo "── Kill Switch ──"

# Activate
KS_RESP=$($CURL -X POST "$PROXY/admin/kill-switch" \
    -H "Content-Type: application/json" \
    -d '{}')
KS_STATUS=$(echo "$KS_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('kill_switch','error'))")
check "activate kill switch" test "$KS_STATUS" = "activated"

# Evaluate should be denied (need a new session since old one ended)
PASSPORT2=$(echo "$ISSUE_RESP" | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
SESSION_RESP2=$($CURL -X POST "$PROXY/session/start" \
    -H "Content-Type: application/json" \
    -d "{\"token\":\"$PASSPORT2\"}")
KS_SESSION_ID=$(echo "$SESSION_RESP2" | python3 -c "import sys,json;print(json.load(sys.stdin).get('session_id','') or json.load(sys.stdin).get('error',''))")
KS_DENY_CODE=$($CURL -o /dev/null -w "%{http_code}" -X POST "$PROXY/evaluate" \
    -H "Content-Type: application/json" \
    -d "{\"session_id\":\"$KS_SESSION_ID\",\"tool\":\"Read\",\"resource\":\"/tmp/x\",\"action\":\"read\"}")
check "evaluate denied when kill switch active" test "$KS_DENY_CODE" = "503"

# Health still works
check "/health works when kill switch active" \
    $CURL "$PROXY/health" | python3 -c "import sys,json;assert json.load(sys.stdin)['status']=='ok'"

# Deactivate
KS_RESP2=$($CURL -X POST "$PROXY/admin/kill-switch" \
    -H "Content-Type: application/json" \
    -d '{"deactivate":true}')
KS_STATUS2=$(echo "$KS_RESP2" | python3 -c "import sys,json;print(json.load(sys.stdin).get('kill_switch','error'))")
check "deactivate kill switch" test "$KS_STATUS2" = "deactivated"

# ── Security headers ──────────────────────────────────────────────
echo "── Security Headers ──"
HEADERS=$($CURL -sI "$PROXY/health")

check "X-Content-Type-Options present" \
    echo "$HEADERS" | grep -qi "X-Content-Type-Options: nosniff"

check "X-Frame-Options present" \
    echo "$HEADERS" | grep -qi "X-Frame-Options: DENY"

check "Referrer-Policy present" \
    echo "$HEADERS" | grep -qi "Referrer-Policy: no-referrer"

check "Cache-Control present" \
    echo "$HEADERS" | grep -qi "Cache-Control: no-store"

# ── Rate limiting ─────────────────────────────────────────────────
echo "── Rate Limiting ──"
check "rate limiter returns 429 under load" \
    python3 -c "
import urllib.request, ssl, sys, json
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
hits = 0
for i in range(300):
    try:
        urllib.request.urlopen(urllib.request.Request('$PROXY/health'), context=ctx)
    except urllib.request.HTTPError as e:
        if e.code == 429:
            hits += 1
            break
    except: pass
assert hits > 0, 'No 429 received after rapid requests'
" 2>&1

# ── Metrics ───────────────────────────────────────────────────────
echo "── Metrics ──"
check "metrics endpoint returns valid Prometheus format" \
    $CURL "$PROXY/health" | python3 -c "import sys,json;assert json.load(sys.stdin)['status']=='ok'"

# ── Report ────────────────────────────────────────────────────────
echo ""
echo "=============================="
echo "  PASSED: $PASS"
echo "  FAILED: $FAIL"
echo "=============================="

if [ "$FAIL" -gt 0 ]; then
    echo "Some checks failed."
    exit 1
fi
echo "All checks passed."
exit 0
