#!/usr/bin/env bash
# Ardur MVP verification harness. Run against a `make demo` instance.
set -euo pipefail

PROXY_URL="${ARDUR_PROXY_URL:-https://127.0.0.1:${ARDUR_PROXY_PORT:-8443}}"
PASS=0
FAIL=0
AUTH_HEADER_FILE=""
REQUEST_BODY_FILE=""

cleanup() {
    rm -f "$AUTH_HEADER_FILE" "$REQUEST_BODY_FILE"
}
trap cleanup EXIT

report() {
    echo ""
    echo "=============================="
    echo "  PASSED: $PASS"
    echo "  FAILED: $FAIL"
    echo "=============================="
}

check() {
    local description="$1"
    shift

    if "$@" > /dev/null 2>&1; then
        echo "  PASS  $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $description"
        FAIL=$((FAIL + 1))
    fi
}

require_check() {
    check "$@"
    if (( FAIL > 0 )); then
        report
        exit 1
    fi
}

curl_public() {
    curl --insecure --silent --show-error --fail "$@"
}

curl_status() {
    curl --insecure --silent --show-error --output /dev/null --write-out '%{http_code}' "$@"
}

curl_auth() {
    curl --insecure --silent --show-error --fail --header "@$AUTH_HEADER_FILE" "$@"
}

post_json() {
    local path="$1"
    local payload="$2"

    printf '%s' "$payload" > "$REQUEST_BODY_FILE"
    curl_auth \
        --request POST \
        --header 'Content-Type: application/json' \
        --data-binary "@$REQUEST_BODY_FILE" \
        "$PROXY_URL$path"
}

assert_json_value() {
    local field_name="$1"
    local expected="$2"

    python3 -c '
import json
import sys

payload = json.load(sys.stdin)
assert payload.get(sys.argv[1]) == sys.argv[2], payload
' "$field_name" "$expected"
}

extract_json_string() {
    local field_name="$1"

    python3 -c '
import json
import sys

value = json.load(sys.stdin).get(sys.argv[1])
assert isinstance(value, str) and value, value
print(value, end="")
' "$field_name"
}

json_session_payload() {
    python3 -c '
import json
import sys

print(json.dumps({"session_id": sys.stdin.read()}), end="")
'
}

json_start_payload() {
    python3 -c '
import json
import sys

print(json.dumps({"token": sys.stdin.read()}), end="")
'
}

json_evaluate_payload() {
    local tool_name="$1"

    python3 -c '
import json
import sys

print(json.dumps({
    "session_id": sys.stdin.read(),
    "tool_name": sys.argv[1],
    "arguments": {"path": "/tmp/ardur-mvp-verifier.txt"},
}), end="")
' "$tool_name"
}

check_decision() {
    local expected="$1"
    local response="$2"

    printf '%s' "$response" | python3 -c '
import json
import sys

assert json.load(sys.stdin).get("decision") == sys.argv[1]
' "$expected"
}

discover_api_token() {
    if [[ -n "${ARDUR_API_TOKEN:-}" ]]; then
        printf '%s' "$ARDUR_API_TOKEN"
        return
    fi

    if command -v docker > /dev/null 2>&1; then
        docker compose exec -T proxy sh -c 'printf %s "$VIBAP_API_TOKEN"' 2>/dev/null || true
    fi
}

check_health() {
    curl_public "$PROXY_URL/health" | assert_json_value status ok
}

check_healthz() {
    curl_public "$PROXY_URL/healthz" | assert_json_value status ok
}

check_jwks() {
    curl_public "$PROXY_URL/.well-known/jwks.json" | python3 -c '
import json
import sys

payload = json.load(sys.stdin)
assert isinstance(payload.get("keys"), list) and payload["keys"], payload
'
}

check_metrics_requires_auth() {
    test "$(curl_status "$PROXY_URL/metrics")" = "401"
}

check_metrics() {
    local metrics
    metrics="$(curl_auth "$PROXY_URL/metrics")"
    [[ "$metrics" == *"ardur_"* ]]
}

echo "=== Ardur MVP Verification ==="
echo ""

echo "-- Public endpoints --"
require_check "proxy /health returns status=ok" check_health
require_check "proxy /healthz returns status=ok" check_healthz
require_check "proxy JWKS endpoint is public" check_jwks

API_TOKEN="$(discover_api_token)"
if [[ -z "$API_TOKEN" || "$API_TOKEN" == *$'\n'* || "$API_TOKEN" == *$'\r'* ]]; then
    echo "  FAIL  configured bearer token is available"
    echo "Set ARDUR_API_TOKEN before starting the local demo, then rerun this verifier."
    report
    exit 1
fi

umask 077
AUTH_HEADER_FILE="$(mktemp "${TMPDIR:-/tmp}/ardur-verify-auth.XXXXXX")"
REQUEST_BODY_FILE="$(mktemp "${TMPDIR:-/tmp}/ardur-verify-body.XXXXXX")"
printf 'Authorization: Bearer %s\n' "$API_TOKEN" > "$AUTH_HEADER_FILE"

echo "-- Auth and lifecycle --"
require_check "auth-required metrics returns 401 without a token" check_metrics_requires_auth

MISSION_PAYLOAD='{"mission":{"agent_id":"mvp-verifier","mission":"verify the local governance proxy","allowed_tools":["read_file","delete_file"],"forbidden_tools":["delete_file"],"max_tool_calls":4}}'
ISSUE_RESPONSE="$(post_json /issue "$MISSION_PAYLOAD")"
PASSPORT="$(printf '%s' "$ISSUE_RESPONSE" | extract_json_string token)"
require_check "issue a mission passport" test -n "$PASSPORT"

START_PAYLOAD="$(printf '%s' "$PASSPORT" | json_start_payload)"
START_RESPONSE="$(post_json /session/start "$START_PAYLOAD")"
SESSION_ID="$(printf '%s' "$START_RESPONSE" | extract_json_string session_id)"
require_check "start a governed session" test -n "$SESSION_ID"

PERMIT_PAYLOAD="$(printf '%s' "$SESSION_ID" | json_evaluate_payload read_file)"
PERMIT_RESPONSE="$(post_json /evaluate "$PERMIT_PAYLOAD")"
require_check "allowed tool returns PERMIT" check_decision PERMIT "$PERMIT_RESPONSE"

DENY_PAYLOAD="$(printf '%s' "$SESSION_ID" | json_evaluate_payload delete_file)"
DENY_RESPONSE="$(post_json /evaluate "$DENY_PAYLOAD")"
require_check "forbidden tool returns DENY" check_decision DENY "$DENY_RESPONSE"

SESSION_PAYLOAD="$(printf '%s' "$SESSION_ID" | json_session_payload)"
ATTEST_RESPONSE="$(post_json /attest "$SESSION_PAYLOAD")"
ATTESTATION_TOKEN="$(printf '%s' "$ATTEST_RESPONSE" | extract_json_string token)"
require_check "issue a signed attestation" test -n "$ATTESTATION_TOKEN"

END_RESPONSE="$(post_json /session/end "$SESSION_PAYLOAD")"
END_ATTESTATION_TOKEN="$(printf '%s' "$END_RESPONSE" | extract_json_string attestation_token)"
require_check "end the governed session" test -n "$END_ATTESTATION_TOKEN"
require_check "authenticated metrics return Prometheus output" check_metrics

report
if (( FAIL > 0 )); then
    exit 1
fi

echo "All checks passed."
