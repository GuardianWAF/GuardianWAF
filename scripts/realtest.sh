#!/bin/bash
# GuardianWAF Real E2E Test Script
# Usage: ./scripts/realtest.sh [waf_url] [dashboard_url]

WAF="${1:-http://localhost:8080}"
DASH="${2:-http://localhost:9443}"
API_KEY="test-api-key-2024"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
PASSED=0
FAILED=0
TOTAL=0

pass() { PASSED=$((PASSED+1)); TOTAL=$((TOTAL+1)); echo "  [PASS] $1"; }
fail() { FAILED=$((FAILED+1)); TOTAL=$((TOTAL+1)); echo "  [FAIL] $1 -- $2"; }

echo ""
echo "=========================================="
echo " GuardianWAF Real E2E Tests"
echo "=========================================="
echo " WAF:       $WAF"
echo " Dashboard: $DASH"
echo "=========================================="

# --- Health & Metrics ---
echo ""
echo "[1/8] Health & Metrics Endpoints"

code=$(curl -s -o /dev/null -w '%{http_code}' "$WAF/healthz")
[ "$code" = "200" ] && pass "GET /healthz ($code)" || fail "GET /healthz" "expected 200, got $code"

body=$(curl -s "$WAF/healthz")
echo "$body" | grep -q '"status":"ok"' && pass "Healthz JSON body" || fail "Healthz JSON body" "missing status:ok"

code=$(curl -s -o /dev/null -w '%{http_code}' "$WAF/metrics")
[ "$code" = "200" ] && pass "GET /metrics ($code)" || fail "GET /metrics" "expected 200, got $code"

body=$(curl -s "$WAF/metrics")
echo "$body" | grep -q 'guardianwaf_requests_total' && pass "Metrics has requests_total" || fail "Metrics" "missing requests_total"
echo "$body" | grep -q 'guardianwaf_requests_blocked_total' && pass "Metrics has blocked_total" || fail "Metrics" "missing blocked_total"

# --- Clean Requests ---
echo ""
echo "[2/8] Clean Requests (should PASS)"

code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$WAF/")
[ "$code" = "200" ] && pass "GET / ($code)" || fail "GET /" "expected 200, got $code"

body=$(curl -s -A "$UA" "$WAF/")
echo "$body" | grep -q "Hello from backend" && pass "Backend response body" || fail "Backend response" "missing Hello"

code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" -X POST -H 'Content-Type: application/json' -d '{"name":"test"}' "$WAF/api/data")
[ "$code" = "200" ] && pass "POST with JSON body ($code)" || fail "POST JSON" "expected 200, got $code"

# --- SQL Injection ---
echo ""
echo "[3/8] SQL Injection Detection (should BLOCK)"

code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$WAF/?id=1+UNION+SELECT+username,password+FROM+users")
[ "$code" = "403" ] && pass "SQLi: UNION SELECT ($code)" || fail "SQLi: UNION SELECT" "expected 403, got $code"

code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$WAF/?id=1'+OR+'1'='1")
[ "$code" = "403" ] && pass "SQLi: OR 1=1 ($code)" || fail "SQLi: OR 1=1" "expected 403, got $code"

code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" --data-urlencode "q=1;DROP TABLE users--" "$WAF/search")
[ "$code" = "403" ] && pass "SQLi: DROP TABLE ($code)" || fail "SQLi: DROP TABLE" "expected 403, got $code"

# --- XSS ---
echo ""
echo "[4/8] XSS Detection (should BLOCK)"

code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" --data-urlencode 'q=<script>alert(1)</script>' "$WAF/search")
[ "$code" = "403" ] && pass "XSS: script tag ($code)" || fail "XSS: script tag" "expected 403, got $code"

code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" --data-urlencode 'q=<img src=x onerror=alert(1)>' "$WAF/search")
[ "$code" = "403" ] && pass "XSS: img onerror ($code)" || fail "XSS: img onerror" "expected 403, got $code"

code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" --data-urlencode 'q=<svg onload=alert(1)>' "$WAF/search")
[ "$code" = "403" ] && pass "XSS: svg onload ($code)" || fail "XSS: svg onload" "expected 403, got $code"

# --- Path Traversal (LFI) ---
echo ""
echo "[5/8] Path Traversal Detection (should BLOCK)"

code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$WAF/..%2F..%2F..%2Fetc%2Fpasswd")
[ "$code" = "403" ] && pass "LFI: /etc/passwd ($code)" || fail "LFI: /etc/passwd" "expected 403, got $code"

code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" --data-urlencode 'file=../../../../etc/shadow' "$WAF/read")
[ "$code" = "403" ] && pass "LFI: traversal in param ($code)" || fail "LFI: traversal" "expected 403, got $code"

# --- Command Injection ---
echo ""
echo "[6/8] Command Injection Detection (should BLOCK)"

code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" --data-urlencode 'cmd=;cat /etc/passwd' "$WAF/exec")
[ "$code" = "403" ] && pass "CMDi: semicolon ($code)" || fail "CMDi: semicolon" "expected 403, got $code"

code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" --data-urlencode 'cmd=|whoami' "$WAF/exec")
[ "$code" = "403" ] && pass "CMDi: pipe ($code)" || fail "CMDi: pipe" "expected 403, got $code"

# --- SSRF ---
echo ""
echo "[7/8] SSRF Detection (should BLOCK)"

code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" --data-urlencode 'url=http://169.254.169.254/latest/meta-data/' "$WAF/fetch")
[ "$code" = "403" ] && pass "SSRF: AWS metadata ($code)" || fail "SSRF: AWS metadata" "expected 403, got $code"

code=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" --data-urlencode 'url=http://127.0.0.1:22' "$WAF/fetch")
[ "$code" = "403" ] && pass "SSRF: localhost ($code)" || fail "SSRF: localhost" "expected 403, got $code"

# --- Dashboard API ---
echo ""
echo "[8/8] Dashboard API"

code=$(curl -s -o /dev/null -w '%{http_code}' -H "X-API-Key: $API_KEY" "$DASH/api/v1/stats")
[ "$code" = "200" ] && pass "Dashboard stats ($code)" || fail "Dashboard stats" "expected 200, got $code"

body=$(curl -s -H "X-API-Key: $API_KEY" "$DASH/api/v1/stats")
echo "$body" | grep -q "total_requests" && pass "Stats has total_requests" || fail "Stats body" "missing total_requests"

code=$(curl -s -o /dev/null -w '%{http_code}' -H "X-API-Key: $API_KEY" "$DASH/api/v1/events")
[ "$code" = "200" ] && pass "Dashboard events ($code)" || fail "Dashboard events" "expected 200, got $code"

code=$(curl -s -o /dev/null -w '%{http_code}' -H "X-API-Key: $API_KEY" "$DASH/api/v1/config")
[ "$code" = "200" ] && pass "Dashboard config ($code)" || fail "Dashboard config" "expected 200, got $code"

code=$(curl -s -o /dev/null -w '%{http_code}' "$DASH/api/v1/stats")
[ "$code" = "401" ] && pass "Dashboard unauthorized ($code)" || fail "Dashboard unauth" "expected 401, got $code"

# --- Summary ---
echo ""
echo "=========================================="
echo " RESULTS: $PASSED passed, $FAILED failed (total: $TOTAL)"
echo "=========================================="

if [ $FAILED -gt 0 ]; then
    exit 1
fi
echo " ALL TESTS PASSED!"
exit 0
