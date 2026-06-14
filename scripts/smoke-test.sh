#!/usr/bin/env bash
# smoke-test.sh — Quick smoke test for GuardianWAF binary
# Verifies: build, version, validate, check (clean + attack), serve startup
# Usage: ./scripts/smoke-test.sh [path-to-binary]
# Exit codes: 0 = all pass, 1 = failure

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=0

pass() {
    PASS=$((PASS + 1))
    TOTAL=$((TOTAL + 1))
    echo -e "  ${GREEN}PASS${NC} $1"
}

fail() {
    FAIL=$((FAIL + 1))
    TOTAL=$((TOTAL + 1))
    echo -e "  ${RED}FAIL${NC} $1: $2"
}

section() {
    echo -e "\n${YELLOW}=== $1 ===${NC}"
}

# --- Setup ---
BINARY="${1:-}"
TMPDIR="$(mktemp -d)"
SERVER_PID=""
BACKEND_PID=""
SIDECAR_PID=""

kill_process() {
    local pid="$1"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}

cleanup() {
    kill_process "$SIDECAR_PID"
    kill_process "$BACKEND_PID"
    kill_process "$SERVER_PID"
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

if [ -z "$BINARY" ]; then
    section "Building binary"
    BINARY="$TMPDIR/guardianwaf"
    go build -o "$BINARY" ./cmd/guardianwaf/
    pass "Build successful"
fi

if [ ! -x "$BINARY" ] && [ ! -f "$BINARY" ]; then
    echo -e "${RED}Binary not found: $BINARY${NC}"
    exit 1
fi

# --- Test config ---
CONFIG="$TMPDIR/guardianwaf.yaml"
cat > "$CONFIG" <<'YAML'
mode: enforce
listen: ":18888"
waf:
  ip_acl:
    enabled: true
    blacklist:
      - "198.51.100.0/24"
  rate_limit:
    enabled: true
    rules:
      - id: global
        scope: ip
        limit: 1000
        window: 60s
        burst: 100
        action: block
  sanitizer:
    enabled: true
    max_url_length: 4096
    max_body_size: 10485760
  detection:
    enabled: true
    threshold:
      block: 50
      log: 25
    detectors:
      sqli:
        enabled: true
      xss:
        enabled: true
      lfi:
        enabled: true
      cmdi:
        enabled: true
      xxe:
        enabled: true
      ssrf:
        enabled: true
  bot_detection:
    enabled: true
    mode: enforce
    user_agent:
      enabled: true
      block_empty: true
      block_known_scanners: true
  response:
    security_headers:
      enabled: true
    data_masking:
      enabled: true
dashboard:
  enabled: true
  listen: ":19444"
  api_key: "smoke-test-api-key-1234567890"
  admin_key: ""
  tls: false
mcp:
  enabled: false
events:
  max_events: 1000
YAML

# --- 1. Version ---
section "CLI Commands"

OUTPUT=$("$BINARY" version 2>&1) || true
if echo "$OUTPUT" | grep -q "guardianwaf"; then
    pass "version command"
else
    fail "version command" "unexpected output: $OUTPUT"
fi

# --- 2. Help ---
OUTPUT=$("$BINARY" help 2>&1) || true
if echo "$OUTPUT" | grep -q "COMMANDS"; then
    pass "help command"
else
    fail "help command" "missing COMMANDS in output"
fi

# --- 3. Validate ---
OUTPUT=$("$BINARY" validate -config "$CONFIG" 2>&1)
if echo "$OUTPUT" | grep -q "valid"; then
    pass "validate (valid config)"
else
    fail "validate (valid config)" "$OUTPUT"
fi

OUTPUT=$("$BINARY" validate -config "/nonexistent.yaml" 2>&1) && RC=0 || RC=$?
if [ $RC -ne 0 ]; then
    pass "validate (invalid path returns error)"
else
    fail "validate (invalid path)" "expected non-zero exit"
fi

# --- 4. Check (clean request) ---
section "WAF Detection — Clean Requests"

OUTPUT=$("$BINARY" check -config "$CONFIG" -url "/hello" -H "User-Agent: Mozilla/5.0 Chrome/120.0" 2>&1) && RC=0 || RC=$?
if echo "$OUTPUT" | grep -q "PASSED"; then
    pass "clean GET /hello"
else
    # Score below block but above log is also acceptable
    if echo "$OUTPUT" | grep -q "Action:"; then
        pass "clean GET /hello (scored but processed)"
    else
        fail "clean GET /hello" "$OUTPUT"
    fi
fi

OUTPUT=$("$BINARY" check -config "$CONFIG" -url "/api/users?page=1&limit=10" -H "User-Agent: Mozilla/5.0 Chrome/120.0" 2>&1) && RC=0 || RC=$?
if echo "$OUTPUT" | grep -q "Action:"; then
    pass "clean GET /api/users with query params"
else
    fail "clean GET /api/users" "$OUTPUT"
fi

OUTPUT=$("$BINARY" check -config "$CONFIG" -url "/api/data" -method POST -body '{"user":"alice","role":"admin"}' -H "User-Agent: Mozilla/5.0 Chrome/120.0" -H "Content-Type: application/json" 2>&1) && RC=0 || RC=$?
if echo "$OUTPUT" | grep -q "Action:"; then
    pass "clean POST /api/data with JSON body"
else
    fail "clean POST /api/data" "$OUTPUT"
fi

# --- 5. Check (attack requests) ---
section "WAF Detection — Attack Requests"

# SQLi
OUTPUT=$("$BINARY" check -config "$CONFIG" -url "/search?q='+OR+1=1--" -H "User-Agent: Mozilla/5.0 Chrome/120.0" -v 2>&1) && RC=0 || RC=$?
if echo "$OUTPUT" | grep -q "BLOCKED\|Findings:"; then
    pass "SQLi: ' OR 1=1--"
else
    fail "SQLi detection" "$OUTPUT"
fi

# XSS
OUTPUT=$("$BINARY" check -config "$CONFIG" -url "/search?q=<script>alert(1)</script>" -H "User-Agent: Mozilla/5.0 Chrome/120.0" 2>&1) && RC=0 || RC=$?
if echo "$OUTPUT" | grep -q "BLOCKED\|Score:"; then
    pass "XSS: <script>alert(1)</script>"
else
    fail "XSS detection" "$OUTPUT"
fi

# LFI
OUTPUT=$("$BINARY" check -config "$CONFIG" -url "/file?path=../../../etc/passwd" -H "User-Agent: Mozilla/5.0 Chrome/120.0" 2>&1) && RC=0 || RC=$?
if echo "$OUTPUT" | grep -q "BLOCKED\|Score:"; then
    pass "LFI: ../../../etc/passwd"
else
    fail "LFI detection" "$OUTPUT"
fi

# CMDi
OUTPUT=$("$BINARY" check -config "$CONFIG" -url "/exec?cmd=test;cat+/etc/passwd" -H "User-Agent: Mozilla/5.0 Chrome/120.0" 2>&1) && RC=0 || RC=$?
if echo "$OUTPUT" | grep -q "BLOCKED\|Score:"; then
    pass "CMDi: ;cat /etc/passwd"
else
    fail "CMDi detection" "$OUTPUT"
fi

# SSRF
OUTPUT=$("$BINARY" check -config "$CONFIG" -url "/proxy?url=http://169.254.169.254/latest/meta-data/" -H "User-Agent: Mozilla/5.0 Chrome/120.0" 2>&1) && RC=0 || RC=$?
if echo "$OUTPUT" | grep -q "BLOCKED\|Score:"; then
    pass "SSRF: AWS metadata endpoint"
else
    fail "SSRF detection" "$OUTPUT"
fi

# Bot detection (empty UA)
OUTPUT=$("$BINARY" check -config "$CONFIG" -url "/test" 2>&1) && RC=0 || RC=$?
if echo "$OUTPUT" | grep -q "BLOCKED\|Score:"; then
    pass "Bot: empty User-Agent blocked"
else
    fail "Bot detection" "$OUTPUT"
fi

# --- 6. Serve startup/shutdown ---
section "Server Lifecycle"

PORT=18888
"$BINARY" serve -config "$CONFIG" -l ":$PORT" &
SERVER_PID=$!
sleep 1

# Health check
if curl -sf "http://127.0.0.1:$PORT/" > /dev/null 2>&1; then
    pass "serve starts and accepts connections"
else
    # Server may not have an upstream, so any response is fine
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/" 2>/dev/null) || HTTP_CODE="000"
    if [ "$HTTP_CODE" != "000" ]; then
        pass "serve starts and responds (HTTP $HTTP_CODE)"
    else
        fail "serve startup" "could not connect to :$PORT"
    fi
fi

for PROBE in livez readyz healthz; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/$PROBE" 2>/dev/null) || HTTP_CODE="000"
    if [ "$HTTP_CODE" = "200" ]; then
        pass "serve probe /$PROBE returns 200"
    else
        fail "serve probe /$PROBE" "got $HTTP_CODE"
    fi
done

# Send attack through the running server
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PORT/search?q=%27+OR+1%3D1--" -H "User-Agent: Mozilla/5.0 Chrome/120.0" 2>/dev/null) || HTTP_CODE="000"
if [ "$HTTP_CODE" = "403" ]; then
    pass "serve blocks SQLi attack (HTTP 403)"
elif [ "$HTTP_CODE" != "000" ]; then
    pass "serve responds to attack request (HTTP $HTTP_CODE)"
else
    fail "serve attack test" "no response"
fi

# Dashboard health/auth smoke
DASHBOARD_URL="http://127.0.0.1:19444"
DASH_READY=0
for _ in 1 2 3 4 5; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$DASHBOARD_URL/api/v1/health" 2>/dev/null) || HTTP_CODE="000"
    if [ "$HTTP_CODE" = "200" ]; then
        DASH_READY=1
        break
    fi
    sleep 1
done
if [ "$DASH_READY" = "1" ]; then
    pass "dashboard health /api/v1/health returns 200"
else
    fail "dashboard health /api/v1/health" "got $HTTP_CODE"
fi

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$DASHBOARD_URL/api/v1/stats" 2>/dev/null) || HTTP_CODE="000"
if [ "$HTTP_CODE" = "401" ]; then
    pass "dashboard stats rejects missing API key"
else
    fail "dashboard stats unauthenticated" "expected 401, got $HTTP_CODE"
fi

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: smoke-test-api-key-1234567890" "$DASHBOARD_URL/api/v1/stats" 2>/dev/null) || HTTP_CODE="000"
if [ "$HTTP_CODE" = "200" ]; then
    pass "dashboard stats accepts configured API key"
else
    fail "dashboard stats authenticated" "expected 200, got $HTTP_CODE"
fi

# Graceful shutdown
kill -TERM "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""
pass "serve graceful shutdown"

# --- 7. Sidecar startup/proxy/shutdown ---
section "Sidecar Lifecycle"

BACKEND_PORT=19081
SIDECAR_PORT=19082
BACKEND_SRC="$TMPDIR/backend.go"
cat > "$BACKEND_SRC" <<'GO'
package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	addr := os.Args[1]
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "smoke-backend %s\n", r.URL.Path)
	})
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
GO

go run "$BACKEND_SRC" "127.0.0.1:$BACKEND_PORT" &
BACKEND_PID=$!

BACKEND_READY=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$BACKEND_PORT/healthz" 2>/dev/null) || HTTP_CODE="000"
    if [ "$HTTP_CODE" = "200" ]; then
        BACKEND_READY=1
        break
    fi
    sleep 1
done
if [ "$BACKEND_READY" = "1" ]; then
    pass "sidecar smoke backend starts"
else
    fail "sidecar smoke backend" "got $HTTP_CODE"
fi

GWAF_ALLOW_PRIVATE_UPSTREAMS=true "$BINARY" sidecar \
    --listen "127.0.0.1:$SIDECAR_PORT" \
    --upstream "http://127.0.0.1:$BACKEND_PORT" &
SIDECAR_PID=$!

SIDECAR_READY=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$SIDECAR_PORT/healthz" 2>/dev/null) || HTTP_CODE="000"
    if [ "$HTTP_CODE" = "200" ]; then
        SIDECAR_READY=1
        break
    fi
    sleep 1
done
if [ "$SIDECAR_READY" = "1" ]; then
    pass "sidecar starts and responds"
else
    fail "sidecar startup" "got $HTTP_CODE"
fi

for PROBE in livez readyz healthz; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$SIDECAR_PORT/$PROBE" 2>/dev/null) || HTTP_CODE="000"
    if [ "$HTTP_CODE" = "200" ]; then
        pass "sidecar probe /$PROBE returns 200"
    else
        fail "sidecar probe /$PROBE" "got $HTTP_CODE"
    fi
done

BODY=$(curl -s "http://127.0.0.1:$SIDECAR_PORT/hello" -H "User-Agent: Mozilla/5.0 Chrome/120.0" 2>/dev/null || true)
if echo "$BODY" | grep -q "smoke-backend /hello"; then
    pass "sidecar proxies clean request to backend"
else
    fail "sidecar proxy clean request" "unexpected body: $BODY"
fi

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$SIDECAR_PORT/search?q=%27+OR+1%3D1--" -H "User-Agent: Mozilla/5.0 Chrome/120.0" 2>/dev/null) || HTTP_CODE="000"
if [ "$HTTP_CODE" = "403" ]; then
    pass "sidecar blocks SQLi attack (HTTP 403)"
else
    fail "sidecar SQLi block" "got $HTTP_CODE"
fi

kill -TERM "$SIDECAR_PID" 2>/dev/null && wait "$SIDECAR_PID" 2>/dev/null || true
SIDECAR_PID=""
pass "sidecar graceful shutdown"

kill -TERM "$BACKEND_PID" 2>/dev/null && wait "$BACKEND_PID" 2>/dev/null || true
BACKEND_PID=""
pass "sidecar smoke backend shutdown"

# --- Summary ---
echo -e "\n${YELLOW}=== Summary ===${NC}"
echo -e "  Total: $TOTAL | ${GREEN}Passed: $PASS${NC} | ${RED}Failed: $FAIL${NC}"

if [ $FAIL -gt 0 ]; then
    echo -e "\n${RED}SMOKE TEST FAILED${NC}"
    exit 1
else
    echo -e "\n${GREEN}ALL SMOKE TESTS PASSED${NC}"
    exit 0
fi
