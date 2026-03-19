#!/bin/bash
# GuardianWAF Load Test & Attack Simulation Runner
# Usage: ./run-tests.sh [scenario]

set -e

TARGET="${TARGET:-http://localhost:8080}"
DURATION="${DURATION:-30s}"
WORKERS="${WORKERS:-10}"
RATE="${RATE:-50}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         GuardianWAF Load Test Suite                         ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo "Target: $TARGET"
    echo "Duration: $DURATION"
    echo ""
}

check_dependencies() {
    echo -e "${YELLOW}Checking dependencies...${NC}"

    if ! command -v go &> /dev/null; then
        echo -e "${RED}Error: Go is not installed${NC}"
        exit 1
    fi

    # Check if WAF is running
    if ! curl -s -o /dev/null -w "%{http_code}" "$TARGET/api/health" 2>/dev/null | grep -q "200\|404\|401"; then
        echo -e "${YELLOW}Warning: Target $TARGET may not be running${NC}"
        echo "Start GuardianWAF first: ./guardianwaf serve -config guardianwaf.yaml"
    fi

    echo -e "${GREEN}✓ Dependencies OK${NC}"
    echo ""
}

# Build the test tool
build_tool() {
    echo -e "${YELLOW}Building attack simulation tool...${NC}"
    go build -o attack-sim main.go
    echo -e "${GREEN}✓ Build complete${NC}"
    echo ""
}

# Scenario 1: Mixed traffic (legitimate + attacks)
run_mixed() {
    print_header
    echo -e "${BLUE}Scenario: Mixed Traffic (80% attacks, 20% legitimate)${NC}"
    echo ""
    ./attack-sim \
        -target "$TARGET" \
        -duration "$DURATION" \
        -workers "$WORKERS" \
        -rate "$RATE" \
        -mode mixed \
        -legit-ratio 5
}

# Scenario 2: Full attack mode
run_attacks_only() {
    print_header
    echo -e "${RED}Scenario: 100% Attack Traffic${NC}"
    echo ""
    ./attack-sim \
        -target "$TARGET" \
        -duration "$DURATION" \
        -workers "$WORKERS" \
        -rate "$RATE" \
        -mode attacks-only
}

# Scenario 3: Legitimate traffic only (baseline)
run_legitimate_only() {
    print_header
    echo -e "${GREEN}Scenario: 100% Legitimate Traffic (Baseline)${NC}"
    echo ""
    ./attack-sim \
        -target "$TARGET" \
        -duration "$DURATION" \
        -workers "$WORKERS" \
        -rate "$RATE" \
        -mode legitimate-only
}

# Scenario 4: Brute force attack simulation
run_brute_force() {
    print_header
    echo -e "${RED}Scenario: Brute Force Attack (single IP, multiple attempts)${NC}"
    echo ""
    ./attack-sim \
        -target "$TARGET" \
        -duration "$DURATION" \
        -workers 1 \
        -rate 20 \
        -mode brute-force
}

# Scenario 5: Credential stuffing simulation
run_credential_stuffing() {
    print_header
    echo -e "${RED}Scenario: Credential Stuffing (different emails, same password)${NC}"
    echo ""
    ./attack-sim \
        -target "$TARGET" \
        -duration "$DURATION" \
        -workers "$WORKERS" \
        -rate "$RATE" \
        -mode credential-stuffing
}

# Scenario 6: High load stress test
run_stress() {
    print_header
    echo -e "${YELLOW}Scenario: High Load Stress Test (10000+ RPS)${NC}"
    echo ""
    ./attack-sim \
        -target "$TARGET" \
        -duration "60s" \
        -workers 50 \
        -rate 200 \
        -mode legitimate-only
}

# Scenario 7: Quick test (5 seconds)
run_quick() {
    print_header
    echo -e "${BLUE}Scenario: Quick Test (5s, mixed traffic)${NC}"
    echo ""
    ./attack-sim \
        -target "$TARGET" \
        -duration "5s" \
        -workers 5 \
        -rate 100 \
        -mode mixed \
        -legit-ratio 3
}

# Run all scenarios
run_all() {
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Running all test scenarios...${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""

    DURATION="15s"
    WORKERS="5"
    RATE="50"

    echo -e "${YELLOW}[1/5] Legitimate Traffic Baseline${NC}"
    run_legitimate_only
    echo ""
    sleep 2

    echo -e "${YELLOW}[2/5] Mixed Traffic${NC}"
    run_mixed
    echo ""
    sleep 2

    echo -e "${YELLOW}[3/5] Attack Traffic${NC}"
    run_attacks_only
    echo ""
    sleep 2

    echo -e "${YELLOW}[4/5] Brute Force${NC}"
    run_brute_force
    echo ""
    sleep 2

    echo -e "${YELLOW}[5/5] Credential Stuffing${NC}"
    run_credential_stuffing

    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}All scenarios complete!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
}

# Single attack tests using guardianwaf check command
run_single_tests() {
    print_header
    echo -e "${BLUE}Testing individual payloads with guardianwaf check${NC}"
    echo ""

    WAF_CHECK="guardianwaf check -c ../../guardianwaf.yaml"

    # SQL Injection tests
    echo -e "${YELLOW}SQL Injection Tests:${NC}"
    for payload in "' OR '1'='1" "' UNION SELECT NULL--" "1; DROP TABLE users--"; do
        result=$($WAF_CHECK --url "/search?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")" 2>/dev/null || echo "Error")
        echo "  Payload: $payload"
        echo "  Result: $result"
        echo ""
    done

    # XSS tests
    echo -e "${YELLOW}XSS Tests:${NC}"
    for payload in "<script>alert(1)</script>" "<img src=x onerror=alert(1)>"; do
        result=$($WAF_CHECK --url "/search?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")" 2>/dev/null || echo "Error")
        echo "  Payload: $payload"
        echo "  Result: $result"
        echo ""
    done

    # Path traversal tests
    echo -e "${YELLOW}Path Traversal Tests:${NC}"
    for payload in "../../../etc/passwd" "....//....//etc/passwd"; do
        result=$($WAF_CHECK --url "/file?path=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")" 2>/dev/null || echo "Error")
        echo "  Payload: $payload"
        echo "  Result: $result"
        echo ""
    done
}

# Help
show_help() {
    echo "GuardianWAF Load Test & Attack Simulation Runner"
    echo ""
    echo "Usage: $0 [scenario]"
    echo ""
    echo "Scenarios:"
    echo "  mixed              Mixed traffic (80% attacks, 20% legitimate)"
    echo "  attacks-only       100% attack traffic"
    echo "  legitimate-only    100% legitimate traffic (baseline)"
    echo "  brute-force        Brute force attack simulation"
    echo "  credential-stuffing Credential stuffing attack simulation"
    echo "  stress             High load stress test (10000+ RPS)"
    echo "  quick              Quick 5-second test"
    echo "  all                Run all scenarios"
    echo "  single             Test individual payloads"
    echo "  help               Show this help"
    echo ""
    echo "Environment Variables:"
    echo "  TARGET      Target URL (default: http://localhost:8080)"
    echo "  DURATION    Test duration (default: 30s)"
    echo "  WORKERS     Number of workers (default: 10)"
    echo "  RATE        Requests per second per worker (default: 50)"
    echo ""
    echo "Examples:"
    echo "  TARGET=http://localhost:9000 ./run-tests.sh mixed"
    echo "  DURATION=60s WORKERS=20 ./run-tests.sh stress"
}

# Main
case "${1:-help}" in
    mixed)
        check_dependencies
        build_tool
        run_mixed
        ;;
    attacks-only)
        check_dependencies
        build_tool
        run_attacks_only
        ;;
    legitimate-only)
        check_dependencies
        build_tool
        run_legitimate_only
        ;;
    brute-force)
        check_dependencies
        build_tool
        run_brute_force
        ;;
    credential-stuffing)
        check_dependencies
        build_tool
        run_credential_stuffing
        ;;
    stress)
        check_dependencies
        build_tool
        run_stress
        ;;
    quick)
        check_dependencies
        build_tool
        run_quick
        ;;
    all)
        check_dependencies
        build_tool
        run_all
        ;;
    single)
        run_single_tests
        ;;
    help|*)
        show_help
        ;;
esac
