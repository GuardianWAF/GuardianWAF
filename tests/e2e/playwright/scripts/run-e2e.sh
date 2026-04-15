#!/bin/bash
# GuardianWAF E2E Test Runner
# Usage: ./scripts/run-e2e.sh [options]
#
# Options:
#   --headed    Run tests in headed mode (browser visible)
#   --debug     Run tests in debug mode
#   --browser   Specify browser (chromium, firefox, webkit, all)
#   --grep      Run only tests matching pattern
#   --list      List all tests without running
#
# Environment Variables:
#   E2E_BASE_URL    Base URL of GuardianWAF server (default: http://localhost:9443)
#   E2E_API_KEY     API key for authentication (default: test-api-key)
#   E2E_WORKERS     Number of parallel workers (default: 1)

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Defaults
HEADED=""
DEBUG=""
BROWSER="chromium"
GREP=""
LIST=""
WORKERS="${E2E_WORKERS:-1}"
BASE_URL="${E2E_BASE_URL:-http://localhost:9443}"
API_KEY="${E2E_API_KEY:-test-api-key}"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --headed)
            HEADED="--headed"
            shift
            ;;
        --debug)
            DEBUG="--debug"
            HEADED="--headed"
            shift
            ;;
        --browser)
            BROWSER="$2"
            shift 2
            ;;
        --grep)
            GREP="-g \"$2\""
            shift 2
            ;;
        --list)
            LIST="true"
            shift
            ;;
        --workers)
            WORKERS="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --headed      Run tests in headed mode"
            echo "  --debug       Run tests in debug mode"
            echo "  --browser     Browser: chromium, firefox, webkit, all (default: chromium)"
            echo "  --grep        Run only tests matching pattern"
            echo "  --list        List tests without running"
            echo "  --workers N    Number of parallel workers (default: 1)"
            echo ""
            echo "Environment:"
            echo "  E2E_BASE_URL  Server URL (default: http://localhost:9443)"
            echo "  E2E_API_KEY   API key (default: test-api-key)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check if playwright is installed
if ! npx playwright --version > /dev/null 2>&1; then
    echo -e "${YELLOW}Playwright not found. Installing...${NC}"
    npm install
    npx playwright install --with-deps chromium firefox webkit
fi

# Export for Playwright
export E2E_BASE_URL
export E2E_API_KEY

# Build playwright command
PW_CMD="npx playwright test"

if [ "$LIST" = "true" ]; then
    PW_CMD="$PW_CMD --list"
    eval $PW_CMD
    exit 0
fi

# Select project
case $BROWSER in
    chromium)
        PW_CMD="$PW_CMD --project=chromium"
        ;;
    firefox)
        PW_CMD="$PW_CMD --project=firefox"
        ;;
    webkit)
        PW_CMD="$PW_CMD --project=webkit"
        ;;
    all)
        # Run all browsers
        ;;
esac

# Add options
if [ -n "$HEADED" ]; then
    PW_CMD="$PW_CMD $HEADED"
fi
if [ -n "$DEBUG" ]; then
    PW_CMD="$PW_CMD $DEBUG"
fi
if [ -n "$GREP" ]; then
    PW_CMD="$PW_CMD $GREP"
fi

# Run with timeout
echo -e "${GREEN}Running E2E tests...${NC}"
echo "Base URL: $BASE_URL"
echo "Browser: $BROWSER"
echo "Workers: $WORKERS"
echo ""

TIMEOUT_SECONDS=600
timeout $TIMEOUT_SECONDS bash -c "$PW_CMD" || {
    EXIT_CODE=$?
    if [ $EXIT_CODE -eq 124 ]; then
        echo -e "${RED}Tests timed out after ${TIMEOUT_SECONDS}s${NC}"
    else
        echo -e "${RED}Tests failed with exit code $EXIT_CODE${NC}"
    fi
    exit $EXIT_CODE
}

echo -e "${GREEN}E2E tests completed${NC}"
