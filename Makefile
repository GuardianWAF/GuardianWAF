.PHONY: build test lint bench fuzz clean run docker-build smoke docker-test ui ui-dev help fmt tidy e2e e2e-headed e2e-list

BINARY=guardianwaf
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE?=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# Build dashboard UI then Go binary
build: ui
	go build $(LDFLAGS) -o $(BINARY) ./cmd/guardianwaf

# Build React dashboard
ui:
	cd internal/dashboard/ui && npm install --no-audit --no-fund && npm run build
	rm -rf internal/dashboard/dist
	cp -r internal/dashboard/ui/dist internal/dashboard/dist

# Dev mode for dashboard (hot reload on :5173, proxies API to :9443)
ui-dev:
	cd internal/dashboard/ui && npm run dev

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

bench:
	go test -bench=. -benchmem -run=^$$ ./...

fuzz:
	@echo "Running fuzz tests for 30 seconds each..."
	go test -fuzz=Fuzz -fuzztime=30s ./internal/config/
	go test -fuzz=Fuzz -fuzztime=30s ./internal/layers/sanitizer/
	go test -fuzz=Fuzz -fuzztime=30s ./internal/layers/detection/sqli/
	go test -fuzz=Fuzz -fuzztime=30s ./internal/layers/detection/xss/

clean:
	rm -f $(BINARY)
	rm -rf dist/
	rm -rf internal/dashboard/dist
	rm -f coverage.txt coverage.html

run: build
	./$(BINARY) serve

docker-build:
	docker build -t guardianwaf:$(VERSION) .

cover:
	go test -race -coverprofile=coverage.txt -covermode=atomic ./...
	go tool cover -html=coverage.txt -o coverage.html

vet:
	go vet ./...

smoke: build
	@bash scripts/smoke-test.sh ./$(BINARY)

docker-test:
	docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test-runner
	@docker compose -f docker-compose.test.yml down -v

fmt:
	gofmt -s -w .

tidy:
	go mod tidy

# E2E tests (requires GuardianWAF server running on E2E_BASE_URL)
E2E_BASE_URL ?= http://localhost:9443
E2E_API_KEY ?= test-api-key

e2e:
	@echo "Running E2E tests against $(E2E_BASE_URL)..."
	cd tests/e2e/playwright && npm install --silent 2>/dev/null; \
	E2E_BASE_URL=$(E2E_BASE_URL) E2E_API_KEY=$(E2E_API_KEY) \
	npx playwright test --project=chromium

e2e-headed:
	@echo "Running E2E tests (headed) against $(E2E_BASE_URL)..."
	cd tests/e2e/playwright && npm install --silent 2>/dev/null; \
	E2E_BASE_URL=$(E2E_BASE_URL) E2E_API_KEY=$(E2E_API_KEY) \
	npx playwright test --project=chromium --headed

e2e-list:
	@echo "Available E2E tests:"
	cd tests/e2e/playwright && npx playwright test --list 2>/dev/null | head -100

e2e-all:
	@echo "Running E2E tests (all browsers) against $(E2E_BASE_URL)..."
	cd tests/e2e/playwright && npm install --silent 2>/dev/null; \
	E2E_BASE_URL=$(E2E_BASE_URL) E2E_API_KEY=$(E2E_API_KEY) \
	npx playwright test

help:
	@echo "GuardianWAF build targets:"
	@echo "  build        Build dashboard UI + Go binary"
	@echo "  ui           Build React dashboard"
	@echo "  ui-dev       Dashboard dev mode (hot reload :5173)"
	@echo "  test         Run all tests with race detector"
	@echo "  lint         Run golangci-lint"
	@echo "  bench        Run benchmarks with memory stats"
	@echo "  fuzz         Run fuzz tests (30s each)"
	@echo "  e2e          Run Playwright E2E tests (requires running server)"
	@echo "  e2e-headed   Run E2E tests in headed mode"
	@echo "  e2e-list     List all E2E tests"
	@echo "  cover        Generate coverage report (HTML)"
	@echo "  vet          Run go vet"
	@echo "  fmt          Format code with gofmt -s"
	@echo "  tidy         Run go mod tidy"
	@echo "  run          Build and run (serve mode)"
	@echo "  smoke        Build and run smoke tests"
	@echo "  clean        Remove binaries and coverage files"
	@echo "  docker-build Build Docker image"
	@echo "  docker-test  Run integration tests via Docker Compose"
