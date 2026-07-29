.PHONY: build test test-packages lint bench fuzz clean run docker-build smoke docker-test backup-restore-smoke ui ui-dev dev help fmt fmt-check tidy e2e e2e-full e2e-full-all e2e-headed e2e-list

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
	./scripts/build-dashboard.sh

# Dev mode for dashboard (hot reload on :5173, proxies API to :9443)
ui-dev:
	cd internal/dashboard/ui && npm run dev

# Dev build — Go only, skips dashboard rebuild (use ui-dev for frontend changes)
dev:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/guardianwaf

test:
	go test -race -count=1 ./...

# Run Go tests one package at a time with a per-package timeout to isolate slow
# or hanging packages. Override with GO_TEST_PACKAGE_TIMEOUT=300s and/or
# GO_TEST_ARGS='-count=1 -run TestName'. Optional package args can be passed as
# PACKAGES='./internal/config ./cmd/guardianwaf'.
test-packages:
	./scripts/go-test-packages.sh $(PACKAGES)

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
	go test -race -coverprofile=coverage.txt -covermode=atomic $(shell go list ./... | grep -v '/examples/' | grep -v '/scripts/attack-simulation')
	go tool cover -html=coverage.txt -o coverage.html

vet:
	go vet ./...

smoke: build
	@bash scripts/smoke-test.sh ./$(BINARY)

docker-test:
	docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test-runner
	@docker compose -f docker-compose.test.yml down -v

backup-restore-smoke:
	./scripts/backup-restore-smoke.sh

fmt:
	gofmt -s -w .

# CI gate: verify formatting without writing. Exits non-zero if any Go file
# would be changed by `gofmt -s`. Used by .github/workflows/ci.yml.
fmt-check:
	@out=$$(gofmt -s -l .); \
	if [ -n "$$out" ]; then \
		echo "::error::gofmt check failed — the following files need reformatting (run 'make fmt'):"; \
		echo "$$out"; \
		exit 1; \
	fi
	@echo "gofmt check passed."

# Regenerate DeepCopy methods for config structs.
# NOTE: tools/deepcopy/main.go is currently broken with Go 1.26+ (go/parser
# directory restriction). Until fixed, add DeepCopy fields by hand following
# the pattern in internal/config/deepcopy_generated.go.
.PHONY: generate-deepcopy
generate-deepcopy:
	@echo "WARNING: deepcopy tool is broken with Go 1.26 — see internal/config/deepcopy_generated.go header"
	cd tools/deepcopy && go run main.go ../../internal/config/config.go > ../../internal/config/deepcopy_generated.go
	go fmt ./internal/config/

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

e2e-full:
	./scripts/full-e2e.sh

e2e-full-all:
	E2E_PROJECTS=chromium,firefox,webkit E2E_PLAYWRIGHT_DOCKER=true ./scripts/full-e2e.sh

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
	@echo "  dev          Go-only build (skips dashboard rebuild)"
	@echo "  test         Run all tests with race detector"
	@echo "  test-packages Run Go tests package-by-package with per-package timeout"
	@echo "  lint         Run golangci-lint"
	@echo "  bench        Run benchmarks with memory stats"
	@echo "  fuzz         Run fuzz tests (30s each)"
	@echo "  e2e          Run Playwright E2E tests (requires running server)"
	@echo "  e2e-full     Build local runtime and run the complete Chromium E2E suite"
	@echo "  e2e-full-all Build local runtime and run Chromium, Firefox, and WebKit E2E suites"
	@echo "  e2e-headed   Run E2E tests in headed mode"
	@echo "  e2e-list     List all E2E tests"
	@echo "  cover        Generate coverage report (HTML)"
	@echo "  vet          Run go vet"
	@echo "  fmt          Format code with gofmt -s"
	@echo "  fmt-check    Verify gofmt (no write) — used by CI"
	@echo "  tidy         Run go mod tidy"
	@echo "  run          Build and run (serve mode)"
	@echo "  smoke        Build and run smoke tests"
	@echo "  clean        Remove binaries and coverage files"
	@echo "  docker-build Build Docker image"
	@echo "  docker-test  Run integration tests via Docker Compose"
	@echo "  backup-restore-smoke Verify snapshot integrity, tamper rejection, restore, and RTO"
