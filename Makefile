.PHONY: build test lint bench fuzz clean run docker-build

BINARY=guardianwaf
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE?=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/guardianwaf

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
