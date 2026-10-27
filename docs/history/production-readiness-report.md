# GuardianWAF Production-Readiness Evidence Report

Date: 2026-07-06  
Branch verified: `main`  
Verifier environment: local Linux workspace at `/home/ersinkoc/Codebox/GuardianWAF`  
Go toolchain: `go1.26.4` observed during the verification session

## Executive summary

The current local `main` branch passed every verification check that was runnable in this environment. No reproducible issues remain from the executed checks.

This report does **not** claim an impossible mathematical guarantee that no defect can exist in any environment. It records the evidence gathered, the fixes made, and the known checks that could not be executed because required tools are not installed here.

## Git state

At the time this report was prepared:

```text
On branch main
Your branch is ahead of 'origin/main' by 8 commits.
nothing to commit, working tree clean
```

Recent relevant commits included in the verified local `main`:

```text
63d1552 fix(deploy): pin GuardianWAF deployment image tags
33b8254 fix(events): log recovered event consumer panics
1a2b241 test(dashboard): remove SSE hook act warning
0eed041 fix(hardening): library cleanup loop, MCP SSE writer model, AI HTTPS, tenant allow-list
5de3e4f fix(mcp): exempt SSE stream from server WriteTimeout
b643157 fix(deploy): CI ordering, real healthcheck, removed-layer config, doc drift
fbc4ac8 fix(reliability): concurrency, leak, and robustness hardening
b76ce57 fix(security): close cross-tenant disclosure, admin bypass, tenant key DoS, JWT panic
```

## Issues found and fixed in the final readiness pass

### 1. Dashboard SSE hook test emitted a React `act(...)` warning

- Commit: `1a2b241 test(dashboard): remove SSE hook act warning`
- File: `internal/dashboard/ui/src/hooks/use-sse.test.ts`
- Impact: test reliability / signal quality
- Resolution:
  - Wrapped mocked `EventSource` callbacks that update React state in `act(...)`.
  - Replaced loose mock `any` plumbing with a typed `MockEventSource`.
- Verification:
  - Targeted SSE hook test passed.
  - Full dashboard Vitest suite passed.
  - Dashboard lint passed.

### 2. Event consumer panic recovery was silent

- Commit: `33b8254 fix(events): log recovered event consumer panics`
- Files:
  - `guardianwaf.go`
  - `cmd/guardianwaf/event_consumers.go`
- Impact: production observability gap
- Resolution:
  - Replaced silent `recover()` discard paths with structured `slog` error logging.
  - Runtime behavior remains fail-safe: background goroutine panics are still recovered.
- Verification:
  - Go build passed.
  - Go vet passed.
  - Root and CLI tests passed.

### 3. Deployment manifests used mutable GuardianWAF `:latest` image tags

- Commit: `63d1552 fix(deploy): pin GuardianWAF deployment image tags`
- Files:
  - `contrib/k8s/deployment.yaml`
  - `contrib/k8s/helm/values.yaml`
  - `docker-compose.yml`
  - `examples/kubernetes/deployment.yaml`
  - `examples/kubernetes/sidecar-deployment.yaml`
  - `examples/sidecar/docker-compose.yml`
- Impact: production reproducibility and rollback risk
- Resolution:
  - Replaced GuardianWAF `:latest` tags in deployment artefacts with `0.3.0`.
  - Helm `image.tag` now defaults to `Chart.appVersion` when empty.
  - Added guidance to pin semver tags or digests.
- Verification:
  - Grep confirmed no GuardianWAF `:latest` deployment image remains under `contrib/k8s`, `examples`, or root `docker-compose.yml`.
  - YAML parse checks for non-Helm-template YAML passed.

## Verification evidence

### Go build

Command:

```bash
go build ./...
```

Result: passed with exit code `0`.

### Go vet

Command:

```bash
go vet ./...
```

Result: passed with exit code `0`.

### Go tests

The aggregate `go test -count=1 -timeout=10m ./...` command exceeded the local tool wrapper timeout, so packages were tested in groups. All package groups passed.

Representative package-group results:

```text
ok   github.com/guardianwaf/guardianwaf
ok   github.com/guardianwaf/guardianwaf/cmd/guardianwaf
ok   github.com/guardianwaf/guardianwaf/internal/ai
ok   github.com/guardianwaf/guardianwaf/internal/alerting
ok   github.com/guardianwaf/guardianwaf/internal/compliance
ok   github.com/guardianwaf/guardianwaf/internal/config
ok   github.com/guardianwaf/guardianwaf/internal/dashboard
ok   github.com/guardianwaf/guardianwaf/internal/docker
ok   github.com/guardianwaf/guardianwaf/internal/engine
ok   github.com/guardianwaf/guardianwaf/internal/events
ok   github.com/guardianwaf/guardianwaf/internal/geoip
ok   github.com/guardianwaf/guardianwaf/internal/layers/apisecurity
ok   github.com/guardianwaf/guardianwaf/internal/layers/apivalidation
ok   github.com/guardianwaf/guardianwaf/internal/layers/ato
ok   github.com/guardianwaf/guardianwaf/internal/layers/botdetect
ok   github.com/guardianwaf/guardianwaf/internal/layers/botdetect/challenge
ok   github.com/guardianwaf/guardianwaf/internal/layers/botdetect/fingerprint
ok   github.com/guardianwaf/guardianwaf/internal/layers/challenge
ok   github.com/guardianwaf/guardianwaf/internal/layers/clientside
ok   github.com/guardianwaf/guardianwaf/internal/layers/cors
ok   github.com/guardianwaf/guardianwaf/internal/layers/crs
ok   github.com/guardianwaf/guardianwaf/internal/layers/detection
ok   github.com/guardianwaf/guardianwaf/internal/layers/detection/cmdi
ok   github.com/guardianwaf/guardianwaf/internal/layers/detection/lfi
ok   github.com/guardianwaf/guardianwaf/internal/layers/detection/nosqli
ok   github.com/guardianwaf/guardianwaf/internal/layers/detection/sqli
ok   github.com/guardianwaf/guardianwaf/internal/layers/detection/ssrf
ok   github.com/guardianwaf/guardianwaf/internal/layers/detection/ssti
ok   github.com/guardianwaf/guardianwaf/internal/layers/detection/xss
ok   github.com/guardianwaf/guardianwaf/internal/layers/detection/xxe
ok   github.com/guardianwaf/guardianwaf/internal/layers/dlp
ok   github.com/guardianwaf/guardianwaf/internal/layers/ipacl
ok   github.com/guardianwaf/guardianwaf/internal/layers/ratelimit
ok   github.com/guardianwaf/guardianwaf/internal/layers/response
ok   github.com/guardianwaf/guardianwaf/internal/layers/rules
ok   github.com/guardianwaf/guardianwaf/internal/layers/sanitizer
ok   github.com/guardianwaf/guardianwaf/internal/layers/threatintel
ok   github.com/guardianwaf/guardianwaf/internal/layers/virtualpatch
ok   github.com/guardianwaf/guardianwaf/internal/mcp
ok   github.com/guardianwaf/guardianwaf/internal/netutil
ok   github.com/guardianwaf/guardianwaf/internal/proxy
ok   github.com/guardianwaf/guardianwaf/internal/runtime/layerregistry
ok   github.com/guardianwaf/guardianwaf/internal/tenant
ok   github.com/guardianwaf/guardianwaf/internal/tls
ok   github.com/guardianwaf/guardianwaf/internal/tracing
ok   github.com/guardianwaf/guardianwaf/scripts/attack-simulation
ok   github.com/guardianwaf/guardianwaf/tests/e2e
ok   github.com/guardianwaf/guardianwaf/tests/integration
ok   github.com/guardianwaf/guardianwaf/tests/reliability
```

The ACME package was tested separately because it is slower:

```bash
timeout 12m go test -count=1 -timeout=10m ./internal/acme
```

Result:

```text
ok   github.com/guardianwaf/guardianwaf/internal/acme  36.553s
```

### Formatting

Command:

```bash
gofmt -s -l .
```

Result: no output, meaning no Go files required formatting.

### Dashboard tests

Command:

```bash
npm test -- --run
```

Working directory: `internal/dashboard/ui`

Result:

```text
Test Files  13 passed (13)
Tests       99 passed (99)
```

### Dashboard build

Command:

```bash
npm run build
```

Working directory: `internal/dashboard/ui`

Result: passed; Vite production build completed successfully.

### Dashboard lint

Command:

```bash
npm run lint
```

Working directory: `internal/dashboard/ui`

Result: passed with `eslint src/ --max-warnings=0`.

### Dashboard dependency audit

Command:

```bash
npm audit --audit-level=high
```

Working directory: `internal/dashboard/ui`

Result:

```text
found 0 vulnerabilities
```

### Website build

Command:

```bash
npm run build
```

Working directory: `website`

Result: passed; Vite production build completed successfully.

### Website dependency audit

Command:

```bash
npm audit --audit-level=high
```

Working directory: `website`

Result:

```text
found 0 vulnerabilities
```

### Playwright package dependency audit

Command:

```bash
npm audit --audit-level=high
```

Working directory: `tests/e2e/playwright`

Result:

```text
found 0 vulnerabilities
```

### Deployment mutable-tag check

Command pattern searched:

```text
ghcr.io/guardianwaf/guardianwaf:latest|guardianwaf/guardianwaf:latest|tag:\s*"latest"
```

Scope:

```text
contrib/k8s, examples, docker-compose.yml
```

Result: no matches.

### Shell syntax checks

All shell scripts under these paths were syntax checked with `bash -n` during the final pass:

- `scripts/*.sh`
- `scripts/attack-simulation/*.sh`
- `tests/e2e/playwright/scripts/*.sh`

Result: all checked scripts passed syntax validation.

### YAML parse checks

Non-Helm-template YAML files were parsed with PyYAML using multi-document loading.

Result: all checked non-Helm YAML files parsed successfully.

Helm templates were intentionally excluded from raw YAML parsing because Helm template expressions are not valid plain YAML until rendered.

## Checks not executed because tools are unavailable

The following tools were not installed in the verification environment:

```text
missing staticcheck
missing govulncheck
missing shellcheck
missing helm
```

Impact:

- `staticcheck ./...` could not be run locally.
- `govulncheck ./...` could not be run locally.
- Full `shellcheck` diagnostics could not be run locally.
- `helm template guardianwaf contrib/k8s/helm` could not be run locally.

These are the only known verification gaps from this pass.

## Coverage scope note

The repository's local `make cover` target is aligned to the CI coverage scope for tracked production Go packages.

Explicit coverage exclusions:

- `examples/`
- `scripts/attack-simulation/`

These paths are executable demos/operator tooling rather than production library/runtime code, and CI already excluded them from the coverage upload command. The checked-in `Makefile` now matches that scope so local and CI coverage numbers are consistent.

## Current issue list

No issues were reproduced by the checks that were run.

Known remaining verification gaps are tool availability gaps, not confirmed product defects:

1. Install and run `staticcheck`.
2. Install and run `govulncheck`.
3. Install and run `shellcheck`.
4. Install and run `helm template` for the Helm chart.

## Recommended release gate before publishing

Run this in a CI/release environment with the missing tools installed:

```bash
go build ./...
go vet ./...
go test -count=1 -timeout=20m ./...
gofmt -s -l .
staticcheck ./...
govulncheck ./...
shellcheck scripts/*.sh scripts/attack-simulation/*.sh tests/e2e/playwright/scripts/*.sh
helm template guardianwaf contrib/k8s/helm
npm audit --audit-level=high --prefix internal/dashboard/ui
npm test -- --run --prefix internal/dashboard/ui
npm run build --prefix internal/dashboard/ui
npm audit --audit-level=high --prefix website
npm run build --prefix website
npm audit --audit-level=high --prefix tests/e2e/playwright
```

## Final statement

The local `main` branch is clean and passed all runnable build, vet, test, lint, audit, syntax, YAML, and deployment-tag checks executed in this environment. No reproducible issues remain from those checks. Absolute “100% zero issues” should only be asserted after the unavailable external analyzers listed above also pass in CI.
