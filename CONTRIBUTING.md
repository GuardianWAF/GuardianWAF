# Contributing to GuardianWAF

Thank you for your interest in contributing! This guide covers the development workflow for both the Go backend and the React dashboard.

## Prerequisites

- **Go 1.26.10+** — Backend runtime
- **Node.js 22.22.2+ (22.x), 24.15.0+ (24.x), or 26+** — Dashboard build toolchain
- **npm** — Frontend package manager
- **golangci-lint** — Go linter (optional, for `make lint`)
- **Docker** — For integration tests (`make docker-test`)

## Quick Start

```bash
# Clone and build everything (dashboard + Go binary)
make build

# Run in serve mode
make run

# Dashboard dev mode with hot reload (port :5173, proxies API to :9443)
make ui-dev
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature
```

### 2. Make Changes

Follow the architecture conventions documented in `CLAUDE.md`. Key points:

- **Zero external Go dependencies** — only stdlib
- Use `any` instead of `interface{}`
- Use built-in `min`/`max`, `range N`, `slices.Contains`
- Pipeline layers implement `Name() + Process(ctx *RequestContext) LayerResult`

### 3. Test

```bash
# Go tests (always run with -race)
make test

# Single package
go test -race -v ./internal/engine/... -run TestPipeline

# Frontend tests
cd internal/dashboard/ui && npm test

# Frontend tests in watch mode
cd internal/dashboard/ui && npm run test:watch

# Benchmarks and fuzz tests
make bench
make fuzz
```

### 4. Lint

```bash
# Go
make vet
make lint

# Frontend
cd internal/dashboard/ui && npm run lint

# Format
make fmt
make tidy
```

### 5. Commit and Push

```bash
git add -A
git commit -m "feat: description of change"
git push origin feature/your-feature
```

### 6. Open a Pull Request

Include a clear description of what changed and why. Reference any related issues.

## Project Structure

```
cmd/guardianwaf/          CLI entry point (serve, sidecar, check, validate)
internal/engine/          Core engine, pipeline, scoring, request context
internal/config/          YAML config parser, structs, validation
internal/layers/          WAF detection layers (SQLi, XSS, LFI, etc.)
internal/proxy/           Reverse proxy, load balancer, health checks
internal/dashboard/       React dashboard + Go REST API + SSE
  ui/                     React 19 + Vite 8 + Tailwind CSS 4
internal/events/          Event storage (ring buffer, JSONL, event bus)
internal/tenant/          Multi-tenant isolation and management
internal/ai/              AI threat analysis
internal/mcp/             MCP JSON-RPC server
```

## Frontend Development

### Tech Stack

- React 19 + TypeScript
- Vite 8 (build tool)
- Tailwind CSS 4 (styling)
- Vitest 4 + React Testing Library 16 (testing)
- ESLint 10 (linting)
- Lucide React (icons)

### Directory Layout

```
internal/dashboard/ui/
  src/
    components/
      dashboard/          Dashboard-specific components
      ui/                 Reusable UI primitives (Button, Card, etc.)
    hooks/                Custom React hooks (useSSE, useStats, useTheme)
    lib/                  Utility functions and API client
    pages/                Route-level page components (lazy-loaded)
    test/                 Test setup (vitest globals, jest-dom matchers)
```

### Running the Dashboard

```bash
# Dev mode — hot reload on :5173, proxies API to :9443
make ui-dev

# Production build (embedded into Go binary)
make ui
```

### Writing Frontend Tests

Tests use Vitest with jsdom and React Testing Library. Global `describe`, `it`, `expect`, and `vi` are available (configured in `tsconfig.json` types and `vite.config.ts` globals).

```bash
# Run all frontend tests
cd internal/dashboard/ui && npm test

# Watch mode
cd internal/dashboard/ui && npm run test:watch
```

Example test pattern:

```tsx
import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { MyComponent } from './my-component'

describe('MyComponent', () => {
  it('renders correctly', () => {
    render(<MyComponent title="Hello" />)
    expect(screen.getByText('Hello')).toBeInTheDocument()
  })
})
```

For hooks, use `renderHook` from `@testing-library/react` with appropriate mocking of browser APIs (fetch, EventSource, etc.).

### Frontend Linting

```bash
cd internal/dashboard/ui && npm run lint
```

Uses ESLint 10 with typescript-eslint, react-hooks, and react-refresh plugins.

## Code Style

### Go

- Run `make fmt` before committing (gofmt -s)
- Follow standard Go conventions
- Prefer returning errors over panicking
- Use structured logging via `slog`

### TypeScript / React

- Functional components with hooks
- Use `React.memo` for dashboard components that receive stable props
- Use `useNavigate()` from react-router for navigation (never `window.location.href`)
- Use `useToast()` for error notifications (never silent `.catch(() => {})`)
- Use shared `api` module from `@/lib/api` for all API calls (never inline `fetch`)
- Pages are lazy-loaded via `React.lazy` in `App.tsx`

## Commit Messages

Use conventional commit prefixes:

- `feat:` — New feature
- `fix:` — Bug fix
- `refactor:` — Code restructuring
- `test:` — Adding or updating tests
- `docs:` — Documentation changes
- `chore:` — Build, CI, or tooling changes

## CI Pipeline

The GitHub Actions CI pipeline runs on every push:

1. **build-dashboard** — Installs npm deps, builds dashboard, runs frontend tests and lint, uploads build artifact
2. **test** — Downloads dashboard artifact, runs Go tests with `-race`
3. **lint** — Downloads dashboard artifact, runs golangci-lint

Release builds also generate SBOM and publish multi-arch Docker images to GHCR.

## Reporting Issues

Open a GitHub issue with:

- GuardianWAF version (`guardianwaf --version`)
- Go version (`go version`)
- Steps to reproduce
- Expected vs actual behavior
- Relevant log output (redact sensitive data)
