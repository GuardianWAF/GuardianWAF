# Dependency Audit

## Go Dependencies

| Dependency | Version | Type | Notes |
|---|---|---|---|
| `github.com/quic-go/quic-go` | v0.59.0 | direct | HTTP/3 support (build with `-tags http3`) |
| `github.com/quic-go/qpack` | v0.6.0 | indirect | HPACK/QPACK compression for quic-go |
| `golang.org/x/crypto` | v0.49.0 | indirect | Cryptographic primitives |
| `golang.org/x/net` | v0.52.0 | indirect | Networking utilities |
| `golang.org/x/sys` | v0.42.0 | indirect | System calls |
| `golang.org/x/text` | v0.35.0 | indirect | Text processing |

**Assessment:** Minimal dependency surface — only 1 direct dependency. Strong security posture.

## npm Dependencies (Dashboard)

| Dependency | Version | Type |
|---|---|---|
| `@xyflow/react` | ^12.10.1 | production |
| `class-variance-authority` | ^0.7.0 | production |
| `clsx` | ^2.1.0 | production |
| `lucide-react` | ^0.500.0 | production |
| `react` | ^19.0.0 | production |
| `react-dom` | ^19.0.0 | production |
| `react-router` | ^7.0.0 | production |
| `tailwind-merge` | ^3.0.0 | production |

Dev dependencies: `@tailwindcss/vite`, `@types/react`, `@types/react-dom`, `@vitejs/plugin-react`, `tailwindcss`, `typescript`, `vite`.

**Assessment:** No `package-lock.json` found. Semver ranges (`^`) allow unpinned transitive dependencies.

## `//nolint` Suppressions

| File | Line | Suppression | Context |
|---|---|---|---|
| `internal/layers/threatintel/feed.go` | 55 | `//nolint:gosec` | `InsecureSkipVerify: true` — production code |
| `internal/mcp/sse_test.go` | 194,227,462,567,758 | `//nolint:noctx` | `http.Get` without context — test code |
| `internal/mcp/sse_test.go` | 486,600 | `//nolint:noctx` | `http.Post` without context — test code |

**Assessment:** Only 1 production-code suppression (TLS skip-verify for threat intel feeds).

## Findings

| Severity | Finding |
|---|---|
| **Medium** | `InsecureSkipVerify: true` in threat intel client — must be user opt-in only |
| **Low** | No `package-lock.json` — unpinned npm transitive dependencies |
| **Low** | No vendor directory — builds depend on Go module proxy availability |
| **Info** | 7 nolint directives total, 6 in test code (acceptable) |
| **Info** | `golang.org/x/crypto` v0.49.0 and `golang.org/x/net` v0.52.0 are recent, no known CVEs |
