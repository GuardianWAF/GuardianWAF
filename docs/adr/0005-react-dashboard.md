# ADR 0005: React Dashboard with Go Embed

**Date:** 2026-04-15
**Status:** Accepted
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF needs a web-based dashboard for operators to:

- **Monitor real-time security events** — blocks, challenges, log alerts as they happen
- **Configure WAF settings** — virtual hosts, rate limits, rules, alerting
- **View analytics** — top blocked IPs, attack type distribution, traffic trends
- **Visualize routing topology** — upstream services, load balancing, health status

The dashboard must be deployable as a **single binary** with no separate frontend server or static file hosting. This requirement eliminates options like a separate Node.js server or static file hosting via nginx. The tradeoff is that the development toolchain requires Node.js (npm/pnpm), but only at build time — the runtime Go binary is fully self-contained.

## Decision

Build the dashboard using **React 19 + TypeScript + Vite 6 + Tailwind CSS 4**. Built assets are embedded into the Go binary using `embed.FS` and served by the Go HTTP server. Real-time updates use **Server-Sent Events (SSE)**.

### Embed Architecture

```go
//go:embed internal/dashboard/dist
var dashboardFS embed.FS

// In the HTTP server handler:
if strings.HasPrefix(r.URL.Path, "/dashboard") ||
   r.URL.Path == "/" {
    path := strings.TrimPrefix(r.URL.Path, "/dashboard")
    if path == "" || path == "/" {
        path = "index.html"
    }
    f, err := dashboardFS.Open(path)
    if err != nil {
        // Serve index.html for SPA routing (React Router)
        f, _ = dashboardFS.Open("index.html")
    }
    io.Copy(w, f)
}
```

The `//go:embed` directive copies the built `dist/` directory into the `dashboardFS` variable at compile time. The Go binary contains the entire React app. There are no external file reads at runtime.

### Development Mode (Hot Reload)

During development, operators run:

```bash
make ui-dev
# cd internal/dashboard/ui && npm run dev
# Vite dev server starts on :5173, proxies /api and /ws to :9443
```

Vite's dev server provides:
- **Hot Module Replacement (HMR)** — component changes appear in the browser without full page reload
- **Fast refresh** — React state is preserved across component updates
- **API proxy** — `/api/*` requests are forwarded to the Go backend at `localhost:9443`, eliminating CORS issues during development

### Real-Time Updates (SSE)

Instead of WebSocket (which requires a dedicated connection management protocol), the dashboard uses **Server-Sent Events** for real-time updates:

```go
// Dashboard SSE endpoint in internal/dashboard/api.go
func (api *API) HandleSSE(w http.ResponseWriter, r *http.Request) {
    fl, ok := w.(http.Flusher)
    if !ok {
        http.Error(w, "SSE not supported", http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")

    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-r.Context().Done():
            return
        case event := <-api.eventChan:
            fmt.Fprintf(w, "data: %s\n\n", event.JSON())
            fl.Flush()
        case <-ticker.C:
            fmt.Fprintf(w, ": ping\n\n")
            fl.Flush()
        }
    }
}
```

SSE advantages over WebSocket for this use case:
- **HTTP/1.1 compatible** — works through most proxies and load balancers without special configuration
- **Automatic reconnection** — browsers automatically reconnect on connection drop
- **Simpler server implementation** — no connection state management; each event is a single `fmt.Fprintf`
- **Unidirectional** — the dashboard only receives events; it never sends data over the SSE connection

### Routing Topology Graph

The dashboard includes a live **React Flow** topology visualization of the WAF's routing configuration:

```go
// API response for topology data
type Topology struct {
    Upstreams []UpstreamNode
    Routes    []RouteEdge
    Nodes     []ProxyNode // WAF proxy instances
}
```

Nodes represent WAF proxy instances and backend upstreams; edges represent routes. Each node shows health status (green/yellow/red) derived from the health check subsystem, updating via SSE.

## Consequences

### Positive

- **Single binary deployment** — `guardianwaf serve` includes the dashboard; no separate `nginx - serving static files` step, no `npm run build` in production
- **Zero external services at runtime** — no Redis, no separate React app server, no CDN for static assets
- **Hot-reload development** — Vite HMR provides a fast feedback loop during frontend development; `make ui-dev` is optional for operators who prefer to develop the UI
- **Type-safe frontend** — TypeScript catches component prop mismatches and API response shape errors at compile time
- **Modern UI component model** — React's hooks-based architecture and Tailwind's utility-first CSS enable rapid iteration on new dashboard features
- **SSE simplicity** — the dashboard does not need a WebSocket upgrade path; SSE works over standard HTTP/1.1

### Negative

- **Node.js required for frontend development** — `npm install` and `npm run dev` require a Node.js environment even though the Go binary has no Node.js dependency at runtime
- **Binary size increase** — the embedded React app adds ~2–4 MB to the Go binary (acceptable for a WAF; negligible compared to the rest of the binary)
- **Separate test setup** — frontend unit tests require Vitest; `make test` only runs Go tests
- **Build step required after frontend changes** — `make ui` must be run before `make build` if the React app changes; the `make build` target runs `make ui` automatically
- **SPA routing limitation** — because `embed.FS` serves files statically, React Router's client-side routing requires a fallback to `index.html` for all non-asset paths

### Dashboard Pages

The React dashboard (14 pages, all route through React Router SPA with SSE real-time updates):

| Route | Component | Purpose |
|-------|-----------|---------|
| `/` | Dashboard | KPI cards, recent events feed, attack distribution chart |
| `/logs` | Event Log | Filterable event table with export |
| `/routing` | Routing Topology | React Flow graph, upstreams, health status |
| `/rules` | Rule Editor | CRUD for custom WAF rules |
| `/clusters` | Clusters | Cluster node status, leader election |
| `/cluster/:id` | Cluster Detail | Per-node metrics and ban sync |
| `/ssl` | SSL/TLS | Certificate management, ACME, SNI |
| `/alerting` | Alerting | Webhooks, email targets, test alerts |
| `/config` | Config Editor | YAML config viewer with validation |
| `/ai` | AI Analysis | Provider config, model selection, analysis history |
| `/tenants` | Tenant Manager | Multi-tenant management |
| `/tenant/new` | New Tenant | Tenant onboarding form |
| `/tenant/:id` | Tenant Detail | Per-tenant analytics, rules, billing |
| `/tenant/:id/analytics` | Tenant Analytics | Per-tenant traffic trends |

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/dashboard/dashboard.go` | HTTP handler, embed.FS declaration, route wiring |
| `internal/dashboard/api.go` | REST API handlers (events, stats, config) |
| `internal/dashboard/sse.go` | SSE endpoint and event broadcaster |
| `internal/dashboard/ui/` | React 19 source (Vite project) |
| `internal/dashboard/dist/` | Built React assets (embed.FS target) |
| `Makefile` (`ui` target) | `cd internal/dashboard/ui && npm install && npm run build` |

## References

- [React 19 Documentation](https://react.dev/blog/2024/04/25/react-19)
- [Vite 6](https://vite.dev/)
- [Tailwind CSS 4](https://tailwindcss.com/)
- [React Flow](https://reactflow.dev/)
- [Server-Sent Events (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)
- [Go embed package](https://pkg.go.dev embed)
