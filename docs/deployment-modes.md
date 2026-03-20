# Deployment Modes

GuardianWAF supports three deployment modes to fit any architecture. Each mode uses the same detection engine and scoring system.

---

## Mode Comparison

| Feature | Standalone | Library | Sidecar |
|---|---|---|---|
| **Use case** | Drop-in reverse proxy | Go middleware | Container sidecar |
| **Deployment** | Separate binary | Compiled into your app | Separate container |
| **Web dashboard** | Yes | No | No |
| **MCP server** | Yes | No | No |
| **Health check endpoint** | `/healthz` (dashboard) | Your app provides | `/healthz` built-in |
| **Config source** | YAML + env + CLI | Go API / YAML | YAML + env + CLI |
| **Load balancing** | Built-in | N/A | Built-in |
| **Language support** | Any backend | Go only | Any backend |
| **TLS termination** | Optional (ACME) | Your app handles | No |
| **Binary command** | `guardianwaf serve` | N/A (library) | `guardianwaf sidecar` |

---

## 1. Standalone Mode

Full-featured reverse proxy with integrated dashboard and MCP server. Sits in front of your application and inspects all traffic.

```
                    ┌─────────────────────┐
   Client ─────────│    GuardianWAF       │─────────── Backend
    :8088          │  (reverse proxy)     │            :3000
                    │                     │
                    │  Dashboard  :9443   │
                    │  MCP server (stdio) │
                    └─────────────────────┘
```

### Configuration

```yaml
mode: enforce
listen: ":8088"

upstreams:
  - name: api
    targets:
      - url: "http://api-server:3000"
        weight: 1
      - url: "http://api-server-2:3000"
        weight: 1
    load_balancer: round_robin
    health_check:
      enabled: true
      interval: 10s
      timeout: 5s
      path: /healthz

  - name: static
    targets:
      - url: "http://cdn:8088"

routes:
  - path: /api
    upstream: api
    strip_prefix: true
  - path: /
    upstream: static

dashboard:
  enabled: true
  listen: ":9443"
  api_key: "your-secret-key"

mcp:
  enabled: true
  transport: stdio
```

### Running

```bash
# From binary
guardianwaf serve -c guardianwaf.yaml

# With overrides
guardianwaf serve -c guardianwaf.yaml --mode monitor --log-level debug

# Docker
docker run -d \
  -p 8088:8088 -p 9443:9443 \
  -v ./guardianwaf.yaml:/etc/guardianwaf/guardianwaf.yaml:ro \
  guardianwaf/guardianwafwaf:latest \
  serve -c /etc/guardianwaf/guardianwaf.yaml
```

### Features

- **Reverse proxy** with path-based routing to multiple upstreams
- **Load balancing** (round-robin, weighted, least-conn, IP hash)
- **Health checks** with automatic target removal/restoration
- **Web dashboard** with real-time monitoring and rule management
- **MCP server** for AI agent integration (Claude Code, etc.)
- **TLS termination** with optional ACME auto-certificate
- **Graceful shutdown** (15-second drain on SIGINT/SIGTERM)

---

## 2. Library Mode

Embed GuardianWAF directly as Go middleware. No separate process. Ideal when you want WAF protection compiled into your application.

```
   Client ──────── Your Go Application ──────── (no separate proxy)
    :8088         ┌──────────────────┐
                  │  guardianwaf     │
                  │  .Middleware()   │
                  │       ↓          │
                  │  Your Handlers   │
                  └──────────────────┘
```

### Minimal Example

```go
package main

import (
    "fmt"
    "net/http"

    "github.com/guardianwaf/guardianwaf"
)

func main() {
    waf, err := guardianwaf.New(guardianwaf.Config{
        Mode:      guardianwaf.ModeEnforce,
        Threshold: guardianwaf.ThresholdConfig{Block: 50, Log: 25},
    })
    if err != nil {
        panic(err)
    }
    defer waf.Close()

    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintln(w, "Protected!")
    })

    http.ListenAndServe(":8088", waf.Middleware(mux))
}
```

### Loading from YAML File

```go
waf, err := guardianwaf.NewFromFile("guardianwaf.yaml")
if err != nil {
    log.Fatal(err)
}
defer waf.Close()

http.ListenAndServe(":8088", waf.Middleware(myHandler))
```

### Using Functional Options

```go
waf, err := guardianwaf.New(guardianwaf.Config{},
    guardianwaf.WithMode(guardianwaf.ModeEnforce),
    guardianwaf.WithThreshold(60, 30),
    guardianwaf.WithDetector("sqli", true, 1.5),
    guardianwaf.WithDetector("xss", true, 1.0),
    guardianwaf.WithMaxBodySize(5 * 1024 * 1024), // 5MB
    guardianwaf.WithIPWhitelist("10.0.0.0/8"),
    guardianwaf.WithIPBlacklist("203.0.113.0/24"),
    guardianwaf.WithBotDetection(true),
    guardianwaf.WithSecurityHeaders(true),
    guardianwaf.WithDataMasking(true),
    guardianwaf.WithMaxEvents(50000),
)
```

### Event Callbacks

```go
waf.OnEvent(func(event guardianwaf.Event) {
    if event.Action.String() == "block" {
        fmt.Printf("[BLOCKED] %s %s from %s (score: %d)\n",
            event.Method, event.Path, event.ClientIP, event.Score)
    }
})
```

### Manual Request Checking

```go
result := waf.Check(req)
fmt.Printf("Blocked: %v, Score: %d, Findings: %d\n",
    result.Blocked, result.TotalScore, len(result.Findings))

for _, f := range result.Findings {
    fmt.Printf("  %s: %s (score: %d)\n", f.Detector, f.Description, f.Score)
}
```

### Runtime Statistics

```go
stats := waf.Stats()
fmt.Printf("Total: %d, Blocked: %d, Avg latency: %dµs\n",
    stats.TotalRequests, stats.BlockedRequests, stats.AvgLatencyUs)
```

---

## 3. Sidecar Mode

Lightweight proxy designed for container environments. No dashboard, no MCP -- just WAF protection with a health check endpoint.

```
  ┌──────────────────────────────────────┐
  │  Pod / Docker Compose                │
  │                                      │
  │  ┌──────────────┐  ┌──────────────┐ │
  │  │ GuardianWAF  │→ │  Your App    │ │
  │  │  (sidecar)   │  │  :3000       │ │
  │  │  :8088       │  │              │ │
  │  └──────────────┘  └──────────────┘ │
  └──────────────────────────────────────┘
```

### Quick Start

```bash
# Minimal — just upstream URL
guardianwaf sidecar --upstream http://localhost:3000

# With config
guardianwaf sidecar -c guardianwaf.yaml --upstream http://localhost:3000

# Override mode
guardianwaf sidecar --upstream http://app:3000 --mode monitor --listen :8088
```

### Docker Compose

```yaml
version: "3.9"
services:
  waf:
    image: guardianwaf/guardianwafwaf:latest
    command: ["sidecar", "--upstream", "http://app:3000"]
    ports:
      - "8088:8088"
    environment:
      - GWAF_MODE=enforce
    depends_on:
      - app

  app:
    image: myapp:latest
    expose:
      - "3000"
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: app
          image: myapp:latest
          ports:
            - containerPort: 3000

        - name: waf
          image: guardianwaf/guardianwafwaf:latest
          args: ["sidecar", "--upstream", "http://localhost:3000", "--listen", ":8088"]
          ports:
            - containerPort: 8088
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8088
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests:
              cpu: "50m"
              memory: "32Mi"
            limits:
              cpu: "200m"
              memory: "128Mi"
```

### Health Check

Sidecar mode exposes `/healthz` on the listen address:

```bash
curl http://localhost:8088/healthz
# ok
```

### Features

- Zero-config mode (just `--upstream` flag)
- Built-in `/healthz` for Kubernetes liveness probes
- No dashboard or MCP (reduced attack surface)
- Identical detection to standalone mode
- Environment variable configuration for 12-factor apps

---

## Choosing a Mode

| Scenario | Recommended Mode |
|---|---|
| Protecting any web application (any language) | **Standalone** |
| Go application, want minimal infrastructure | **Library** |
| Kubernetes with sidecar pattern | **Sidecar** |
| Need a web dashboard for monitoring | **Standalone** |
| Need AI agent integration (MCP) | **Standalone** |
| Multiple backends with load balancing | **Standalone** |
| Single Go service, embedded protection | **Library** |
| CI/CD pipeline request validation | **Library** (`Check()` API) |
