# Getting Started

This guide covers installing GuardianWAF and running it in each of its three deployment modes.

---

## Installation

### go install

```bash
go install github.com/guardianwaf/guardianwaf/cmd/guardianwaf@latest
```

### Binary Download

Download the latest release from [GitHub Releases](https://github.com/guardianwaf/guardianwaf/releases):

```bash
# Linux (amd64)
curl -Lo guardianwaf https://github.com/guardianwaf/guardianwaf/releases/latest/download/guardianwaf-linux-amd64
chmod +x guardianwaf
sudo mv guardianwaf /usr/local/bin/

# macOS (arm64)
curl -Lo guardianwaf https://github.com/guardianwaf/guardianwaf/releases/latest/download/guardianwaf-darwin-arm64
chmod +x guardianwaf
sudo mv guardianwaf /usr/local/bin/

# Windows (amd64)
# Download guardianwaf-windows-amd64.exe from the releases page
```

### Docker

```bash
docker pull guardianwaf/guardianwafwaf:latest
```

### Build from Source

```bash
git clone https://github.com/guardianwaf/guardianwaf.git
cd guardianwaf
make build
# Binary: ./guardianwaf
```

---

## Deployment Modes

### 1. Standalone Reverse Proxy

Full-featured mode: reverse proxy + web dashboard + MCP server.

Create `guardianwaf.yaml`:

```yaml
mode: enforce
listen: ":8088"

upstreams:
  - name: backend
    targets:
      - url: "http://localhost:3000"
    health_check:
      enabled: true
      interval: 10s
      path: /healthz

routes:
  - path: /
    upstream: backend

dashboard:
  enabled: true
  listen: ":9443"
  api_key: "your-secret-key"

logging:
  level: info
  format: json
```

Start the WAF:

```bash
guardianwaf serve -c guardianwaf.yaml
```

GuardianWAF now proxies all traffic on `:8088` to your backend on `:3000`, inspecting every request. The dashboard is available on `:9443`.

### 2. Library Mode (Go Middleware)

Embed GuardianWAF directly into your Go application:

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
        fmt.Fprintln(w, "Hello, protected world!")
    })

    http.ListenAndServe(":8088", waf.Middleware(mux))
}
```

### 3. Sidecar Mode (Docker / Kubernetes)

Lightweight proxy without dashboard or MCP. Ideal for container environments.

```bash
# Docker
docker run -d \
  --name guardianwaf \
  -p 8088:8088 \
  guardianwaf/guardianwafwaf:latest \
  sidecar --upstream http://app:3000

# Or with a config file
docker run -d \
  -v ./guardianwaf.yaml:/etc/guardianwaf/guardianwaf.yaml:ro \
  -p 8088:8088 \
  guardianwaf/guardianwafwaf:latest \
  sidecar -c /etc/guardianwaf/guardianwaf.yaml
```

Kubernetes sidecar example:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp
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
```

---

## Minimal Configuration

GuardianWAF ships with production-safe defaults. This minimal config is enough:

```yaml
mode: enforce
listen: ":8088"

upstreams:
  - name: app
    targets:
      - url: "http://localhost:3000"

routes:
  - path: /
    upstream: app
```

All detection (SQLi, XSS, LFI, CMDi, XXE, SSRF), rate limiting, sanitization, bot detection, security headers, and data masking are enabled by default.

---

## Running the Check Command

Test a request without running the full server:

```bash
# Safe request
guardianwaf check --url "/search?q=hello"

# Malicious request
guardianwaf check --url "/search?q=' OR 1=1 --" --verbose

# With custom headers and method
guardianwaf check \
  --url "/api/users" \
  --method POST \
  -H "Content-Type: application/json" \
  --body '{"name": "test"}' \
  --verbose
```

Output:

```
Action:   block
Score:    85
Duration: 142µs
Result:   BLOCKED
Findings: 2

  [1] Boolean-based SQL injection with tautology detected (sqli)
      Severity: high | Score: 85 | Confidence: 0.90
      Match:    ' OR 1 = 1
      Location: query
```

Exit codes: `0` = passed, `2` = blocked.

---

## Validating Configuration

Check your config file for errors before deploying:

```bash
guardianwaf validate -c guardianwaf.yaml
```

Output:

```
Configuration guardianwaf.yaml is valid.
  Mode:       enforce
  Listen:     :8088
  Upstreams:  1
  Routes:     1
  Detection:  true (6 detectors)
  Rate Limit: true (1 rules)
  IP ACL:     true
  Bot Detect: true
  Dashboard:  true (:9443)
  MCP:        true (stdio)
```

---

## Verifying It Works

1. Start GuardianWAF in front of your app.
2. Send a normal request to confirm traffic flows:
   ```bash
   curl http://localhost:8088/
   ```
3. Send a test attack to confirm detection:
   ```bash
   curl "http://localhost:8088/search?q=%27%20OR%201%3D1%20--"
   # Expected: 403 Forbidden - Request blocked by GuardianWAF
   ```
4. Check the response header for the request ID:
   ```
   X-GuardianWAF-RequestID: <uuid>
   ```

---

## Next Steps

- [Configuration Reference](configuration.md) -- full YAML schema
- [Detection Engine](detection-engine.md) -- how scoring works
- [Tuning Guide](tuning-guide.md) -- reducing false positives
- [API Reference](api-reference.md) -- REST API endpoints
- [MCP Integration](mcp-integration.md) -- AI agent integration
