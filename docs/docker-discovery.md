# Docker Auto-Discovery

GuardianWAF can automatically discover backend services running as Docker containers. Simply add labels to your containers — GuardianWAF watches the Docker daemon and dynamically creates upstreams, routes, and virtual hosts. Zero configuration files needed for backends.

## How It Works

```
Docker Daemon ──► Watcher ──► Label Parse ──► BuildConfig ──► Atomic Proxy Rebuild
       ▲                                                            │
  Event Stream                                              upstreamHandler.Store()
 (start/stop/die)                                           (zero-downtime swap)
```

1. GuardianWAF connects to the Docker daemon (Unix socket or CLI)
2. Lists all containers with `gwaf.enable=true` label
3. Parses `gwaf.*` labels → builds upstream pools, routes, virtual hosts
4. Watches for container start/stop events in real-time
5. Atomically rebuilds the proxy on changes — **zero downtime**

## Quick Start

### 1. Enable Docker Discovery

```yaml
# guardianwaf.yaml
docker:
  enabled: true
  socket_path: /var/run/docker.sock   # Linux/macOS
  label_prefix: gwaf                   # Label prefix (default: gwaf)
  poll_interval: 5s                    # Fallback poll interval
  network: bridge                      # Docker network to read IPs from
```

### 2. Label Your Containers

```yaml
# docker-compose.yml
services:
  guardianwaf:
    image: guardianwaf/guardianwaf:latest
    ports:
      - "80:8088"
      - "443:8443"
      - "9443:9443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./guardianwaf.yaml:/etc/guardianwaf/guardianwaf.yaml
    command: serve -c /etc/guardianwaf/guardianwaf.yaml

  # Backend API — automatically discovered!
  api:
    image: my-api:latest
    labels:
      gwaf.enable: "true"
      gwaf.host: "api.example.com"
      gwaf.upstream: "api-pool"
      gwaf.port: "8088"
      gwaf.health.path: "/healthz"

  # Frontend — automatically discovered!
  web:
    image: nginx:alpine
    labels:
      gwaf.enable: "true"
      gwaf.host: "www.example.com"
      gwaf.upstream: "web-pool"

  # Admin panel — different path
  admin:
    image: my-admin:latest
    labels:
      gwaf.enable: "true"
      gwaf.host: "www.example.com"
      gwaf.path: "/admin"
      gwaf.upstream: "admin-pool"
      gwaf.strip_prefix: "true"
```

That's it! GuardianWAF automatically:
- Creates `api-pool` upstream with `api` container as target
- Creates `web-pool` upstream with `web` container as target
- Creates `admin-pool` upstream with `admin` container at `/admin` path
- Sets up virtual hosts for `api.example.com` and `www.example.com`

## Label Reference

All labels use the configurable prefix (default: `gwaf`).

### Required Labels

| Label | Description | Example |
|-------|-------------|---------|
| `gwaf.enable` | Enable discovery for this container | `"true"` |

### Routing Labels

| Label | Description | Default | Example |
|-------|-------------|---------|---------|
| `gwaf.host` | Virtual host domain | *(default route)* | `"api.example.com"` |
| `gwaf.path` | Route path prefix | `"/"` | `"/api"` |
| `gwaf.upstream` | Upstream pool name | *container name* | `"api-pool"` |
| `gwaf.port` | Container port to proxy to | *auto-detect* | `"8088"` |
| `gwaf.strip_prefix` | Strip path prefix before forwarding | `"false"` | `"true"` |

### Load Balancing Labels

| Label | Description | Default | Example |
|-------|-------------|---------|---------|
| `gwaf.lb` | Load balancer strategy | `"round_robin"` | `"weighted"` |
| `gwaf.weight` | Target weight (for weighted LB) | `"1"` | `"3"` |

**Supported strategies:** `round_robin`, `weighted`, `least_conn`, `ip_hash`

### Health Check Labels

| Label | Description | Default | Example |
|-------|-------------|---------|---------|
| `gwaf.health.path` | Health check endpoint | *(disabled)* | `"/healthz"` |
| `gwaf.health.interval` | Check interval | `"10s"` | `"30s"` |

### TLS Labels

| Label | Description | Default | Example |
|-------|-------------|---------|---------|
| `gwaf.tls` | TLS mode for backend connection | `"off"` | `"auto"` |

**TLS modes:**
- `off` — HTTP connection to backend (default)
- `auto` — HTTPS connection to backend
- `manual` — HTTPS with custom certificates

## Upstream Pooling

Containers with the **same `gwaf.upstream`** value are grouped into a single upstream pool and load-balanced:

```yaml
services:
  # 3 API instances → same pool → load balanced
  api-1:
    image: my-api:latest
    labels:
      gwaf.enable: "true"
      gwaf.host: "api.example.com"
      gwaf.upstream: "api-pool"
      gwaf.weight: "1"

  api-2:
    image: my-api:latest
    labels:
      gwaf.enable: "true"
      gwaf.host: "api.example.com"
      gwaf.upstream: "api-pool"
      gwaf.weight: "1"

  api-3:
    image: my-api:latest
    labels:
      gwaf.enable: "true"
      gwaf.host: "api.example.com"
      gwaf.upstream: "api-pool"
      gwaf.weight: "2"    # gets 2x traffic
```

Result: `api-pool` upstream with 3 targets (weights 1:1:2), health checked, load balanced.

## Scaling

Docker Compose scaling works automatically:

```bash
docker compose up -d --scale api=5
```

GuardianWAF detects all 5 `api` instances and adds them to the upstream pool.

## Port Auto-Detection

If `gwaf.port` is not specified, GuardianWAF auto-detects the port:

1. First exposed TCP port from the container
2. Common ports: 80, 8088, 3000, 5000, 8000
3. Fallback: port 80

## Static + Dynamic Routing

Docker-discovered services are **merged** with static config. Static upstreams take priority:

```yaml
# guardianwaf.yaml — static config
upstreams:
  - name: legacy-backend          # This is preserved
    targets:
      - url: http://10.0.0.5:8088

routes:
  - path: /legacy
    upstream: legacy-backend

docker:
  enabled: true                    # Dynamic services are added alongside static ones
```

## Dashboard Integration

Discovered services appear in:
- **Routing Topology Graph** — Docker containers shown as nodes with health status
- **API endpoint** — `GET /api/v1/docker/services` returns discovered container list

```bash
curl -H "X-API-Key: $KEY" http://localhost:9443/api/v1/docker/services
```

```json
{
  "enabled": true,
  "count": 3,
  "services": [
    {
      "container_id": "abc123def456",
      "container_name": "api-1",
      "image": "my-api:latest",
      "host": "api.example.com",
      "target": "http://172.17.0.2:8088",
      "upstream": "api-pool",
      "weight": 1,
      "health_path": "/healthz",
      "status": "running"
    }
  ]
}
```

## Event-Driven Updates

GuardianWAF uses two methods to detect changes:

1. **Event Stream** (primary) — `docker events` subprocess, instant detection
2. **Polling** (fallback) — periodic container list, configurable interval

When a container starts or stops:
1. Watcher detects the event
2. Re-scans labeled containers
3. Rebuilds proxy configuration
4. Atomic handler swap — **zero request drops**

## Platform Support

| Platform | Connection Method | Notes |
|----------|------------------|-------|
| Linux | Unix socket | `/var/run/docker.sock` |
| macOS | Unix socket | Docker Desktop socket |
| Windows | Docker CLI | Named pipe via `docker` command |
| Remote | Docker CLI | Any Docker context |

## Configuration Reference

```yaml
docker:
  # Enable/disable Docker auto-discovery
  enabled: false

  # Docker socket path (Linux/macOS)
  socket_path: /var/run/docker.sock

  # Label prefix for container labels
  label_prefix: gwaf

  # Poll interval (fallback when event streaming unavailable)
  poll_interval: 5s

  # Docker network to read container IPs from
  network: bridge
```

## Troubleshooting

### Container not discovered
- Verify label: `docker inspect <container> --format '{{json .Config.Labels}}'`
- Check `gwaf.enable` is exactly `"true"` (string, not bool)
- Ensure container is running: `docker ps --filter label=gwaf.enable=true`
- Check GuardianWAF logs for discovery messages

### Wrong IP address
- Set `docker.network` to match your Docker network name
- Check: `docker inspect <container> --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'`

### Permission denied
- Mount Docker socket: `-v /var/run/docker.sock:/var/run/docker.sock:ro`
- Or enable TCP: Docker Desktop → Settings → General → "Expose daemon on tcp://localhost:2375"
