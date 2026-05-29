# GuardianWAF Health Probes

GuardianWAF exposes three unauthenticated operational probe endpoints on the proxy listener.

## Probe Semantics

| Endpoint | Intended use | Success condition | Failure condition |
|---|---|---|---|
| `GET /livez` | Liveness probe | The process is running and the HTTP listener can serve requests. | The process is dead, wedged, or unable to answer HTTP requests. |
| `GET /readyz` | Readiness probe | The process is live and every configured upstream group with targets has at least one healthy target. | One or more configured upstream groups has targets, but zero healthy targets. |
| `GET /healthz` | Backward-compatible legacy probe | Same liveness-style behavior as `/livez`. | Same failure modes as `/livez`. |

Use `/livez` for restart decisions and `/readyz` for load-balancer or Kubernetes traffic routing decisions.

## Kubernetes

```yaml
livenessProbe:
  httpGet:
    path: /livez
    port: 8088
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /readyz
    port: 8088
  initialDelaySeconds: 5
  periodSeconds: 5
```

Do not use readiness failures to restart the pod. A readiness failure often means every backend target is temporarily unhealthy, not that GuardianWAF itself is broken.

## Docker

Container health checks should use liveness:

```yaml
healthcheck:
  test: ["CMD", "wget", "-q", "--spider", "http://localhost:8088/livez"]
  interval: 30s
  timeout: 3s
  retries: 3
```

External load balancers should use readiness:

```bash
curl -f http://guardianwaf:8088/readyz
```

## Response Shape

`/livez` and `/healthz` return a small JSON body with process-level stats:

```json
{
  "status": "ok",
  "mode": "enforce",
  "total_requests": 1234,
  "blocked_requests": 12
}
```

`/readyz` adds upstream readiness details:

```json
{
  "status": "ready",
  "mode": "enforce",
  "total_requests": 1234,
  "blocked_requests": 12,
  "upstreams_total": 2,
  "upstreams_unhealthy": []
}
```

When readiness fails, the status code is `503` and `upstreams_unhealthy` lists the affected upstream groups.

## Current Coverage Boundary

Readiness currently covers configured upstream target health. Future production hardening should extend `/readyz` to include required local dependencies such as persistent event storage, GeoIP data when configured as required, and dashboard state when the dashboard is enabled.
