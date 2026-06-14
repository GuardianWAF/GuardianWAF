# GuardianWAF Health Probes

GuardianWAF exposes three unauthenticated operational probe endpoints on the proxy listener.

## Probe Semantics

| Endpoint | Intended use | Success condition | Failure condition |
|---|---|---|---|
| `GET /livez` | Liveness probe | The process is running and the HTTP listener can serve requests. | The process is dead, wedged, or unable to answer HTTP requests. |
| `GET /readyz` | Readiness probe | The process is live, config/engine/event store are initialized, dashboard listener startup succeeded when dashboard is enabled, configured proxy routing has an active router, and every configured upstream group with targets has at least one healthy target. | A required runtime dependency is not initialized, dashboard listener startup failed, configured proxy routing has no active router/upstreams, or one or more configured upstream groups has targets but zero healthy targets. |
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

`/readyz` adds dependency and upstream readiness details:

```json
{
  "status": "ready",
  "mode": "enforce",
  "reasons": [],
  "total_requests": 1234,
  "blocked_requests": 12,
  "dashboard_ready": true,
  "event_store_ready": true,
  "geoip_ready": true,
  "geoip_ranges": 145231,
  "router_ready": true,
  "upstreams_total": 2,
  "upstreams_unhealthy": []
}
```

When readiness fails, the status code is `503`, `status` is `not_ready`, and `reasons` explains the failed dependency. Possible baseline reasons are:

- `config_not_loaded`
- `engine_not_ready`
- `event_store_not_ready`
- `dashboard_not_ready`
- `router_not_ready`
- `no_active_upstreams`
- `upstreams_unhealthy`
- `geoip_not_ready`

`upstreams_unhealthy` lists the affected upstream groups. `geoip_ready` and `geoip_ranges` are reported for operators. GeoIP is not a hard readiness dependency by default; set `waf.geoip.enabled: true` and `waf.geoip.require_ready: true` when a deployment profile must not receive traffic until GeoIP data is loaded.

## Profile Readiness Policy

All shipped profiles use `/livez` for process restart decisions and `/readyz` for traffic admission. The baseline hard readiness dependencies are config load, engine startup, event-store startup, router construction, and upstream health. Dashboard listener startup is hard readiness only when `dashboard.enabled: true`. GeoIP is hard readiness only when `waf.geoip.require_ready: true`.

| Profile | Hard readiness dependencies | Not a hard dependency |
|---|---|---|
| `local-development.yaml` | Config, engine, in-memory event store, dashboard listener, router, local upstream health. | GeoIP, ACME, Docker discovery, external AI providers. |
| `standalone-production.yaml` | Config, engine, file event store open, dashboard listener, router, public upstream health. | GeoIP unless `waf.geoip.require_ready` is enabled, external AI providers, alert delivery targets. |
| `sidecar-production.yaml` | Config, engine, file event store open, router, loopback workload health. | Dashboard, GeoIP unless `waf.geoip.require_ready` is enabled, ACME, Docker discovery. |
| `kubernetes-production.yaml` | Config, engine, file event store open, dashboard listener, router, Kubernetes service upstream health. | GeoIP unless `waf.geoip.require_ready` is enabled, ACME, external AI providers. |
| `docker-discovery-production.yaml` | Config, engine, file event store open, dashboard listener, router, fallback upstream health. | Docker event-stream freshness, GeoIP unless `waf.geoip.require_ready` is enabled, external AI providers. |
| `edge-dashboard-disabled.yaml` | Config, engine, file event store open, router, public origin health. | Dashboard, GeoIP unless `waf.geoip.require_ready` is enabled, external AI providers. |
| `dashboard-admin-only.yaml` | Config, engine, in-memory event store, dashboard listener, router, local placeholder upstream health. | GeoIP, ACME, Docker discovery, external AI providers. |

Do not make outbound integrations such as AI providers, webhooks, email, threat-intel feeds, NVD, GeoIP downloads, Docker polling freshness, or alert delivery hard readiness dependencies unless the profile explicitly requires them for safe traffic handling. Prefer metrics and alerts for degraded optional integrations so transient third-party outages do not remove otherwise healthy WAF instances from service.

## Current Coverage Boundary

Readiness currently covers config/engine/event-store initialization, dashboard listener startup when dashboard is enabled, proxy router construction, active upstream status, and optional mandatory GeoIP readiness via `waf.geoip.require_ready`. Future production hardening should update the profile policy above and extend `/readyz` before making any other profile-specific dependency mandatory.
