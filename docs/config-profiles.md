# Production Config Profiles

GuardianWAF ships validated starter profiles under `examples/profiles/`. These files are parsed and validated by `internal/config` fixture tests, so schema drift fails locally and in CI.

## Profiles

| Profile | Use case | Run command |
|---|---|---|
| `local-development.yaml` | Local app on `127.0.0.1:3000`, monitor mode, local dashboard. | `guardianwaf serve -config examples/profiles/local-development.yaml` |
| `standalone-production.yaml` | Public standalone edge proxy with ACME TLS and managed dashboard secrets. | `GWAF_DASHBOARD_API_KEY=... GWAF_DASHBOARD_ADMIN_KEY=... guardianwaf serve -config examples/profiles/standalone-production.yaml` |
| `sidecar-production.yaml` | Loopback sidecar in front of one local workload. | `guardianwaf serve -config examples/profiles/sidecar-production.yaml` |
| `kubernetes-production.yaml` | Kubernetes service-network backend and mounted dashboard secret. | Mount as `/etc/guardianwaf/guardianwaf.yaml`, then run `guardianwaf serve -config /etc/guardianwaf/guardianwaf.yaml`. |
| `docker-discovery-production.yaml` | Docker label discovery with a fallback upstream. | Mount Docker socket and run `guardianwaf serve -config examples/profiles/docker-discovery-production.yaml`. |
| `edge-dashboard-disabled.yaml` | WAF-only edge proxy with no dashboard/admin listener. | `guardianwaf serve -config examples/profiles/edge-dashboard-disabled.yaml` |
| `dashboard-admin-only.yaml` | Local operations dashboard with proxy bound to loopback. | `GWAF_DASHBOARD_API_KEY=... GWAF_DASHBOARD_ADMIN_KEY=... guardianwaf serve -config examples/profiles/dashboard-admin-only.yaml` |

## Runbook

Before using any profile:

1. Copy the profile into your deployment-owned config path.
2. Replace example domains, upstreams, ports, ACME email addresses, and trusted proxy CIDRs.
3. Store `GWAF_DASHBOARD_API_KEY` and `GWAF_DASHBOARD_ADMIN_KEY` in your secret manager when the profile references them.
4. Prefer `allowed_upstream_cidrs` for private service-network backends. Keep `allow_private_upstreams: true` only for deployments that intentionally trust every configured loopback, Docker, Kubernetes, or other private upstream target.
5. Validate before rollout:

```bash
guardianwaf validate -config /etc/guardianwaf/guardianwaf.yaml
```

6. Roll out with liveness on `/livez` and readiness on `/readyz`.
7. Confirm startup logs show the expected mode, upstreams, active WAF pipeline, and dashboard/admin-key state.
8. Send one clean request and one blocked test request before moving production traffic.

## Dashboard Secret Contract

- Empty `dashboard.api_key` is acceptable for local development only; startup generates and prints a strong temporary key.
- Production profiles use `GWAF_DASHBOARD_API_KEY`.
- Tenant-admin APIs stay disabled unless `dashboard.admin_key` or `GWAF_DASHBOARD_ADMIN_KEY` is explicitly configured.

## Persistence

Profiles intended for production use file-backed event storage under `/var/lib/guardianwaf/events/events.jsonl`. Mount that path on persistent storage when events must survive restarts.
