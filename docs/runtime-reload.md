# Runtime Reload Contract

GuardianWAF supports targeted runtime updates, but not every configuration field is hot-reloadable. Operators should treat the dashboard/API reload path as an in-memory configuration update plus targeted proxy rebuild, not as a full process reconfiguration.

## Supported Without Restart

| Change type | Supported path | Runtime effect |
| --- | --- | --- |
| WAF mode | `PUT /api/v1/config` with `{"mode":"monitor"}` or MCP mode tooling | Updates the engine config snapshot for subsequent requests. |
| Detection thresholds | `PUT /api/v1/config` under `waf.detection.threshold` | Updates block/log thresholds atomically in the engine. |
| Sanitizer max body size | `PUT /api/v1/config` under `waf.sanitizer.max_body_size` | Updates the engine's atomic max body size for subsequent request reads. |
| Trusted proxy CIDRs | `PUT /api/v1/config` with `trusted_proxies` when exposed by the caller, or engine reload from an updated config snapshot | Updates client-IP extraction trust rules in the engine. |
| Upstreams, routes, and virtual hosts | `PUT /api/v1/routing` or `POST /api/v1/config/reload` after an in-memory routing change | Prepares a complete candidate router, reloads and atomically persists the config, then swaps the router and request handler together. New health checkers start on the candidate; old health checkers/transports close after commit. In-flight requests continue on the previous handler. |
| Custom rules | Dashboard rules API | Reloads the engine config and persists the rule set through the dashboard save callback. |
| IP ACL and auto-bans | Dashboard/API IP ACL and ban endpoints | Mutates the active IP ACL layer state directly; configured persistence flushes on its normal interval and shutdown. |
| Alert webhook/email definitions | Dashboard alerting APIs | Updates and persists config, but currently running alert manager instances are created at startup; restart after changing alert delivery topology if immediate delivery behavior must change. |
| TLS certificate file contents | Certificate file watcher | Existing certificate paths are polled and reloaded when file contents change. |
| Docker-discovered routing | Docker watcher | Rebuilds the proxy router from discovered services and stops old health checkers/transports. |

## Restart Required

Restart GuardianWAF for changes that affect listeners, process-level background services, or startup-only dependencies:

- `listen`, `tls.listen`, HTTP/3/QUIC listener settings, and dashboard listen address.
- Enabling or disabling TLS, ACME, HTTP redirect behavior, or changing ACME account/cache settings.
- Enabling or disabling Docker discovery itself, changing Docker socket/network settings, or changing poll interval.
- Enabling or disabling AI analysis, alerting manager, tenant runtime, MCP transport, tracing, compliance engine, SIEM exporter, cluster sync, or other startup-owned background services.
- Event store mode or event file path.
- GeoIP auto-download settings or DB path when the GeoIP layer must be mandatory for the deployment profile.
- WAF layer topology or layer-instance configuration, including layer `enabled` flags, detector enabled flags/multipliers, rate-limit rules, sanitizer URL/header/cookie limits, bot-detection settings, CORS policy, threat-intel feeds, API-security settings, CRS paths, virtual-patch settings, DLP settings, client-side protection settings, and response-layer settings.
- Any other change that needs new layer construction rather than changing values read by an already-running layer.

## API Semantics

`POST /api/v1/config/reload` re-applies the current in-memory engine configuration and, when the serve runtime has a routing controller, rebuilds proxy routing from that engine snapshot. It does not reread the YAML file from disk.

`PUT /api/v1/config` accepts a JSON patch for supported top-level and WAF fields, reloads the engine snapshot, and persists through the dashboard save callback when configured. It does not recreate startup-owned services. If the patch would change WAF layer topology or layer-instance configuration, the dashboard returns `409 Conflict` and leaves the active config unchanged. If persistence fails, the endpoint returns `500`, restores the previous runtime snapshot, and never reports a non-durable success.

`PUT /api/v1/routing` is the supported live path for upstream, route, and virtual-host changes because it validates routing references and performs an all-or-nothing candidate build. A target/DNS validation, engine reload, or atomic config write failure returns `500`, closes candidate resources, and leaves the previous proxy and engine routing active. The request handler and router pointer commit in the same critical section only after persistence succeeds.

Dashboard persistence uses the resolved explicit or platform-default config path. A read-only mount, directory-based composite config, missing parent directory, or disk failure therefore rejects and rolls back the mutation instead of leaving runtime and restart state divergent.

GuardianWAF does not currently install a SIGHUP config reload handler in serve or sidecar mode. Use the REST/dashboard API for supported runtime updates, or restart the process after updating the config file.

## Operational Rule

For production rollouts, classify each change before applying it:

1. Use dashboard/API endpoints for request-policy tuning and routing changes listed as supported without restart.
2. Use a rolling restart for listener, storage, background service, or layer-topology changes.
3. After a live routing update, verify `/readyz` and upstream metrics before shifting additional traffic.
4. After a restart-required change, verify `/livez`, `/readyz`, `/metrics`, alert delivery, and dashboard health before considering the rollout complete.
