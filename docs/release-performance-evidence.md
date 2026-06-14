# Release Performance Evidence

This document records the latest local release-candidate performance evidence. It complements the release budget in [Performance Budget](performance-budget.md).

## 2026-06-11 Local Proxy Load Test

Environment:

- Timestamp UTC: `2026-06-11T03:39:29Z`
- Go: `go version go1.26.4 linux/amd64`
- GOOS/GOARCH: `linux/amd64`
- CPU count: `16`
- Kernel: `Linux 7.0.0-22-generic x86_64 GNU/Linux`
- Requests: `1000`
- Concurrency: `20`
- Warmup requests per target: `50`
- Command:

```bash
./scripts/proxy-load-test.sh
```

The load test measures a direct local backend first, then standalone and sidecar proxy paths. The proxy overhead columns subtract direct backend p95/p99 latency from the proxy p95/p99 latency, matching the performance budget wording of proxy latency plus upstream RTT.

| Path | Errors | RPS | p95 | p99 | p95 overhead vs backend | p99 overhead vs backend |
|---|---:|---:|---:|---:|---:|---:|
| Direct backend | `0` | `491.28` | `42.030 ms` | `42.449 ms` | n/a | n/a |
| Standalone proxy | `0` | `475.67` | `42.993 ms` | `43.674 ms` | `0.963 ms` | `1.225 ms` |
| Sidecar proxy | `0` | `475.96` | `43.066 ms` | `43.526 ms` | `1.037 ms` | `1.077 ms` |

Result:

- Standalone local HTTP proxy overhead is within the `p99 < 5 ms plus upstream RTT` release budget.
- Sidecar local HTTP proxy overhead is within the `p99 < 3 ms plus upstream RTT` release budget.
- The script fails if any load-test request returns a non-200 response.

## 2026-06-11 Local Focused Benchmark

Environment:

- Timestamp UTC: `2026-06-11T03:30:44Z`
- Go: `go version go1.26.4 linux/amd64`
- GOOS/GOARCH: `linux/amd64`
- CPU: `AMD Ryzen 7 PRO 6850H with Radeon Graphics`
- CPU count: `16`
- Kernel: `Linux 7.0.0-22-generic x86_64 GNU/Linux`
- Command:

```bash
BENCH='BenchmarkEngine_(BenignRequest|AttackRequest|LargeHeaders|LargeBody|GzipBody|DeflateBody|FullPipeline_MultiParam|Parallel)$|BenchmarkRouteLookup_ManyRoutes$|BenchmarkTenantResolve_ManyTenants$|BenchmarkEventStore_HighEventRate$' \
  PACKAGES='./tests/integration ./internal/tenant' \
  ./scripts/benchmark.sh 5
```

The Go benchmark rows below are average time per operation. They are useful release-candidate regression evidence, but they do not replace external proxy/load tests for wall-clock p95/p99 behavior.

| Scenario | Benchmark | Worst avg/op across 5 runs | Worst allocation profile across 5 runs |
|---|---|---:|---:|
| Clean request | `BenchmarkEngine_BenignRequest` | `24.395 us/op` | `5919 B/op`, `72 allocs/op` |
| Attack request | `BenchmarkEngine_AttackRequest` | `28.659 us/op` | `5965 B/op`, `75 allocs/op` |
| Large headers | `BenchmarkEngine_LargeHeaders` | `50.872 us/op` | `30639 B/op`, `376 allocs/op` |
| Large body | `BenchmarkEngine_LargeBody` | `137.628 us/op` | `511832 B/op`, `142 allocs/op` |
| gzip body | `BenchmarkEngine_GzipBody` | `142.904 us/op` | `378293 B/op`, `101 allocs/op` |
| deflate body | `BenchmarkEngine_DeflateBody` | `130.024 us/op` | `376439 B/op`, `98 allocs/op` |
| Full pipeline multi-param | `BenchmarkEngine_FullPipeline_MultiParam` | `21.754 us/op` | `6126 B/op`, `90 allocs/op` |
| Parallel clean request | `BenchmarkEngine_Parallel` | `3.622 us/op` | `5633 B/op`, `72 allocs/op` |
| Many routes | `BenchmarkRouteLookup_ManyRoutes` | `1.033 us/op` | `0 B/op`, `0 allocs/op` |
| Many tenants | `BenchmarkTenantResolve_ManyTenants` | `0.1343 us/op` | `24 B/op`, `1 allocs/op` |
| High event rate | `BenchmarkEventStore_HighEventRate` | `0.1593 us/op` | `6 B/op`, `0 allocs/op` |

Bounded overload observations:

- The focused benchmark command includes both `./tests/integration` and `./internal/tenant`, so route, event, engine, body, compression, and tenant scale scenarios are all represented.
- Event-store overload is observable through `guardianwaf_event_store_dropped_total`.
- Event-bus fan-out pressure is observable through `guardianwaf_event_bus_dropped_total`, `guardianwaf_event_bus_subscribers`, `guardianwaf_event_bus_max_subscribers`, and `guardianwaf_event_bus_rejected_subscriptions_total`.
- Alert dispatch pressure is observable through `guardianwaf_alert_manager_dropped_total` and the fixed dispatch cap `guardianwaf_alert_manager_max_dispatch`.
- AI pending analysis pressure is observable through `guardianwaf_ai_pending_events`.
- Rate-limit, ATO, and tenant boundedness are covered by package regression tests for hard-cap cleanup, tracker caps, fixed sliding-window slots, and tenant map limits.

Remaining release evidence:

- Record hosted CI results for the same focused benchmark command when GitHub-hosted runner validation is available.
- Repeat the proxy load test in the target deployment environment with `./scripts/target-load-evidence.sh` before tagging a stable production release, then attach `target_load_results.txt` to the release evidence bundle.
