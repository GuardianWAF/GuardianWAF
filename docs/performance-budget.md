# GuardianWAF Performance Budget

This document defines release performance budgets and the benchmark evidence required before claiming a production release is ready.

## Release Evidence

Every release candidate must include benchmark output generated with:

```bash
./scripts/benchmark.sh 5
```

For focused release notes, run the named production budget suite:

```bash
BENCH='BenchmarkEngine_(BenignRequest|AttackRequest|LargeHeaders|LargeBody|GzipBody|DeflateBody|FullPipeline_MultiParam|Parallel)$|BenchmarkRouteLookup_ManyRoutes$|BenchmarkTenantResolve_ManyTenants$|BenchmarkEventStore_HighEventRate$' \
  PACKAGES='./tests/integration ./internal/tenant' \
  ./scripts/benchmark.sh 5
```

The script writes `benchmark_results.txt` and records the timestamp, Go version, `GOOS`, `GOARCH`, CPU count, kernel, benchmark pattern, `benchtime`, count, and package set. Release notes must include the measured environment and the benchmark rows used to support the release.

For local standalone and sidecar proxy load evidence, run:

```bash
./scripts/proxy-load-test.sh
```

For target deployment environment evidence, measure a backend URL and the deployed GuardianWAF proxy URL with:

```bash
TARGET_BACKEND_URL=https://backend.example.com/healthz \
TARGET_STANDALONE_URL=https://waf.example.com/healthz \
TARGET_LABEL=prod-us-east-1 \
./scripts/target-load-evidence.sh
```

The latest local release-candidate runs are recorded in [Release Performance Evidence](release-performance-evidence.md). Treat the Go benchmarks as regression evidence for the named in-process paths and the proxy load test as local HTTP p95/p99 evidence against a loopback backend. Hosted runner and deployment-environment measurements from `target_load_results.txt` should still be captured before a stable production tag.

The strict release evidence verifier enforces p99 overhead budgets for both local `proxy_load_results.txt` and target deployment `target_load_results.txt`: standalone proxy `overhead_p99_ms` must be lower than `5 ms`, sidecar proxy `overhead_p99_ms` must be lower than `3 ms`, and every load-test `errors=` line must be zero. If a target environment intentionally accepts higher overhead, attach an explicit release risk acceptance instead of bypassing the verifier.

## Budgets

Budgets are stated as WAF processing overhead measured in-process unless the deployment mode explicitly includes proxy/network behavior. Wall-clock budgets are not enforced under `-race`.

| Deployment mode | Scenario | Release budget | Evidence benchmark |
|---|---|---:|---|
| Library middleware | Clean request | p99 < 1 ms, 0 unexpected blocks | `TestLoadTest_BenignTraffic`, `BenchmarkEngine_BenignRequest` |
| Library middleware | Attack-heavy request | p99 < 2 ms for detector processing | `BenchmarkEngine_AttackRequest`, `BenchmarkEngine_FullPipeline_MultiParam` |
| Library middleware | Large headers | p99 < 5 ms with 100 bounded headers | `BenchmarkEngine_LargeHeaders` |
| Library middleware | Large body inspection | p99 < 25 ms at default 10 MiB inspection cap | `BenchmarkEngine_LargeBody` |
| Library middleware | gzip body inspection | p99 < 35 ms, decompressed data still capped | `BenchmarkEngine_GzipBody` |
| Library middleware | deflate body inspection | p99 < 35 ms, decompressed data still capped | `BenchmarkEngine_DeflateBody` |
| Standalone proxy | Clean HTTP proxy path | p99 < 5 ms plus upstream RTT | CLI smoke plus release load test |
| Sidecar proxy | Clean local backend path | p99 < 3 ms plus upstream RTT | CLI sidecar smoke plus release load test |
| Routing | 100 virtual hosts x 100 routes | lookup p99 < 1 ms | `BenchmarkRouteLookup_ManyRoutes` |
| Tenancy | 1000 tenants by host | resolve p99 < 1 ms | `BenchmarkTenantResolve_ManyTenants` |
| Events | High event write rate | no unbounded growth, drops observable | `BenchmarkEventStore_HighEventRate`, `guardianwaf_event_store_dropped_total` |

If a budget is missed, release notes must either document the regression as a known issue with mitigation, or the release must be held until the regression is fixed.

## Required Benchmark Scenarios

The production benchmark set covers:

- Clean traffic: `BenchmarkEngine_BenignRequest` and `TestLoadTest_BenignTraffic`.
- Attack-heavy traffic: `BenchmarkEngine_AttackRequest`, `BenchmarkEngine_XSSRequest`, and `TestLoadTest_MixedTraffic`.
- Large headers: `BenchmarkEngine_LargeHeaders`.
- Large bodies: `BenchmarkEngine_LargeBody`.
- gzip bodies: `BenchmarkEngine_GzipBody`.
- deflate bodies: `BenchmarkEngine_DeflateBody`.
- Many routes: `BenchmarkRouteLookup_ManyRoutes`.
- Many tenants: `BenchmarkTenantResolve_ManyTenants`.
- High event rate: `BenchmarkEventStore_HighEventRate`.

## Operational Metrics

Production deployments must scrape these metrics for performance and overload visibility:

- `guardianwaf_request_duration_seconds` for P95/P99 request processing latency.
- `guardianwaf_layer_duration_seconds` for per-layer latency attribution.
- `guardianwaf_latency_avg_microseconds` for coarse current latency.
- `guardianwaf_event_store_dropped_total` for event drops and persistence failures.
- `guardianwaf_event_bus_dropped_total` for slow event subscribers that are losing event deliveries.
- `guardianwaf_event_bus_subscribers` for current event fan-out cardinality.
- `guardianwaf_upstream_active_connections` for proxy concurrency.
- `guardianwaf_upstream_circuit_state` for upstream circuit pressure.
- `guardianwaf_alert_manager_dropped_total` for alert dispatch backpressure.
- `guardianwaf_alert_manager_failed_total` and `guardianwaf_alert_email_failed_total` for alert delivery pressure.
- `guardianwaf_ai_pending_events`, `guardianwaf_ai_requests_current`, `guardianwaf_ai_tokens_used_current`, and `guardianwaf_ai_cost_usd_total` for AI provider pressure and budget tracking.

## Bounded Overload Contract

GuardianWAF should degrade by bounding, dropping, rejecting, or cleaning up overload state rather than growing memory without limit.

| Surface | Bound | Overload behavior | Operator signal |
|---|---|---|---|
| Request body inspection | Configured sanitizer max body size plus one byte for oversize detection | Inspection stops at the cap and records an oversize finding instead of buffering the full body | Request action counters and layer latency histograms |
| gzip and deflate inspection | Same sanitizer body cap after decompression | Decompression reads only enough bytes to classify oversize content | Request action counters and layer latency histograms |
| File event store channel | Fixed asynchronous write channel | New events can be dropped or counted as not persisted when the writer is full or closed | `guardianwaf_event_store_dropped_total` |
| Event bus fan-out | Fixed subscriber channels owned by consumers, capped at `guardianwaf_event_bus_max_subscribers` | Slow subscribers lose deliveries while request processing continues; new subscribers are rejected after the cap or after bus shutdown | `guardianwaf_event_bus_dropped_total`, `guardianwaf_event_bus_subscribers`, `guardianwaf_event_bus_rejected_subscriptions_total` |
| Alert dispatch | Fixed dispatch semaphore exposed as `guardianwaf_alert_manager_max_dispatch` and shutdown gate | Alerts are counted as dropped/failed when dispatch capacity is full or closed | `guardianwaf_alert_manager_dropped_total`, `guardianwaf_alert_manager_failed_total`, `guardianwaf_alert_manager_max_dispatch` |
| AI pending analysis | Validated `waf.ai_analysis.batch_size` range of 1-1000 plus provider usage windows | Suspicious events wait only in the bounded pending batch and provider limits stop further spend | `guardianwaf_ai_pending_events`, `guardianwaf_ai_requests_current`, `guardianwaf_ai_tokens_used_current` |
| Rate-limit per-IP buckets | Hard bucket cap plus periodic stale cleanup | New unseen bucket keys are denied by the zero-token overflow bucket after the cap; cleanup releases capacity | Request action counters, rate-limit findings, cleanup logs |
| ATO per-IP and per-email trackers | `maxEntries` for top-level maps and inner IP/email/password sets | New tracking records beyond the cap are dropped or oldest top-level mapping entries are evicted | ATO findings and cleanup logs |
| Tenant maps and request trackers | `maxTenants`, fixed sliding-window slots, and tenant-rate cleanup | Tenant creation is rejected at the cap; per-tenant request counters reuse fixed slots and cleanup removes idle trackers | Dashboard/API tenant errors and tenant quota alerts |

If any overload counter increases continuously for more than one scrape window, treat it as a production incident: reduce incoming load, add capacity, tune the relevant queue or retention setting, or disable the optional consumer that is falling behind.

## Release Notes Template

Use this shape in release notes:

```markdown
### Performance Evidence

Environment:
- Go:
- GOOS/GOARCH:
- CPU:
- Kernel:
- Command:

Budget results:
- Clean request:
- Attack request:
- Large headers:
- Large body:
- gzip body:
- deflate body:
- Many routes:
- Many tenants:
- High event rate:

Known performance risks:
- 
```
