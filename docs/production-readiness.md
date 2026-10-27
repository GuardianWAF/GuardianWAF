# Production Readiness

The single, maintained statement of what is production-ready, what is not, and
what remains. Dated reports and earlier roadmaps live in [history](history/README.md)
and are not kept current.

**As of:** 2026-10-27 · **Version line:** 0.6.x → 0.7.0

## Verdict

The standalone `serve` WAF core is suitable for controlled production use behind
a staged rollout (monitor mode first, then enforce per route). It is **not** yet
released as a signed, independently assessed stable version; see
[Exit criteria](#exit-criteria-for-a-stable-release).

## Scope

| Tier | Components | Meaning |
|---|---|---|
| **Stable** | Reverse proxy and router, the 16 pipeline layers, JS challenge, dashboard and admin API, TLS/SNI, ACME HTTP-01, event store, alerting, SIEM export, GeoIP, library mode for the layers it supports | Covered by regression tests and CI gates; breaking changes are called out in the changelog. |
| **Use with care** | Multi-tenancy, MCP server, Docker discovery, AI batch analysis, tracing (stdout and OTLP/HTTP exporters, W3C trace context), Raft clustering | Functional and tested, but larger trust surfaces or newer code paths; review the linked docs before enabling. Raft compacts its log every `cluster.snapshot_threshold` (default 10000) applied entries ([clustering](clustering.md#persistence--backup)). |
| **Removed in 0.7.0** | Compliance reporting, tenant billing plans and invoices | Rejected at config load; see [Removed sections](configuration.md#removed-sections). |

## Hardening landed in this cycle

Request path:

- Request bodies the WAF cannot decode are blocked with 400 and never forwarded
  on raw-byte inspection. This covers malformed or truncated streams, trailing
  junk, unsupported or stacked codings, and the former 100:1 ratio fallback.
- Decoded expansion is capped at max(100× wire size, 256 KiB); larger expansion
  is blocked with 413.
- Client IP resolution parses `ip:port` X-Forwarded-For entries. An unparsable
  entry stops the walk at the last trusted hop instead of letting a forged entry
  win.
- Upstreams receive the client X-Forwarded-For chain only from trusted proxies.
  X-Forwarded-Proto reflects the real scheme, and `Forwarded` is stripped.

Admin surface:

- Rotating the dashboard API key revokes all existing sessions.
- Failed `X-API-Key` attempts on the dashboard API, admin routes and MCP SSE
  share the login lockout: 5 failures in 5 minutes lock the source for 15 minutes.

Cluster:

- Unset Raft election and heartbeat timings are normalized. Zero timings
  previously caused an election storm with unbounded goroutine and memory growth.
- Raft log compaction now uses state-machine snapshots: compacted entries are
  dropped, the snapshot is persisted atomically, and lagging followers catch up
  via InstallSnapshot. AppendEntries batches are bounded.
- Ban expiry is fixed at proposal time, so log replay no longer resurrects
  expired bans.

Detection (each pinned by a regression test; see [detection quality](detection-quality.md)):

- Bypasses closed: urlencoded form bodies (`+` undecoded), JSON bodies scanned
  as raw text, URL-encoded cookies, application-defined headers
  (`X-Api-Key`, `X-Original-URL`, ...), home-directory secret files
  (`/root/.ssh/id_rsa`), and JavaScript string breakouts (`';alert(1)//`).
- False positives removed: every binary upload was blocked under the default
  `block_null_bytes`, multipart forms had a 35-point SQLi baseline, and SQL
  keywords, Windows paths and quoted English prose with `--` blocked.
- Large-body inspection is 1.3-2.8x faster (plain text 40 -> 14 ms, JSON
  20 -> 14 ms for the benchmark bodies).

Admin and tenancy:

- The dashboard audit log is hash-chained; `guardianwaf verify-audit` checks it.
- Tenant-scoped API keys get their own tenant's `/api/v1/stats`, no longer the
  process-wide counters and operator integration data.
- The plain-HTTP dashboard warning fires only for binds reachable off the host.

Observability:

- OTLP/HTTP trace export with a bounded, non-blocking queue and a dropped-span
  metric; incoming W3C `traceparent` is joined and propagated upstream.

Library mode:

- Library mode builds layers through the standalone registry builders, so it
  runs the same 11 detectors, API security and per-path body limits.
- The event ring buffer allocates as events arrive instead of reserving
  ~44 MB for the default 100,000-event capacity at startup.

## Known limits

- **Response masking** is not a DLP guarantee. Responses larger than 1 MiB,
  streamed or flushed responses, and unsupported encodings pass through
  unmasked.
- **Audit tamper evidence.** The dashboard audit log is a SHA-256 hash chain.
  Edits, insertions, deletions and reordering are detected, but truncating the
  newest entries is not unless the chain head was recorded off the host
  ([runbook §17](runbook.md)). SIEM export remains the off-host copy.
- **Detection quality** is measured on curated corpora, not production traffic.
  The end-to-end gate blocks 0 of 1724 benign requests and 0 of 138 developer
  posts quoting code, and 98.7% of 1648 attack requests
  ([detection quality](detection-quality.md)). Real applications differ: deploy
  in monitor mode and tune per application before enforcing.
- **Large-body inspection cost.** Detection runs at roughly 11 MB/s per core on
  JSON bodies (≈14 ms for 150 KB) and faster on forms. Keep
  `waf.sanitizer.max_body_size` and per-path overrides as small as each
  endpoint allows.
- **CRS and OpenAPI support are subsets.** Neither is full ModSecurity or full
  OpenAPI/JSON Schema compatibility.

## Remaining roadmap

| Priority | Item | Done when |
|---|---|---|
| P1 | Raft long-uptime soak | Multi-day cluster soak shows bounded WAL size and restart time with the default `cluster.snapshot_threshold` |
| P1 | Detection evidence | The CI gate (block FP < 1% general, < 5% technical, attacks >= 85% per class) is in place; remaining: gotestwaf / CRS regression results published, corpora grown with anonymized production traffic |
| P1 | Large-body inspection throughput | `BenchmarkEngine_LargeBody` p99 within the [performance budget](performance-budget.md) on release hardware |
| P2 | Test suite consolidation | Per-bug regression files consolidated by theme |

Closed this cycle: OTLP trace exporter, hash-chained audit log, tenant test
cost (234 s -> 5 s), and the startup guard. The guard was decided as a
warning, not a refusal: the shipped config and container deployments bind
`:9443` behind a TLS-terminating proxy, so refusing would break them.

## Exit criteria for a stable release

- `main` CI green for two consecutive weeks, including the nightly race job.
- No open P1 security findings.
- A signed release with SBOM and provenance, produced by the release workflow
  ([release checklist](release-checklist.md)).
- Target-environment load test within the p99 overhead budget
  ([release performance evidence](release-performance-evidence.md)).
- Published detection-quality results meeting the FP gate above.
- An independent security review of the request path and admin surface.
