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
| **Use with care** | Multi-tenancy, MCP server, Docker discovery, AI batch analysis, tracing (stdout/noop exporters only), Raft clustering | Functional and tested, but larger trust surfaces or newer code paths; review the linked docs before enabling. Raft compacts its log every `cluster.snapshot_threshold` (default 10000) applied entries ([clustering](clustering.md#persistence--backup)). |
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

Library mode:

- Library mode builds layers through the standalone registry builders, so it
  runs the same 11 detectors, API security and per-path body limits.

## Known limits

- **Response masking** is not a DLP guarantee. Responses larger than 1 MiB,
  streamed or flushed responses, and unsupported encodings pass through
  unmasked.
- **Audit tamper evidence.** The dashboard audit log is append-only JSONL, not
  hash-chained. Fingerprint exports into write-once storage and use SIEM export
  as the off-host copy ([runbook §17](runbook.md)).
- **Detection quality** has only been measured on small corpora. Block-level
  false positives are 0–8% depending on corpus ([detection quality](detection-quality.md)).
  Deploy in monitor mode and tune per application before enforcing.
- **Large-body inspection cost.** Detection runs at roughly 10 MB/s per core on
  JSON bodies (≈15 ms for 150 KB). Keep `waf.sanitizer.max_body_size` and
  per-path overrides as small as each endpoint allows.
- **CRS and OpenAPI support are subsets.** Neither is full ModSecurity or full
  OpenAPI/JSON Schema compatibility.

## Remaining roadmap

| Priority | Item | Done when |
|---|---|---|
| P1 | Raft long-uptime soak | Multi-day cluster soak shows bounded WAL size and restart time with the default `cluster.snapshot_threshold` |
| P1 | Detection quality gate | Benign corpus of thousands of samples; block FP < 1% enforced in CI; gotestwaf / CRS regression results published |
| P1 | Large-body inspection throughput | Profile-driven work on per-field scanning; LargeBody p99 within the [performance budget](performance-budget.md) |
| P2 | Hash-chained dashboard audit log | Tamper evidence without relying on external fingerprints |
| P2 | Production-profile startup guard | Refuse non-loopback plain-HTTP dashboard unless explicitly acknowledged |
| P2 | Test suite cost | Tenant package under 60 s (PBKDF2 cost in tests), per-bug regression files consolidated by theme |
| P3 | OTLP trace exporter | Traces reach a standard collector without custom code |

## Exit criteria for a stable release

- `main` CI green for two consecutive weeks, including the nightly race job.
- No open P1 security findings.
- A signed release with SBOM and provenance, produced by the release workflow
  ([release checklist](release-checklist.md)).
- Target-environment load test within the p99 overhead budget
  ([release performance evidence](release-performance-evidence.md)).
- Published detection-quality results meeting the FP gate above.
- An independent security review of the request path and admin surface.
