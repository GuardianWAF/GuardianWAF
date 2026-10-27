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
| **Use with care** | Multi-tenancy, MCP server, Docker discovery, AI batch analysis, tracing (stdout/noop exporters only) | Functional and tested, but larger trust surfaces; review the linked docs before enabling. |
| **Not production-ready** | Raft clustering at long uptimes | The WAL has no state-machine snapshot or log truncation, so history grows with writes and is replayed on restart. Gossip/peer sync for bans and rules is unaffected. |
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

Library mode:

- Library mode builds layers through the standalone registry builders, so it
  runs the same 11 detectors, API security and per-path body limits.

## Known limits

- **Response masking** is not a DLP guarantee. Responses larger than 1 MiB,
  streamed or flushed responses, and unsupported encodings pass through
  unmasked.
- **Audit tamper evidence.** The dashboard audit log is a SHA-256 hash chain.
  Edits, insertions, deletions and reordering are detected, but truncating the
  newest entries is not unless the chain head was recorded off the host
  ([runbook §17](runbook.md)). SIEM export remains the off-host copy.
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
| P1 | Raft state-machine snapshot, log truncation and InstallSnapshot | Long-running cluster soak shows bounded WAL size and restart time |
| P1 | Detection quality gate | Benign corpus of thousands of samples; block FP < 1% enforced in CI; gotestwaf / CRS regression results published |
| P1 | Large-body inspection throughput | Profile-driven work on per-field scanning; LargeBody p99 within the [performance budget](performance-budget.md) |
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
