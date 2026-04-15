# ADR 0037: Request Recording and Replay

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

Reproducing production bugs and validating WAF rule changes requires real production traffic. Synthetic test suites cannot capture the full diversity of real-world requests. Two use cases drive this feature:

1. **Bug reproduction** — when a user reports a false positive or a missed attack, the original request is needed to reproduce and fix the issue
2. **Rule regression testing** — before deploying a new CRS version or custom rule update, replay recent production traffic through the new ruleset to measure false positive / true positive rate changes

Without a recording mechanism, engineers must reconstruct requests from incomplete log entries (headers are often omitted, bodies are truncated). A full request recorder captures all fields needed for exact replay.

The replay layer runs at **Order 145** (after cache at ~140, before detection) to record requests before WAF decisions are made, ensuring the recorded request is the raw input, not a post-decision view.

## Decision

Implement a request recorder and replayer (`internal/layers/replay/`) that:

1. **Records** requests to a rolling JSONL file (configurable sampling rate)
2. **Replays** recorded requests against a target WAF instance for regression testing
3. Applies **path and header filtering** to avoid recording sensitive endpoints

### Recording

The `Recorder` writes each sampled request to a JSONL file as a `RecordedRequest`:

```go
type RecordedRequest struct {
    ID          string            `json:"id"`
    Timestamp   time.Time         `json:"ts"`
    Method      string            `json:"method"`
    Path        string            `json:"path"`
    Query       string            `json:"query"`
    Headers     map[string]string `json:"headers"`    // Filtered
    Body        string            `json:"body"`        // Truncated at max_body_size
    ClientIP    string            `json:"client_ip"`
    TenantID    string            `json:"tenant_id"`
    WAFScore    int               `json:"waf_score"`   // Score at time of recording
    WAFAction   string            `json:"waf_action"`  // block | pass | challenge
}
```

**Sampling** uses a pseudo-random reservoir approach: each request has a `1/sample_rate` probability of being recorded. The sampler state is a single atomic counter with no mutex.

**Rolling files**: recordings rotate when the current file exceeds `max_file_size` (default: 100MB) or `max_age` (default: 24h). Old files beyond `max_files` are deleted.

**Filtering**: sensitive paths (`/api/login`, `/api/payment`) and headers (`Authorization`, `Cookie`, `X-API-Key`) are excluded by default. Body recording is disabled by default to avoid capturing passwords and PII.

### Replaying

The `Replayer` reads a JSONL recording file and replays each request against a target URL:

```bash
guardianwaf replay --file recordings/2026-04-15.jsonl --target http://localhost:9443 --rate 100
```

The replayer sends requests at the original inter-arrival timing (or a configurable rate override) and compares the WAF action in the response (`X-WAF-Action` header, added by the response layer) against the recorded WAF action. Divergences are reported:

```
[DIVERGENCE] req_abc123 was PASS, now BLOCK (score: 75)
  Path: /search?q=foo
  Detector: sqli (score: 75)
```

This output directly identifies which requests changed behaviour after a rule update.

### Dashboard Integration

- **Live recording toggle** — enable/disable recording from the dashboard
- **Recording file browser** — list, download, and delete recording files
- **Replay job launcher** — upload a recording file, select a target, start replay
- **Divergence report** — tabular view of divergences with before/after scores

### Configuration

```yaml
replay:
  enabled: false               # Off by default

  recording:
    output_dir: /var/lib/guardianwaf/recordings/
    sample_rate: 100           # Record 1 in N requests
    max_file_size: 104857600   # 100MB
    max_age: 24h
    max_files: 7               # Keep 7 days

    record_body: false         # Disabled by default (PII risk)
    max_body_size: 4096        # If enabled, truncate at this size

    exclude_paths:
      - /api/login
      - /api/register
      - /gwaf/*

    exclude_headers:
      - Authorization
      - Cookie
      - X-API-Key
      - Set-Cookie

  replay:
    default_rate: 0            # 0 = use original inter-arrival timing
    timeout: 10s
    parallel: 10               # Concurrent replay goroutines
```

## Consequences

### Positive
- Real production traffic corpus for regression testing is invaluable — a 1% sample over 24 hours captures millions of diverse requests
- Divergence reporting pinpoints exactly which requests change behaviour after a rule update, making WAF upgrades confident
- Sampling is zero-allocation (single atomic counter) — recording overhead is negligible even at high request rates

### Negative
- Even with `record_body: false` and header filtering, the recorded path and query string may contain sensitive data (tokens in URLs, PII in query params) — recordings must be treated as sensitive and deleted after use
- Replay requests arrive from a single IP (`127.0.0.1` if replayed locally), which may trigger rate limit or bot detection differently from the distributed original traffic
- Original WAF actions reflect the state at record time; replaying after a configuration change (e.g., new threshold) may produce expected divergences that appear as noise in the report

## Implementation Locations

**Note**: `internal/layers/replay/` package exists. The layer is not yet registered in the
main engine pipeline (`main.go`/`guardianwaf.go`). `Order 145` is not defined in
`internal/engine/layer.go`. Registration in the pipeline is pending.

| File | Purpose |
|------|---------|
| `internal/layers/replay/recorder.go` | Request sampling and JSONL file writing |
| `internal/layers/replay/replayer.go` | JSONL reading, HTTP replay, divergence comparison |
| `internal/layers/replay/layer.go` | WAF pipeline layer (Order 145) |
| `internal/config/config.go` | `ReplayConfig` struct |

## References

- [Netflix: Diffy — Traffic Replay for Regression Testing](https://github.com/opendiffy/diffy)
- [Go Reservoir Sampling](https://en.wikipedia.org/wiki/Reservoir_sampling)
- [ADR 0004: Pipeline Architecture](./0004-pipeline-architecture.md)
