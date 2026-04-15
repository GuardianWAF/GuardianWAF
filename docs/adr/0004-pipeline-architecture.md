# ADR 0004: Pipeline Architecture

**Date:** 2026-04-15
**Status:** Accepted
**Deciders:** GuardianWAF Team

---

## Context

A WAF must process requests through multiple independent checks — IP ACL, rate limiting, CORS, custom rules, CRS, detection (SQLi, XSS, LFI, etc.), bot detection, virtual patching, DLP, and response hardening — in a well-defined order. Some layers depend on the results of earlier layers (e.g., the Sanitizer must normalize input before the Detection layer analyzes it). The pipeline must also:

- **Short-circuit on block** — once a request is determined to be malicious, no further layers should run (saves CPU, reduces latency for blocked requests)
- **Accumulate scores** — multiple low-confidence findings from different layers may collectively indicate an attack even if no single layer's threshold is met
- **Support exclusions** — some paths should bypass specific detectors (e.g., `/api/health` should not trigger SQLi detection even if it contains SQL keywords)
- **Be extensible** — operators should be able to add new layers without modifying the engine

The naive approach — a single function with a long `if/else` chain — becomes unmaintainable at 20+ layers and makes testing each layer in isolation difficult.

## Decision

Implement a **layer pipeline** (`internal/engine/pipeline.go`) where each layer implements the `Layer` interface and is sorted by an `Order` constant at construction time.

### Layer Interface

```go
// Layer is implemented by every WAF processing layer.
type Layer interface {
    Name() string                               // Unique layer name (e.g., "ipacl", "sqli")
    Process(ctx *RequestContext) LayerResult    // Process one request; returns result
}

// OrderedLayer wraps a Layer with its execution order constant.
type OrderedLayer interface {
    Layer
    Order() int // Lower values execute first
}

// LayerResult is returned by each layer's Process method.
type LayerResult struct {
    Action   Action // ActionPass, ActionBlock, ActionLog, ActionChallenge
    Findings []Finding
}
```

### Pipeline Execution

```go
func (p *Pipeline) Execute(ctx *RequestContext) PipelineResult {
    result := PipelineResult{Action: ActionPass}

    for _, ol := range layers { // sorted by Order ascending
        if shouldSkip(ol.Layer, ctx) {
            continue
        }

        lr := ol.Layer.Process(ctx)
        ctx.Accumulator.AddMultiple(lr.Findings) // accumulate scores

        switch lr.Action {
        case ActionBlock:
            return result.withBlock(lr.Findings) // short-circuit
        case ActionLog:
            if result.Action == ActionPass {
                result.Action = ActionLog
            }
        case ActionChallenge:
            if result.Action == ActionPass {
                result.Action = ActionChallenge
            }
        }
    }
    return result
}
```

### Short-Circuit Semantics

```
Layer 100 (IP ACL)    → ActionPass → continue
Layer 125 (Threat Intel) → ActionLog → continue (pass still possible)
Layer 200 (Rate Limit) → ActionBlock → STOP, return immediately
         ↑ remaining layers (300-600) NEVER execute
```

Only `ActionBlock` causes immediate short-circuit. `ActionLog` is recorded but does not stop execution. `ActionChallenge` applies only if the current action is still `ActionPass` (block takes priority).

### RequestContext Pool

`RequestContext` is the sole vessel for per-request state. It is pooled via `sync.Pool` to minimize GC pressure on the hot path:

```go
// AcquireContext obtains a RequestContext from the pool.
func AcquireContext(w http.ResponseWriter, r *http.Request) *RequestContext {
    ctx := ctxPool.Get().(*RequestContext)
    ctx.reset()              // zero all fields
    ctx.Request = r
    ctx.StartTime = time.Now()
    ctx.RequestID = generateRequestID()
    // ... parse headers, decompress body, extract client IP
    return ctx
}

// ReleaseContext returns a RequestContext to the pool.
func ReleaseContext(ctx *RequestContext) {
    ctx.reset()           // clear all fields (NOT zero-alloc; fields are set to zero/nil)
    ctxPool.Put(ctx)
}
```

### ScoreAccumulator

Each `Finding` has a `Score` field (0–100). The `ScoreAccumulator` maintains a running total:

```go
type ScoreAccumulator struct {
    mu      sync.Mutex
    scores  map[string]int      // detector name → score
    total   int
}

func (a *ScoreAccumulator) Add(f Finding) {
    a.mu.Lock()
    defer a.mu.Unlock()
    a.scores[f.Detector] += f.Score
    a.total += f.Score
}

func (a *ScoreAccumulator) Total() int {
    a.mu.Lock()
    defer a.mu.Unlock()
    return a.total
}
```

After all layers complete, `PipelineResult.TotalScore` is compared against the configured thresholds (block ≥ 50, log ≥ 25).

### Exclusion Matching

Detector layers can be selectively skipped for specific path prefixes:

```go
type Exclusion struct {
    PathPrefix string   // e.g., "/api/webhook"
    Detectors  []string // e.g., ["sqli", "xss"]
}
```

Exclusion matching uses `ctx.NormalizedPath` when available (written by the Sanitizer layer at Order 300), falling back to `ctx.Path` for layers that run before the Sanitizer. Using `NormalizedPath` prevents evasion via path traversal (`/api/webhook/../../etc/passwd`).

## Consequences

### Positive

- **Explicit ordering** — `Order()` constants in each layer's type declaration make the execution sequence self-documenting; adding a layer means choosing an order constant, not inserting into a chain
- **Independent testability** — each layer can be unit tested with a mock `RequestContext` without starting the full engine
- **Short-circuit efficiency** — blocked requests stop at the earliest possible layer; a request blocked at the IP ACL layer never touches the SQLi or XSS detectors
- **Per-layer scoring** — each `Finding` is tagged with its detector; the dashboard can show per-detector score breakdowns
- **Hot-reload friendly** — adding or removing layers calls `Pipeline.AddLayer()` which re-sorts in place; no restart required
- **Exclusion granularity** — path-prefix exclusions are checked per-detector, not per-layer, allowing fine-grained control (e.g., skip SQLi on `/api/health` but still check XSS)

### Negative

- **Sequential execution** — all layers run on the same goroutine; there is no parallelism within a single request's pipeline (parallelism is at the connection level via Go's HTTP server)
- **Order constant management** — constants must be manually chosen to avoid collisions and maintain logical grouping; there is no automated collision detection
- **Statelessness assumption** — layers are expected to be stateless; any per-layer state (e.g., rate limit buckets) must be stored externally (in the `RequestContext.Metadata` map or in a dedicated subsystem)
- **No conditional branching** — unlike a rules engine, there is no `if-then-else` or `when` construct; a layer always runs for every request unless explicitly excluded

### Layer Order Reference

| Order | Layer | Runs Before |
|-------|-------|-------------|
| 95 | Canary | IP ACL |
| 100 | IP ACL | Threat Intel |
| 125 | Threat Intel | CORS, Custom Rules |
| 145 | Replay | Sanitizer |
| 150 | CORS, Custom Rules | Rate Limit |
| 200 | Rate Limit | ATO Protection |
| 250 | ATO Protection | API Security |
| 275 | API Security | API Validation |
| 280 | API Validation | CRS |
| 300 | Sanitizer | CRS |
| 350 | CRS | Detection |
| 400 | Detection | Virtual Patch |
| 450 | Virtual Patch | DLP |
| 475 | DLP | Bot Detection |
| 500 | Bot Detection | Client-Side |
| 590 | Client-Side | Response |
| 600 | Response | *(last)* |

## Implementation Locations

| File | Purpose |
|------|---------|
| `internal/engine/pipeline.go` | Pipeline struct, Execute(), AddLayer(), SetExclusions() |
| `internal/engine/layer.go` | Layer interface, OrderedLayer struct, LayerResult, Action, Finding, LayerOrder constants (100–600, 16 defined) |
| `internal/engine/context.go` | RequestContext struct, AcquireContext(), ReleaseContext() |
| `internal/engine/finding.go` | ScoreAccumulator, Add(), AddMultiple(), Total() |

## References

- [ADR 0001: Zero External Go Dependencies](./0001-zero-external-dependencies.md)
- [ADR 0033: Request Sanitizer](./0033-request-sanitizer.md) — writes Normalized* fields read by Detection
