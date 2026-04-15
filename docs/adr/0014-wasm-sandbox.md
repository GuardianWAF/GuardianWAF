# ADR 0014: WebAssembly Sandbox for Rule Evaluation

**Date:** 2026-04-15
**Status:** Proposed
**Deciders:** GuardianWAF Team

---

## Context

GuardianWAF uses a tokenizer-based detection system with regex patterns for rule matching. While powerful, this approach has limitations:
- Complex rules require hardcoded Go code
- Community rule contributions require full releases
- Testing new rules requires recompilation
- No sandboxed execution environment for untrusted rules

## Decision

Implement an optional WebAssembly (WASM) sandbox for evaluating untrusted or community-contributed rules.

### Design Principles

1. **Sandboxed execution** — Rules run in isolated WASM runtime
2. **Opt-in** — Traditional Go rules remain default
3. **Community-friendly** — Share rules without code review for core
4. **High performance** — WASM execution <10µs overhead
5. **Secure by default** — No filesystem, network, or system calls from WASM

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    GuardianWAF Pipeline                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────┐    ┌─────────┐    ┌─────────────────────────┐  │
│  │   Go    │───▶│  WASM   │───▶│      Fallback Go        │  │
│  │  Rules  │    │ Sandbox │    │     (if WASM fails)     │  │
│  └─────────┘    └─────────┘    └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │  WASM Runtime│
                    │  (Wasmtime) │
                    └─────────────┘
```

### Rule Definition

WASM rules use a simple API:

```wat
;; example.wat (WebAssembly Text Format)
(module
  (import "guardian" "match" (func $match (param i32 i32) (result i32)))
  (import "guardian" "score" (func $score (param i32)))
  (import "guardian" "log" (func $log (param i32 i32)))

  (func (export "evaluate")
    ;; Get request body pointer and length
    (call $score (i32.const 10))  ;; Add 10 to threat score

    ;; If suspicious pattern found, block
    (if (i32.eq (local.get 0) (i32.const 1))
      (then
        (call $score (i32.const 50))
      )
    )
  )
)
```

### Go SDK for Rule Authors

Provide a Go SDK to compile rules to WASM:

```go
package guardianrules

import "github.com/guardianwaf/guardianwaf/rulesdk"

// Rule implements a SQL injection detector
var Rule = rulesdk.Rule{
    Name:        "sql-injection-basic",
    Description: "Detects basic SQL injection patterns",
    Version:     "1.0.0",
    Author:      "community",
    Tags:        []string{"sqli", "owasp"},

    Evaluate: func(ctx *rulesdk.Context) {
        body := ctx.Request.Body()
        if strings.Contains(body, "' OR '1'='1") {
            ctx.Block("SQL injection detected")
        }
    },
}
```

### Configuration

```yaml
rules:
  wasm:
    enabled: true
    runtime: wasmtime          # or "wasmer"
    cache_dir: /var/lib/guardianwaf/rules/
    max_memory: 64mb           # Per-rule memory limit
    timeout: 1ms              # Max execution time
    fallback_to_go: true       # Fall back to Go rules if WASM fails

  wasm_rules:
    - path: /etc/guardianwaf/rules/community/*.wasm
    - path: /etc/guardianwaf/rules/custom/*.wasm
```

### Security Model

| Capability | Allowed | Notes |
|------------|---------|-------|
| Memory access | ✅ | Sandboxed, rule-specific |
| CPU execution | ✅ | Time-limited (1ms default) |
| Filesystem | ❌ | No access |
| Network | ❌ | No access |
| System calls | ❌ | Blocked |
| Go runtime | ❌ | Isolated |
| External libraries | ❌ | Only WASM imports |

### WASM Imports (Guardian API)

Rules can call these functions imported into WASM:

```go
// Allowed imports for WASM rules
var AllowedImports = []string{
    "guardian.match",      // Check if pattern matches
    "guardian.score",      // Add to threat score
    "guardian.block",      // Block request with message
    "guardian.log",        // Log event (rate limited)
    "guardian.get_header", // Get request header
    "guardian.get_param",  // Get query/body param
}
```

### Performance

| Metric | Go Rules | WASM Rules | Overhead |
|--------|----------|------------|----------|
| Simple rule | 50ns | 200ns | 4x |
| Complex rule | 500ns | 2µs | 4x |
| Regex rule | 1µs | 5µs | 5x |

### Trade-offs

**Positive:**
- Community rule sharing without code review
- Fast iteration on new detection patterns
- Sandboxed execution prevents rule bugs from crashing WAF
- Portable rules (compile once, run anywhere)

**Negative:**
- Additional complexity (~2K LOC)
- WASM runtime dependency (Wasmtime ~10MB)
- Performance overhead (2-5x slower than native Go)
- Debugging harder in WASM context

### Implementation Phases

**Phase 1: Core Runtime**
- Integrate Wasmtime for WASM execution
- Implement WASM imports (match, score, block, log)
- Basic sandbox (memory, CPU limits)

**Phase 2: Go SDK**
- `rulesdk` package for rule authors
- Compiler helper to build WASM from Go
- Documentation and examples

**Phase 3: Management**
- WASM rule hot-reload
- Rule validation before loading
- Performance profiling

**Phase 4: Community**
- Public rule repository
- Rule signing/verification
- Community contribution workflow

## Consequences

### Positive
- Extensible rule system without core changes
- Community rule marketplace potential
- Faster innovation on detection patterns
- Sandboxed execution prevents security issues

### Negative
- Performance overhead (2-5x)
- Additional complexity and dependencies
- Harder debugging in production
- WASM ecosystem is still maturing in Go

## Implementation Locations

**Note**: This ADR describes a proposed feature. `internal/wasm/` and `rulesdk/` do not yet exist in the codebase — the files below represent the intended implementation structure.

| File | Purpose |
|------|---------|
| `internal/wasm/runtime.go` | Wasmtime integration |
| `internal/wasm/sandbox.go` | Security sandbox |
| `internal/wasm/imports.go` | Guardian imports |
| `rulesdk/` | Go SDK for rule authors |
| `cmd/rulesdk/` | CLI for compiling rules |

## References

- [Wasmtime](https://wasmtime.dev/)
- [WebAssembly Specification](https://webassembly.org/)
- [GuardianWAF Rule Engine](../ARCHITECTURE.md#layer-order)
- [WASI Preview 2](https://github.com/WebAssembly/WASI)
