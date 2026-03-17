# IMPLEMENTATION.md — GuardianWAF Architecture & Implementation Guide

**Author:** Ersin Koc / ECOSTACK TECHNOLOGY OU
**Module:** `github.com/guardianwaf/guardianwaf`
**Go Version:** 1.22+
**Date:** 2026-03-16

> This document bridges the "what" (SPECIFICATION.md) to the "how" (TASKS.md). It records
> every architecture decision, algorithm choice, data structure selection, and performance
> trade-off together with the rationale behind each non-obvious decision.

---

## Table of Contents

1. [Guiding Principles](#1-guiding-principles)
2. [Core Data Structures](#2-core-data-structures)
3. [Algorithm Choices](#3-algorithm-choices)
4. [Concurrency Model](#4-concurrency-model)
5. [Memory Management](#5-memory-management)
6. [Configuration System](#6-configuration-system)
7. [Reverse Proxy Design](#7-reverse-proxy-design)
8. [TLS Implementation](#8-tls-implementation)
9. [Dashboard Architecture](#9-dashboard-architecture)
10. [MCP Server Implementation](#10-mcp-server-implementation)
11. [Performance Optimization Strategy](#11-performance-optimization-strategy)
12. [Error Handling Strategy](#12-error-handling-strategy)
13. [Security Considerations](#13-security-considerations)
14. [Testing Architecture](#14-testing-architecture)
15. [Package Dependency Graph](#15-package-dependency-graph)

---

## 1. Guiding Principles

Every decision in this document is filtered through four non-negotiable principles.
When two principles conflict, the list order is the tiebreaker.

| # | Principle | Implication |
|---|-----------|-------------|
| 1 | **Zero external dependencies** | Every parser, data structure, cryptographic flow, and protocol handler is built from Go stdlib only. The allowed import set is fixed (see SPECIFICATION.md Section "Non-Negotiable Rules"). No exceptions. |
| 2 | **Performance-first** | < 1 ms p99 total pipeline latency for clean requests. Every allocation on the hot path must be justified. Benchmark regressions fail CI. |
| 3 | **Modularity** | Each layer is an independent package behind a common interface. Any layer can be disabled, replaced, or tested in isolation without touching the others. |
| 4 | **Safety** | No panics in production. No goroutine leaks. Graceful degradation when a layer errors. Clear, bounded resource usage. |

**Why this order?** Dependencies are the hardest constraint to relax after the fact — once
you import a library your entire supply chain changes. Performance is next because a WAF
that adds visible latency will be disabled in production. Modularity enables long-term
maintenance. Safety is table-stakes but comes last because the other three constrain how
we achieve it.

---

## 2. Core Data Structures

### 2.1 RequestContext

`RequestContext` is the single object that flows through every layer of the pipeline.
It is the hot-path data structure — every microsecond and every allocation here matters.

```
internal/engine/context.go
```

**Fields:**

```go
type RequestContext struct {
    // Original request — read-only after construction
    Request       *http.Request   // stdlib request; never modified
    RemoteIP      net.IP          // parsed once at construction
    TLSInfo       *TLSInfo        // JA3 hash, TLS version, cipher (nil if plain HTTP)

    // Normalized copies — written by sanitizer, read by detectors
    NormalizedPath   string
    NormalizedQuery  map[string][]string  // pre-allocated capacity 16
    DecodedBody      []byte              // URL-decoded, null-stripped body
    BodyContentType  ContentType          // enum: FormData, JSON, XML, Raw, None

    // Pipeline results — written by layers
    Findings     []Finding         // pre-allocated capacity 8, grows if needed
    TotalScore   int
    Action       Action            // enum: Allow, Log, Block
    BlockReason  string            // human-readable, set by the blocking layer

    // Timing
    StartTime    time.Time
    LayerTimings [6]time.Duration  // one slot per layer, indexed by LayerID

    // Identifiers
    RequestID    string            // 16-byte hex, generated at construction

    // Internal bookkeeping (not exported)
    recycled     bool              // guard against double-return to pool
}
```

**Design decisions:**

| Decision | Rationale | Alternatives Considered |
|----------|-----------|------------------------|
| Pre-allocate via `sync.Pool` | Eliminates a ~200-byte heap allocation per request. At 50K RPS that is 10 MB/s of GC pressure removed. | Fresh allocation per request — simpler but GC cost unacceptable. |
| Fixed-size `LayerTimings [6]time.Duration` | Array lives inline in the struct (no pointer chase, no slice header). Six layers is a compile-time constant. | Slice — adds 24 bytes of header + pointer indirection. Map — absurd overhead. |
| `Findings` slice pre-allocated to cap 8 | Most requests produce 0 findings (clean traffic). Attacks rarely exceed 5-6 findings. Cap 8 covers 99.9% without re-allocation. The backing array is part of the pooled struct's associated buffer. | Linked list — poor cache locality. Channel — wrong abstraction. |
| `NormalizedQuery` map cap 16 | HTTP requests rarely carry more than 10-12 query params. Pre-allocated map avoids the first few grow-and-rehash cycles. | Flat `[][2]string` slice — faster iteration but O(n) lookup by key; detection layers look up specific params. |
| `net.IP` for RemoteIP | Stdlib type, directly usable with radix tree bit operations. Parsed once at construction, not per-layer. | `string` — requires re-parsing for CIDR comparison every time. `uint32/[16]byte` — loses IPv4/IPv6 abstraction. |

**Pool lifecycle:**

```
  ┌──────────────┐     Get()      ┌──────────────────┐
  │  sync.Pool   │ ─────────────► │  RequestContext   │
  │  (warm)      │                │  (zeroed fields)  │
  └──────────────┘                └────────┬─────────┘
                                           │
                         populate from *http.Request
                                           │
                                           ▼
                                  ┌──────────────────┐
                                  │  Layer 1 (IPACL) │
                                  │  Layer 2 (Rate)  │
                                  │  Layer 3 (Sanit) │
                                  │  Layer 4 (Detect)│
                                  │  Layer 5 (Bot)   │
                                  │  Layer 6 (Resp)  │
                                  └────────┬─────────┘
                                           │
                               reset + Put() back to pool
                                           │
                                           ▼
                                  ┌──────────────────┐
                                  │  sync.Pool       │
                                  │  (warm)          │
                                  └──────────────────┘
```

**Reset contract:** On return to the pool, every slice is resliced to length 0 (but
capacity preserved), every string is set to `""`, every pointer is set to nil, and
`recycled` is set to true. The `Get()` wrapper checks and resets `recycled` to false,
providing a double-free guard in debug builds.

---

### 2.2 Finding

A `Finding` records one piece of evidence from one detector during one request.

```go
type Finding struct {
    DetectorName string   // "sqli", "xss", "lfi", "cmdi", "xxe", "ssrf", "bot"
    RuleID       string   // e.g. "sqli-union-select", "xss-event-handler"
    Score        int      // 0-100, before multiplier
    Evidence     string   // truncated input snippet, max 128 bytes
    Location     Location // enum: Path, Query, Body, Header, Cookie
    MatchOffset  int      // byte offset in the scanned input
}
```

**Why evidence truncation (128 bytes)?**

1. **Log safety** — Full payloads in logs can exceed megabytes (e.g., a POST body).
   Truncated evidence provides enough context to understand the attack vector without
   creating a log-storage problem.
2. **Security** — Logging the full payload of a data-exfiltration attempt could
   ironically exfiltrate the data into the log system. Truncation bounds this risk.
3. **Performance** — String copying is proportional to length. Capping at 128 bytes
   keeps evidence generation allocation-free (fits in a small buffer from the pool).

**Why `MatchOffset`?** Enables the dashboard to highlight exactly where in the input the
detection triggered. Without it, the UI would have to re-run detection to show context.

---

### 2.3 Event

An `Event` is the persisted record of a WAF decision. It is written to the event store
(ring buffer or file) after the request completes.

```go
type Event struct {
    ID           string        // 16-byte hex, same as RequestContext.RequestID
    Timestamp    time.Time
    RemoteIP     string        // string form for serialization
    Method       string
    Path         string
    TotalScore   int
    Action       Action        // Allow, Log, Block
    Findings     []Finding     // copied from RequestContext
    ResponseCode int
    Latency      time.Duration // total pipeline time
    UserAgent    string        // truncated to 256 bytes
    TLSVersion   string        // "1.2", "1.3", or ""
    JA3Hash      string        // hex MD5, or ""
}
```

**Ring buffer storage (memory mode):**

```
  Index:  0   1   2   3   4   ...  N-1
        ┌───┬───┬───┬───┬───┐     ┌───┐
        │ E │ E │ E │ E │ E │ ... │ E │
        └───┴───┴───┴───┴───┘     └───┘
                      ▲
                      │
                    write cursor (atomic uint64)

  - Fixed capacity: configurable, default 100,000 events
  - Write: events[atomic.AddUint64(&cursor,1) % cap] = event
  - Read: iterate from (cursor-count) to cursor
  - No locks on write path (single-writer from event channel)
  - RWMutex for reads (dashboard queries)
```

**Why ring buffer over unbounded slice?** Bounded memory. At 100K events x ~200 bytes
serialized = ~20 MB. An unbounded slice would grow indefinitely and eventually OOM the
process.

**Why single-writer channel pattern?** The ring buffer write is not atomic (struct copy),
so concurrent writes would corrupt data. Funneling all writes through a single buffered
channel (cap 4096) serializes writes without requiring a mutex on the write path.

---

## 3. Algorithm Choices

### 3.1 YAML Parser (Custom Subset)

```
internal/config/yaml.go
```

**Why custom?** The zero-dependency constraint eliminates `gopkg.in/yaml.v3` and every
other third-party parser. Go's stdlib has `encoding/json` but no YAML support.

**Scope — what we support:**

| YAML Feature | Supported | Notes |
|-------------|-----------|-------|
| Scalar values (string, int, float, bool) | Yes | `true`/`false`/`yes`/`no` for bool |
| Quoted strings (`"..."`, `'...'`) | Yes | Double-quoted supports `\n`, `\t`, `\\` escapes |
| Unquoted strings | Yes | Terminated by `:`, `#`, newline |
| Maps (key: value) | Yes | Indentation-based nesting |
| Sequences (- item) | Yes | Indentation-based |
| Inline maps ({key: val}) | Yes | Needed for `sqli: { enabled: true, multiplier: 1.0 }` |
| Inline sequences ([a, b]) | Yes | Needed for `domains: []` and `methods: ["GET", "POST"]` |
| Comments (#) | Yes | Line-end and full-line |
| Nested structures | Yes | Arbitrary depth via indentation tracking |
| Empty values | Yes | `key:` with no value → empty string |
| Null | Yes | `~` or `null` → nil |
| Anchors (&) and aliases (*) | **No** | Not needed for guardianwaf.yaml |
| Tags (!!) | **No** | Not needed |
| Multi-document (---) | **No** | Single document only |
| Multiline scalars (\|, >) | **No** | Not needed for config format |

**Approach — line-by-line state machine:**

```
  ┌──────────────┐
  │  Read Line   │◄──────────────────────────────────┐
  └──────┬───────┘                                   │
         │                                           │
         ▼                                           │
  ┌──────────────┐    blank/comment                  │
  │ Trim + Check │───────────────────────────────────┤
  │ Indentation  │                                   │
  └──────┬───────┘                                   │
         │                                           │
         ▼                                           │
  ┌──────────────────┐   starts with "- "            │
  │ Classify Line    │──────────────► Sequence Item ──┤
  │                  │                                │
  │                  │   contains ": "                │
  │                  │──────────────► Map Entry ──────┤
  │                  │                                │
  │                  │   starts with "{"              │
  │                  │──────────────► Inline Map ─────┤
  │                  │                                │
  │                  │   starts with "["              │
  │                  │──────────────► Inline Seq ─────┘
  └──────────────────┘
```

The parser maintains an indentation stack. Each indent level corresponds to a nesting
level in the output tree. When indentation decreases, the parser pops back to the
appropriate parent node.

**Output type:** `map[string]any` tree (internal use only — the `any` restriction applies
to public APIs, not internal config parsing).

**Config struct population:** Manual field mapping, not reflection. Reflection would work
but adds ~5 us per field on startup (acceptable) and makes the code harder to follow. A
hand-written `populateConfig(tree map[string]any) (*Config, error)` function provides
compile-time type safety, clear error messages ("config.waf.detection.threshold.block
must be an integer"), and zero overhead at request time.

**Testing strategy:**
- Parse the full example `guardianwaf.yaml` from the spec, verify every field.
- Parse edge cases: empty file, comments-only, inline maps/sequences.
- Fuzz with `FuzzYAMLParser` — must never panic, always return an error or valid tree.
- Negative tests: invalid indentation, tabs mixed with spaces, unterminated quotes.

---

### 3.2 Radix Tree (IP ACL)

```
internal/layers/ipacl/radix.go
```

**Why radix tree over hash map?**

| Criterion | Hash Map | Radix Tree (Patricia Trie) |
|-----------|----------|---------------------------|
| Exact IP lookup | O(1) average | O(k), k=32 for IPv4 |
| CIDR range lookup | Impossible without expansion | O(k) — natural fit |
| Memory for /16 CIDR | 65,536 entries | 1 node |
| Memory for 10K mixed rules | ~800 KB | ~400 KB |
| Longest-prefix match | Not supported | Built-in |

CIDR support is essential — operators block entire subnets (`192.168.0.0/16`), not
individual IPs. A hash map would require expanding every CIDR into individual IPs,
which is both memory-prohibitive (a /8 = 16M entries) and semantically wrong (no
longest-prefix match).

**Implementation — compressed Patricia trie:**

```
  Root
   │
   ├─ 0: 10.0.0.0/8 (private, blocked)
   │   │
   │   └─ 10.0.1.0/24 (exception, allowed)
   │
   ├─ 1: ...
   │   │
   │   ├─ 10: 192.168.0.0/16 (blocked)
   │   │
   │   └─ 11: ...
   │       └─ 169.254.169.254/32 (cloud metadata, blocked)
   ...
```

Each node stores:

```go
type radixNode struct {
    children [2]*radixNode  // bit 0 and bit 1
    prefix   []byte         // compressed prefix bits
    prefLen  int            // number of bits in prefix
    value    *ACLEntry      // non-nil if this node is a rule endpoint
}
```

**Path compression:** Instead of one node per bit, consecutive bits with no branching
are stored as a prefix in a single node. This reduces tree depth from 32 (IPv4) to
typically 8-12 nodes for a real-world rule set, improving both memory and lookup speed.

**Dual tree:** Separate trees for IPv4 (32-bit) and IPv6 (128-bit). The lookup function
checks `len(ip)` to select the tree. IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are
checked against both trees.

**Concurrent access:**

```go
type IPAccessControl struct {
    mu        sync.RWMutex
    ipv4White *radixTree
    ipv4Black *radixTree
    ipv6White *radixTree
    ipv6Black *radixTree
    autoBan   *radixTree    // dynamic, TTL-based entries
}
```

- **Reads** (every request): `RLock` — many concurrent readers, no contention.
- **Writes** (config reload, auto-ban): `Lock` — rare, acceptable to block briefly.
- Alternative considered: copy-on-write with `atomic.Value`. This eliminates read locks
  entirely but doubles memory during updates and complicates auto-ban TTL management.
  The RWMutex approach is simpler and the read-lock overhead is ~10 ns (well within the
  100 ns budget).

**Lookup algorithm:**

```
func (t *radixTree) Lookup(ip net.IP) *ACLEntry:
    bits = ipToBits(ip)             // [32]byte for IPv4, [128]byte for IPv6
    node = t.root
    matched = nil                   // track deepest match (longest prefix)

    for each bit in bits:
        if node.value != nil:
            matched = node.value    // record this as potential longest-prefix match
        if node has compressed prefix:
            if bits[pos:pos+prefLen] != node.prefix:
                return matched      // diverged — return last match
            advance pos by prefLen
        child = node.children[bit]
        if child == nil:
            return matched
        node = child

    if node.value != nil:
        return node.value
    return matched
```

**Performance target: < 100 ns per lookup.**
At 32 bits max depth (IPv4), with ~10 nodes traversed on average after compression,
and ~5 ns per node (two comparisons + one pointer chase), we expect ~50 ns. Benchmarks
will validate.

---

### 3.3 Token Bucket (Rate Limiter)

```
internal/layers/ratelimit/bucket.go
```

**Why token bucket over alternatives?**

| Algorithm | Burst Handling | Memory per Bucket | Implementation Complexity | Background Work |
|-----------|---------------|-------------------|--------------------------|-----------------|
| Token bucket | Natural — burst = bucket capacity | 24 bytes (2 fields) | Low | None (lazy refill) |
| Sliding window log | Exact — no burst | O(n) per window entry | Medium | Cleanup needed |
| Sliding window counter | Approximate | 16 bytes | Low | None |
| Leaky bucket | Smooths — no burst | 16 bytes | Low | None |
| Fixed window counter | Boundary spike (2x burst) | 16 bytes | Trivial | None |

Token bucket wins because:
1. **Natural burst absorption** — a burst of `B` tokens is allowed, then rate-limited to
   `R` tokens/second. This matches real user behavior (page load = burst of requests,
   then reading time).
2. **Constant memory** — exactly two fields per bucket regardless of window size.
3. **Lazy refill** — no background goroutine per bucket. Tokens are computed on access
   using elapsed time. This is critical when tracking 100K+ IPs.
4. **Simplicity** — fewer edge cases than sliding window implementations.

**Implementation:**

```go
type Bucket struct {
    tokens     float64       // current token count
    lastRefill int64         // UnixNano timestamp of last refill
    rate       float64       // tokens per nanosecond (computed from config)
    capacity   float64       // max tokens (= burst size)
}

func (b *Bucket) Allow() bool {
    now := time.Now().UnixNano()
    elapsed := now - atomic.LoadInt64(&b.lastRefill)

    // Lazy refill: add tokens for elapsed time
    b.tokens = min(b.capacity, b.tokens + float64(elapsed) * b.rate)
    atomic.StoreInt64(&b.lastRefill, now)

    if b.tokens >= 1.0 {
        b.tokens -= 1.0
        return true
    }
    return false
}
```

**Thread safety for individual buckets:** Each bucket is accessed by at most a handful of
goroutines concurrently (same IP making concurrent requests). We use a per-bucket
`sync.Mutex` rather than atomics on `tokens` (float64 atomics are not available in Go
without `math.Float64bits` gymnastics, and the mutex overhead is < 20 ns uncontended).

**Bucket storage — `sync.Map`:**

```go
type RateLimiter struct {
    buckets sync.Map // map[string]*Bucket — key is scope-dependent
}
```

**Why `sync.Map` over regular map + RWMutex?**

The rate limiter has a specific access pattern: many goroutines reading/updating existing
entries (hot IPs), occasional new entries (new IPs), and rare deletions (cleanup). This is
exactly the pattern `sync.Map` is optimized for — the "append-mostly" case. In benchmarks,
`sync.Map` outperforms `map + RWMutex` by 2-5x for this pattern because it avoids lock
contention on the read path via internal atomic operations and a read-only copy.

**Scope resolution:**

| Scope | Key Format | Example |
|-------|-----------|---------|
| `"ip"` | `RemoteIP` | `"203.0.113.42"` |
| `"ip+path"` | `RemoteIP + ":" + PathPattern` | `"203.0.113.42:/login"` |

Path pattern matching uses a simple prefix match — the rate limit rule's `paths` are
checked against the request path. First matching rule wins.

**Expired bucket cleanup:**

```go
func (rl *RateLimiter) cleanupLoop(ctx context.Context) {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            now := time.Now().UnixNano()
            rl.buckets.Range(func(key, value any) bool {
                b := value.(*Bucket)
                // If bucket has been idle for 2x the window, delete it
                if now - atomic.LoadInt64(&b.lastRefill) > rl.idleTimeout {
                    rl.buckets.Delete(key)
                }
                return true
            })
        }
    }
}
```

Every 5 minutes, iterate all buckets and delete those idle for longer than `2 * window`.
This bounds memory: at steady state with 100K active IPs, memory is ~100K * 40 bytes =
~4 MB. After traffic drops, buckets are reclaimed within 10 minutes.

**Performance target: < 500 ns per check.** The critical path is: `sync.Map.Load` (~30 ns
hit) + mutex lock (~15 ns uncontended) + float64 arithmetic (~5 ns) + mutex unlock
(~15 ns) = ~65 ns typical. The 500 ns budget has 7x headroom for contended cases and
new-bucket creation.

---

### 3.4 SQL Tokenizer

```
internal/layers/detection/sqli/tokenizer.go
```

**Design: hand-written lexer with a state machine.**

**Why hand-written vs regex?**

| Criterion | Regex (`regexp` package) | Hand-Written Lexer |
|-----------|--------------------------|-------------------|
| Throughput | ~50 MB/s (Go RE2) | ~500 MB/s - 1 GB/s |
| Predictability | RE2 is linear-time but constant factor is high | Constant, deterministic |
| Backtracking | No (RE2), but alternation has cost | No backtracking possible |
| Allocation | Submatch allocates slices | Zero-allocation with pooled buffer |
| Debuggability | Opaque automaton | Step through state machine |
| Maintenance | Regex soup becomes unreadable | Verbose but clear |

A regex-based SQLi detector would need ~20 regexes, each compiled and matched against
every input field. At 4 fields per request and ~10 us per regex match, that is 800 us
just for SQLi — exceeding our entire pipeline budget. The hand-written lexer processes
the same input in < 50 us by doing a single pass.

**State machine:**

```
                          ┌─────────────┐
                          │   INITIAL   │
                          └──────┬──────┘
                                 │ read char
                     ┌───────────┼───────────┬──────────────┐
                     │           │           │              │
                     ▼           ▼           ▼              ▼
              ┌────────┐  ┌──────────┐ ┌──────────┐  ┌──────────┐
              │ ALPHA  │  │  QUOTE   │ │  DIGIT   │  │ SPECIAL  │
              │ a-z,_  │  │  ', ", ` │ │  0-9     │  │ ;,(,),=  │
              └───┬────┘  └────┬─────┘ └────┬─────┘  └────┬─────┘
                  │            │            │              │
                  ▼            ▼            ▼              ▼
           ┌──────────┐ ┌──────────┐ ┌──────────┐  ┌──────────┐
           │ Classify │ │ Read to  │ │ Read     │  │ Emit     │
           │ keyword  │ │ matching │ │ number   │  │ operator │
           │ via trie │ │ quote    │ │ literal  │  │ token    │
           └──────────┘ └──────────┘ └──────────┘  └──────────┘
                  │            │            │              │
                  └────────────┴────────────┴──────────────┘
                                     │
                                     ▼
                              ┌────────────┐
                              │ Emit Token │
                              │ Advance    │
                              │ → INITIAL  │
                              └────────────┘
```

**Keyword classification — trie-based O(k) lookup:**

SQL keywords are loaded into a trie at init time. The trie is built once, read many
times, and requires no synchronization.

```go
type trieNode struct {
    children [26]trieNode   // a-z only (keywords are case-normalized)
    token    TokenType      // non-zero if this node terminates a keyword
}
```

Why a trie over a `map[string]TokenType`?
- Map lookup requires hashing the string (~15 ns for a 6-char keyword) plus a
  comparison. The trie traverses 6 pointers (~6 ns total) for the same keyword.
- More importantly, the trie enables prefix matching: as we read characters from the
  input, we can walk the trie simultaneously. If the trie walk reaches a dead end, we
  know the word is not a keyword without reading the rest of it.
- The trie is small: ~26 * 26 * 10 = ~6,760 nodes for the full SQL keyword set,
  each node is ~210 bytes (26 pointers + 1 byte). Total: ~1.4 MB. Allocated once at
  startup.

**Handling evasion techniques:**

| Evasion | Detection Approach |
|---------|-------------------|
| `UN/**/ION SEL/**/ECT` | Strip comments before tokenization (comment removal pass) |
| `%55NION %53ELECT` | Sanitizer layer URL-decodes first; tokenizer sees `UNION SELECT` |
| `uNiOn SeLeCt` | All input lowercased before tokenization |
| `UNION%09SELECT` | Whitespace normalization by sanitizer |
| `0x756e696f6e` | Hex literal detected as token, classified, and checked against keyword hex encodings |
| Null byte injection (`UN%00ION`) | Null bytes stripped by sanitizer |

**Token output:**

```go
type Token struct {
    Type   TokenType  // enumerated constant
    Value  string     // the original text of this token (points into input, no copy)
    Offset int        // byte offset in input
}
```

Token slices are pooled via `sync.Pool` with a pre-allocated capacity of 64 tokens.
Most SQL injection payloads produce fewer than 30 tokens. The `Value` field is a
substring of the input (Go string sharing), so no allocation occurs for token values.

**Pattern matching — sequential token scan:**

After tokenization, the detector scans the token sequence for known dangerous patterns.
This is implemented as a set of pattern-matching functions, each checking for a specific
attack class:

```go
func checkUnionSelect(tokens []Token) (score int, evidence string)
func checkTautology(tokens []Token) (score int, evidence string)
func checkStackedQuery(tokens []Token) (score int, evidence string)
func checkTimeBased(tokens []Token) (score int, evidence string)
func checkFileOps(tokens []Token) (score int, evidence string)
func checkCommentEvasion(tokens []Token) (score int, evidence string)
```

Each function returns independently. Scores from all matching patterns are summed. The
maximum possible score is capped at 100 (per detector).

---

### 3.5 HTML Tag Parser (XSS)

```
internal/layers/detection/xss/parser.go
```

**Design: minimal HTML-aware scanner, not a full DOM parser.**

A full HTML parser (tokenizer + tree builder) would correctly handle all edge cases but
is massive to implement (the HTML5 spec's parsing algorithm is thousands of lines) and
far more work than needed. We need to detect *injection attempts*, not render valid HTML.

**Scanning approach:**

```
Input: <img src=x onerror=alert(1)>

Scan state machine:
  1. Scan for '<' character
  2. If found, enter TAG_NAME state
  3. Read tag name (alphanumeric + some special chars)
  4. Enter ATTRIBUTES state
  5. For each attribute:
     a. Read attribute name
     b. If name matches /^on[a-z]+$/ → emit EVENT_HANDLER finding
     c. If name is "href" or "src" and value starts with "javascript:" → emit JS_PROTOCOL
     d. If name is "href" or "src" and value starts with "data:" → emit DATA_URI
  6. Continue until '>' or EOF
```

**Detection patterns implemented as direct checks, not regex:**

```go
func (d *XSSDetector) scanTagOpen(input []byte, pos int) (findings []Finding) {
    // Read tag name
    tagName = readTagName(input, pos+1) // after '<'

    switch toLower(tagName) {
    case "script":
        findings = append(findings, Finding{Score: 90, ...})
    case "iframe", "frame":
        findings = append(findings, Finding{Score: 50, ...})
    case "object", "embed", "applet":
        findings = append(findings, Finding{Score: 45, ...})
    // ... other dangerous tags
    }

    // Scan attributes regardless of tag name
    for attr in scanAttributes(input, afterTagName) {
        if isEventHandler(attr.Name) { // starts with "on" + lowercase alpha
            findings = append(findings, Finding{Score: 70, ...})
        }
        if isJSProtocol(attr.Value) {
            findings = append(findings, Finding{Score: 80, ...})
        }
    }
}
```

**Encoding detection:**

XSS payloads often encode `<` and other characters to bypass filters:

| Encoding | Pattern | Detection |
|----------|---------|-----------|
| HTML entity (decimal) | `&#60;` | Scan for `&#` + digits + `;` |
| HTML entity (hex) | `&#x3c;` | Scan for `&#x` + hex + `;` |
| HTML entity (named) | `&lt;` | Lookup in small table of 5-6 dangerous entities |
| JS escape (hex) | `\x3c` | Scan for `\x` + 2 hex digits |
| JS escape (unicode) | `\u003c` | Scan for `\u` + 4 hex digits |
| URL encoding | `%3c` | Already handled by sanitizer, but double-check |

Each encoding detection adds a +20 evasion bonus to the finding score, because encoding
of angle brackets or quotes strongly suggests an attack attempt (legitimate input does
not typically encode these characters).

---

### 3.6 IP Address Parser (SSRF)

```
internal/layers/detection/ssrf/ipcheck.go
```

**Goal:** Detect when a user-supplied URL points to a private/internal IP address,
without making any DNS lookups (DNS lookups are slow and can be manipulated via DNS
rebinding).

**Pure arithmetic approach:**

```go
func isPrivateIP(s string) bool {
    // 1. Try standard dotted-decimal: "192.168.1.1"
    if ip := parseStandardIP(s); ip != nil {
        return isPrivateRange(ip)
    }

    // 2. Try decimal integer: "2130706433" → 127.0.0.1
    if n, ok := parseDecimalIP(s); ok {
        return isPrivateRange(uint32ToIP(n))
    }

    // 3. Try octal: "0177.0.0.1" → 127.0.0.1
    if ip := parseOctalIP(s); ip != nil {
        return isPrivateRange(ip)
    }

    // 4. Try hex: "0x7f000001" → 127.0.0.1
    if n, ok := parseHexIP(s); ok {
        return isPrivateRange(uint32ToIP(n))
    }

    // 5. Try mixed notation: "0x7f.0.0.1"
    if ip := parseMixedIP(s); ip != nil {
        return isPrivateRange(ip)
    }

    return false
}
```

**Private range check using bit shifts:**

```go
func isPrivateRange(ip net.IP) bool {
    if ip4 := ip.To4(); ip4 != nil {
        n := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])

        // 127.0.0.0/8     → 0x7F000000
        if n>>24 == 127 { return true }

        // 10.0.0.0/8      → 0x0A000000
        if n>>24 == 10 { return true }

        // 172.16.0.0/12   → 0xAC100000
        if n>>20 == 0xAC1 { return true }

        // 192.168.0.0/16  → 0xC0A80000
        if n>>16 == 0xC0A8 { return true }

        // 169.254.0.0/16  → link-local
        if n>>16 == 0xA9FE { return true }

        // 0.0.0.0/8       → current network
        if n>>24 == 0 { return true }

        return false
    }

    // IPv6 checks
    if len(ip) == net.IPv6len {
        // ::1 (loopback)
        // fc00::/7 (unique local)
        // fe80::/10 (link-local)
        // ::ffff:0:0/96 (IPv4-mapped — re-check as IPv4)
        // ...
    }
    return false
}
```

**Why no DNS lookups?**
1. **Speed:** DNS lookups take 1-50 ms. Our entire pipeline budget is 1 ms.
2. **DNS rebinding:** An attacker controls a domain that first resolves to a public IP
   (passes the check) then re-resolves to 127.0.0.1 (hits internal services). Without
   DNS, we only check the literal IP in the URL.
3. **Availability:** DNS failures should not cause WAF failures.

The trade-off: we cannot detect SSRF attempts that use domain names pointing to private
IPs. This is documented as a known limitation. The behavioral analysis layer provides
partial compensation by detecting patterns of internal-service probing.

---

### 3.7 JA3 Fingerprinting

```
internal/layers/botdetect/ja3.go
```

**Extraction point:** `tls.Config.GetConfigForClient` callback.

```go
tlsConfig := &tls.Config{
    GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
        ja3 := computeJA3(hello)
        // Store JA3 in a sync.Map keyed by connection RemoteAddr
        // Retrieved later when building RequestContext
        ja3Store.Store(hello.Conn.RemoteAddr().String(), ja3)
        return nil, nil  // nil config = use default
    },
}
```

**JA3 computation:**

```
JA3 = MD5(
    SSLVersion,
    Ciphers (sorted, comma-separated),
    Extensions (sorted, comma-separated),
    EllipticCurves (sorted, comma-separated),
    ECPointFormats (sorted, comma-separated)
)
```

Each field is converted to its IANA numeric value, sorted numerically, and joined with
commas. The five groups are joined with commas as separators. The result is MD5-hashed
and hex-encoded.

**Why MD5?** JA3 is a fingerprint, not a security hash. MD5 is used because:
1. It is the standard — all JA3 databases use MD5 hashes.
2. It is fast (~300 ns for a typical JA3 input via `crypto/md5`).
3. Collision resistance is irrelevant here — we are matching against a known database.

**Embedded fingerprint database:**

```go
var knownFingerprints = map[string]FingerprintInfo{
    "e7d705a3286e19ea42f587b344ee6865": {Name: "Chrome 120+", Category: Browser, Risk: Safe},
    "b32309a26951912be7dba376398abc3b": {Name: "Firefox 120+", Category: Browser, Risk: Safe},
    // ... 50-100 entries for known browsers

    "3b5074b1b5d032e5620f69f9f700ff0e": {Name: "Python requests", Category: Library, Risk: Suspicious},
    "cd08e31494f9531f560d64c695473da9": {Name: "Go net/http", Category: Library, Risk: Suspicious},
    "e35d880f43a14f39a3c50c8a09a82835": {Name: "sqlmap", Category: Scanner, Risk: Malicious},
    "9e10692f1b7f78228b2d4e424db3a98c": {Name: "nikto", Category: Scanner, Risk: Malicious},
    // ... 20-30 entries for known tools
}
```

**Update strategy:** Fingerprints are embedded as Go constants compiled into the binary.
They are updated with code releases. This is a deliberate trade-off:
- **Pro:** No external database dependency, no file I/O, no parsing at startup.
- **Con:** New fingerprints require a new release. Mitigated by the behavioral analysis
  layer, which catches unknown bots regardless of their JA3 fingerprint.

**JA3-to-User-Agent cross-validation:**

```go
func (d *BotDetector) crossValidate(ja3 string, ua string) int {
    fp, known := knownFingerprints[ja3]
    if !known {
        return 20 // unknown fingerprint — mild suspicion
    }

    // If JA3 says Chrome but UA says something else
    if fp.Category == Browser && !uaMatchesBrowser(ua, fp.Name) {
        return 65 // fingerprint mismatch — strong suspicion
    }

    if fp.Risk == Malicious {
        return 80 // known scanner
    }

    return 0
}
```

---

### 3.8 Behavioral Analysis

```
internal/layers/botdetect/behavior.go
```

**Sliding window: time-bucketed ring buffer.**

```
  Time:   t-300s  t-299s  t-298s  ...  t-1s    t
          ┌─────┬─────┬─────┐    ┌─────┬─────┐
          │  B  │  B  │  B  │... │  B  │  B  │
          └─────┴─────┴─────┘    └─────┴─────┘
            ▲                              ▲
            │                              │
          oldest                      current (write head)

  Each bucket B stores:
    - requestCount  uint32
    - errorCount    uint32   (4xx/5xx responses)
    - uniquePaths   uint16   (bounded set, max 256)
    - minTiming     uint32   (nanoseconds, for stddev approximation)
    - maxTiming     uint32
```

**Why ring buffer over sliding window log?**

| Criterion | Sliding Window Log | Ring Buffer |
|-----------|-------------------|-------------|
| Memory per IP | O(requests in window) — unbounded | O(window_seconds) — fixed 300 buckets |
| Update | Append entry | Increment counter |
| Query (sum over window) | Iterate all entries | Sum all buckets |
| Cleanup | Remove expired entries | Overwrite old buckets |

At 10 RPS per IP over a 5-minute window, a sliding window log stores 3,000 entries per
IP. At 100K tracked IPs, that is 300M entries — unacceptable. The ring buffer stores
300 buckets per IP regardless of request rate, using ~2.4 KB per IP.

**Per-IP tracking:**

```go
type BehaviorTracker struct {
    mu          sync.RWMutex
    trackers    map[string]*IPBehavior  // keyed by RemoteIP string
    cleanupChan chan string             // IPs to remove
}

type IPBehavior struct {
    buckets     [300]Bucket  // 5 minutes at 1-second granularity
    writeHead   int          // current bucket index
    lastUpdate  int64        // UnixNano, for detecting idle trackers
    pathSet     [256]uint64  // bloom-filter-like bounded set for path uniqueness
}
```

**Path uniqueness — bounded set with FNV hash:**

Tracking exact unique paths requires a `map[string]struct{}`, which is expensive (string
allocations, map overhead). Instead, we use a 256-slot hash set:

```go
func (b *IPBehavior) addPath(path string) {
    h := fnv32(path)
    slot := h & 0xFF  // mod 256
    b.pathSet[slot] = h  // overwrite — approximate but bounded
}

func (b *IPBehavior) uniquePathEstimate() int {
    count := 0
    for _, v := range b.pathSet {
        if v != 0 { count++ }
    }
    return count
}
```

This is an approximation (collisions cause undercounting), but it is sufficient for
behavioral scoring. The alternative — HyperLogLog — provides better accuracy for large
cardinalities but is overkill when we only need to distinguish "< 10 unique paths"
(normal) from "> 50 unique paths" (scanning).

**Cleanup goroutine:**

```go
// Runs every 1 minute
func (bt *BehaviorTracker) cleanupLoop(ctx context.Context) {
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            threshold := time.Now().Add(-10 * time.Minute).UnixNano()
            bt.mu.Lock()
            for ip, behavior := range bt.trackers {
                if behavior.lastUpdate < threshold {
                    delete(bt.trackers, ip)
                }
            }
            bt.mu.Unlock()
        }
    }
}
```

IPs with no activity for 10 minutes (2x the analysis window) are removed.

---

### 3.9 Analytics Engine

```
internal/analytics/analytics.go
```

**TopK tracker — min-heap of size K:**

```go
type TopKTracker struct {
    mu      sync.Mutex
    counts  map[string]uint64  // full counts
    heap    []heapEntry        // min-heap of size K
    k       int
}

type heapEntry struct {
    key   string
    count uint64
}
```

**Why min-heap?** To maintain the top K items, we keep a min-heap of size K. When a new
item's count exceeds the minimum in the heap, we replace the minimum and re-heapify.
This gives O(log K) updates and O(K) reads, with K typically 10-50.

Alternative: sorting the full map on every read. This is O(n log n) where n = number of
unique keys (potentially 100K+ IPs). TopK with a heap is O(n log K) for building and
O(1) for maintenance per update.

**Rolling counters — time-bucketed:**

```
  1-hour counter:   60 buckets × 1-minute granularity
  24-hour counter:  24 buckets × 1-hour granularity
  7-day counter:    7 buckets  × 1-day granularity
  30-day counter:   30 buckets × 1-day granularity
```

Each counter is a ring buffer of `uint64` values. The current bucket is identified by
`time.Now() / granularity % numBuckets`. Summing all buckets gives the total for the
window.

**Ring buffer for time-series (dashboard charts):**

```go
type TimeSeriesRing struct {
    data      []DataPoint
    capacity  int
    writeHead uint64  // atomic
}

type DataPoint struct {
    Timestamp   int64   // Unix seconds
    Requests    uint32
    Blocked     uint32
    Logged      uint32
    AvgLatency  uint32  // microseconds
}
```

Fixed capacity (e.g., 8,640 points = 24 hours at 10-second granularity). The dashboard
reads the ring to render time-series charts without any aggregation on the server side.

---

## 4. Concurrency Model

### 4.1 Request Processing

```
  Client ──► net/http Server ──► goroutine per request
                                       │
                                       ▼
                                 Get RequestContext from sync.Pool
                                       │
                                       ▼
                                 ┌─────────────┐
                                 │ Layer 1: IP  │◄── RLock(radix tree)
                                 └──────┬──────┘
                                        │ (continue if allowed)
                                        ▼
                                 ┌─────────────┐
                                 │ Layer 2: RL  │◄── sync.Map.Load + Mutex(bucket)
                                 └──────┬──────┘
                                        │
                                        ▼
                                 ┌─────────────┐
                                 │ Layer 3: San │◄── pure computation, no locks
                                 └──────┬──────┘
                                        │
                                        ▼
                                 ┌─────────────┐
                                 │ Layer 4: Det │◄── pure computation, no locks
                                 └──────┬──────┘
                                        │
                                        ▼
                                 ┌─────────────┐
                                 │ Layer 5: Bot │◄── sync.Map.Load (JA3) + RLock(behavior)
                                 └──────┬──────┘
                                        │
                                        ▼
                                 ┌─────────────┐
                                 │ Layer 6: Rsp │◄── pure computation, no locks
                                 └──────┬──────┘
                                        │
                                        ▼
                                 Send event to channel (non-blocking)
                                       │
                                       ▼
                                 Return RequestContext to sync.Pool
```

**Key insight:** Layers 3, 4, and 6 are pure computation with no shared mutable state.
They operate entirely on the `RequestContext` (owned by the current goroutine) and
read-only configuration (immutable after load). This means zero lock contention for
60%+ of the pipeline.

**Early return:** If any layer decides to block, the pipeline short-circuits. Layer 1
(IP ACL) blocks known-bad IPs in < 100 ns without running any subsequent layers. This
is critical for DDoS mitigation — the most expensive layers (detection, bot analysis)
are never reached for blocked IPs.

### 4.2 Background Goroutines

| Goroutine | Interval | Purpose | Shutdown |
|-----------|----------|---------|----------|
| Rate limiter cleanup | 5 min | Delete expired token buckets | Context cancellation |
| Behavioral tracker cleanup | 1 min | Delete idle IP behavior trackers | Context cancellation |
| Health check workers (1 per upstream) | Configurable (default 10s) | Active health probes to upstream backends | Context cancellation |
| ACME certificate renewal | 12 h | Check cert expiry, renew if < 30 days | Context cancellation |
| Auto-ban TTL checker | 30 s | Remove expired auto-ban entries from radix tree | Context cancellation |
| Event writer | Continuous (channel) | Drain event channel, write to ring buffer or file | Channel close + drain |
| SSE broadcaster | Continuous (channel) | Fan-out events to connected dashboard clients | Context cancellation |
| Analytics aggregator | 1 min | Roll up counters, update TopK heaps | Context cancellation |
| Config file watcher | 5 s | `os.Stat` config file, reload if modified | Context cancellation |

**Total background goroutines:** 8 + N (where N = number of upstream backends, typically
1-5). This is well within Go's goroutine capacity (millions) and represents negligible
scheduler overhead.

**Why not timers instead of tickers?** Tickers provide a regular cadence. Timers would
require re-arming after each fire, adding code complexity with no benefit. The ticker
pattern is idiomatic Go for periodic background work.

### 4.3 Graceful Shutdown

```
  SIGINT/SIGTERM received
         │
         ▼
  1. Cancel root context
         │
         ├──► All background goroutines see ctx.Done(), begin exit
         │
         ▼
  2. Stop accepting new connections
         │    (http.Server.Shutdown with timeout)
         │
         ▼
  3. Wait for in-flight requests (default 30s timeout)
         │    Each request's goroutine completes its pipeline
         │    and returns RequestContext to pool
         │
         ▼
  4. Close event channel, wait for writer to drain
         │    (buffered channel drains remaining events)
         │
         ▼
  5. Flush and close event file (if file storage)
         │
         ▼
  6. Close SSE connections (clients receive EOF)
         │
         ▼
  7. Log final statistics, exit 0
```

**What is NOT persisted:**
- Rate limiter state (buckets) — rebuilds naturally as traffic resumes.
- Behavioral analysis state — same rationale.
- In-memory event ring buffer — events that were only in memory are lost. This is
  acceptable because the ring buffer is a bounded window, and operators who need
  durable events should use file storage.

**What IS persisted:**
- ACME certificates and account keys (in `cache_dir`).
- Configuration file (obviously).
- Event file (if file storage mode).

---

## 5. Memory Management

### 5.1 sync.Pool Usage

| Pool | Object Size | Hot Path? | Expected Throughput |
|------|------------|-----------|-------------------|
| RequestContext pool | ~512 bytes | Yes — every request | 50K+/sec |
| Token slice pool (SQLi) | 64 * 24 = 1,536 bytes | Yes — every request with query/body | 50K+/sec |
| Byte buffer pool (normalization) | 4,096 bytes | Yes — every request | 50K+/sec |
| Finding slice pool | 8 * 48 = 384 bytes | Yes — every request | 50K+/sec |

**Why sync.Pool specifically?**

`sync.Pool` is designed for exactly this pattern: objects that are expensive to allocate,
used briefly, and can be recycled. The Go runtime integrates `sync.Pool` with the garbage
collector — pool objects may be collected between GC cycles if load drops, preventing
memory leaks. Manual free-lists would require explicit size management.

**Pool initialization:**

```go
var requestContextPool = sync.Pool{
    New: func() any {
        return &RequestContext{
            Findings:        make([]Finding, 0, 8),
            NormalizedQuery: make(map[string][]string, 16),
        }
    },
}
```

The `New` function pre-allocates the Findings slice and query map. Subsequent `Get()`
calls return these pre-allocated objects, avoiding the initial allocation cost.

### 5.2 Memory Budgets

```
┌──────────────────────────────────────────────────────────────────┐
│                    Standalone Mode (~30 MB)                       │
│                                                                  │
│  ┌─────────────────────┐  ┌──────────────────────┐              │
│  │ Go runtime overhead │  │ Config + keyword DB  │              │
│  │ ~5 MB               │  │ ~2 MB                │              │
│  └─────────────────────┘  └──────────────────────┘              │
│                                                                  │
│  ┌─────────────────────┐  ┌──────────────────────┐              │
│  │ Radix trees (4x)    │  │ JA3 fingerprint DB   │              │
│  │ ~1 MB               │  │ ~100 KB              │              │
│  └─────────────────────┘  └──────────────────────┘              │
│                                                                  │
│  ┌─────────────────────┐  ┌──────────────────────┐              │
│  │ Event ring buffer   │  │ Analytics engine     │              │
│  │ ~20 MB (100K events)│  │ ~1 MB                │              │
│  └─────────────────────┘  └──────────────────────┘              │
│                                                                  │
│  ┌─────────────────────┐  ┌──────────────────────┐              │
│  │ Dashboard static    │  │ sync.Pool objects    │              │
│  │ ~500 KB             │  │ ~500 KB              │              │
│  └─────────────────────┘  └──────────────────────┘              │
│                                                                  │
│  Variable: Rate limiter + Behavior tracker                       │
│  ~10 MB per 10K tracked IPs                                      │
└──────────────────────────────────────────────────────────────────┘
```

**Library mode (~5 MB):** No dashboard, no MCP, no proxy, no event ring buffer
(events go to callback). Just the engine, config, keyword DB, and pooled objects.

**Sidecar mode (~20 MB):** Like standalone but no dashboard static files and a smaller
default event ring buffer (10K events instead of 100K).

### 5.3 String Handling

**Rules for the hot path:**

1. **Never concatenate strings with `+` in a loop.** Use `bytes.Buffer` or
   `[]byte` append. String concatenation creates a new allocation per operation.

2. **Normalize in-place on `[]byte`.** The sanitizer operates on a `[]byte` copy of the
   input. Transformations (lowercase, URL decode, null removal) modify the slice in
   place. The final normalized string is created with a single `string(buf)` conversion.

3. **Use sub-slicing for token values.** When the SQL tokenizer identifies a token, its
   `Value` field is a slice of the original input string: `input[start:end]`. Go strings
   share underlying bytes, so this is a zero-allocation operation.

4. **Pre-compute common strings.** HTTP method names, common header names, and common
   header values are stored as package-level constants. Comparison uses these constants
   directly, avoiding allocation.

5. **Avoid `fmt.Sprintf` on the hot path.** Use `strconv.AppendInt`, `strconv.AppendFloat`,
   etc., writing into a pre-allocated buffer. `fmt.Sprintf` allocates via reflection
   internally.

---

## 6. Configuration System

### 6.1 YAML Parser Design

**Parser phases:**

```
  Input: []byte (file contents)
         │
         ▼
  Phase 1: Line Splitting + Comment Removal
         │  Split on \n, strip \r, remove # comments (respect quoted strings)
         │  Track line numbers for error reporting
         │
         ▼
  Phase 2: Indentation Analysis
         │  Count leading spaces per line
         │  Build indentation→depth mapping
         │  Reject mixed tabs/spaces (error with line number)
         │
         ▼
  Phase 3: Line Classification
         │  Each line is one of:
         │    MapEntry    → "key: value" or "key:"
         │    SeqItem     → "- value" or "- key: value"
         │    InlineMap   → "{key: val, key: val}"
         │    InlineSeq   → "[val, val, val]"
         │    Continuation→ multiline value (not supported — error)
         │    Blank       → skip
         │
         ▼
  Phase 4: Tree Construction
         │  Walk lines, using indentation to determine parent-child relationships
         │  Build map[string]any tree
         │
         ▼
  Phase 5: Type Coercion
         │  Scalar values are stored as strings
         │  A separate phase converts to int/float/bool based on the target
         │  Config struct's field types
         │
         ▼
  Output: map[string]any tree → populateConfig() → *Config
```

**Inline map/sequence parsing:**

The YAML config uses inline maps for detector settings:
```yaml
sqli: { enabled: true, multiplier: 1.0 }
```

The parser handles this by detecting the opening `{` and parsing key-value pairs until
the matching `}`, handling nested quotes and escapes. Similarly for `[...]` sequences.

```go
func parseInlineMap(s string) (map[string]any, error) {
    // Strip outer { }
    // Split by commas (respecting quotes)
    // For each segment, split by first ":" to get key-value
    // Recursively parse values (could be inline maps/sequences)
}
```

**Error reporting:**

Every parse error includes the line number and a clear description:

```
guardianwaf.yaml:42: expected value after ":", got end of line
guardianwaf.yaml:55: inconsistent indentation (expected 4 spaces, got 3)
guardianwaf.yaml:68: unterminated quoted string starting at column 12
```

### 6.2 Configuration Layering

```
  Priority (highest wins):

  ┌──────────────────────────┐
  │  Environment Variables   │  GWAF_WAF_DETECTION_SQLI_ENABLED=false
  ├──────────────────────────┤
  │  CLI Flags               │  --mode=monitor --listen=:9090
  ├──────────────────────────┤
  │  YAML File               │  guardianwaf.yaml
  ├──────────────────────────┤
  │  Hardcoded Defaults      │  internal/config/defaults.go
  └──────────────────────────┘
```

**Environment variable naming convention:**

```
Config path:                     Env var:
mode                         →   GWAF_MODE
listen                       →   GWAF_LISTEN
waf.detection.sqli.enabled   →   GWAF_WAF_DETECTION_SQLI_ENABLED
waf.rate_limit.rules[0].limit →  (arrays not supported via env — use YAML)
tls.acme.email               →   GWAF_TLS_ACME_EMAIL
```

Nested keys are joined by `_`, uppercased, prefixed with `GWAF_`. Array-type config
values cannot be set via environment variables — this is a deliberate limitation to keep
the env var mapping simple. Operators needing complex config should use a YAML file.

**Merging algorithm:**

```go
func LoadConfig(yamlPath string, flags *Flags) (*Config, error) {
    // 1. Start with defaults
    cfg := DefaultConfig()

    // 2. If YAML file exists, parse and merge
    if yamlPath != "" {
        tree, err := ParseYAML(readFile(yamlPath))
        populateFromTree(cfg, tree)
    }

    // 3. Override with CLI flags (only non-zero values)
    if flags.Mode != "" { cfg.Mode = flags.Mode }
    if flags.Listen != "" { cfg.Listen = flags.Listen }
    // ...

    // 4. Override with environment variables
    applyEnvOverrides(cfg)

    // 5. Validate the final config
    return cfg, Validate(cfg)
}
```

### 6.3 Validation

Validation runs once after all layers are merged. It returns ALL errors at once (not
fail-on-first) so the operator can fix everything in one pass.

```go
func Validate(cfg *Config) error {
    var errs []string

    // Range checks
    if cfg.WAF.Detection.Threshold.Block < 0 || cfg.WAF.Detection.Threshold.Block > 100 {
        errs = append(errs, "waf.detection.threshold.block must be 0-100")
    }

    // Cross-references
    for _, route := range cfg.Routes {
        if !upstreamExists(cfg.Upstreams, route.Upstream) {
            errs = append(errs, fmt.Sprintf("route %q references unknown upstream %q",
                route.Path, route.Upstream))
        }
    }

    // Logical consistency
    if cfg.WAF.Detection.Threshold.Log > cfg.WAF.Detection.Threshold.Block {
        errs = append(errs, "log threshold must be <= block threshold")
    }

    // Multiplier ranges
    for name, det := range cfg.WAF.Detection.Detectors {
        if det.Multiplier < 0 {
            errs = append(errs, fmt.Sprintf("detector %q multiplier must be >= 0", name))
        }
    }

    if len(errs) > 0 {
        return &ConfigError{Errors: errs}
    }
    return nil
}
```

### 6.4 Hot Reload

```
  ┌────────────────────┐       os.Stat every 5s         ┌─────────────┐
  │ Config File Watcher│ ──────────────────────────────► │ File Changed?│
  │ (background gortn) │                                 └──────┬──────┘
  └────────────────────┘                                        │
                                                         Yes    │  No → sleep
                                                                │
                                                         ┌──────▼──────┐
                                                         │ Parse YAML  │
                                                         │ Merge layers│
                                                         │ Validate    │
                                                         └──────┬──────┘
                                                                │
                                                         ┌──────▼───────┐
                                                         │ Validation   │
                                                         │ passed?      │
                                                         └──────┬───────┘
                                                          Yes   │  No → log error
                                                                │       keep old config
                                                         ┌──────▼──────┐
                                                         │ Atomic swap │
                                                         │ config ptr  │
                                                         │ (atomic.Value)
                                                         └──────┬──────┘
                                                                │
                                                         ┌──────▼──────┐
                                                         │ Notify all  │
                                                         │ layers of   │
                                                         │ config chg  │
                                                         └─────────────┘
```

**Atomic config swap:** The active config is stored in an `atomic.Value`. Readers call
`cfg := configHolder.Load().(*Config)` with zero locking. The writer (config watcher)
calls `configHolder.Store(newCfg)`. This is lock-free on the read path.

**Layer notification:** Each layer implements an optional `OnConfigReload(cfg *Config)`
method. After the atomic swap, the watcher calls this method on each layer sequentially.
Layers update their internal state (e.g., the IP ACL rebuilds its radix trees, the rate
limiter adjusts bucket parameters for new rules).

**What cannot be hot-reloaded:**
- Listen address (requires socket rebind — restart required).
- TLS certificate paths (ACME handles rotation separately).
- Dashboard listen address.
- Event storage mode change (memory ↔ file).

These are documented and validated: if a non-reloadable field changes, the reload logs a
warning and ignores the change.

---

## 7. Reverse Proxy Design

### 7.1 HTTP Proxy

```
internal/proxy/proxy.go
```

**Architecture:**

```
  Client Request
       │
       ▼
  ┌──────────────────┐
  │ WAF Pipeline     │  (Layers 1-5)
  └────────┬─────────┘
           │ (if allowed)
           ▼
  ┌──────────────────┐
  │ Route Matching   │  Match request path to upstream
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────┐
  │ Load Balancer    │  Select backend from upstream pool
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────┐
  │ Circuit Breaker  │  Check if backend is available
  └────────┬─────────┘
           │ (if closed/half-open)
           ▼
  ┌──────────────────┐
  │ HTTP Transport   │  Send request to backend
  │ (connection pool)│
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────┐
  │ Response Stream  │  io.Copy back to client
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────┐
  │ Layer 6: Response│  Security headers, masking
  └──────────────────┘
```

**Custom RoundTripper:**

```go
type WAFTransport struct {
    base    *http.Transport  // stdlib transport with connection pooling
    reqIDFn func() string    // request ID generator
}

func (t *WAFTransport) RoundTrip(req *http.Request) (*http.Response, error) {
    // Inject WAF headers
    req.Header.Set("X-Forwarded-For", clientIP(req))
    req.Header.Set("X-Real-IP", clientIP(req))
    req.Header.Set("X-Request-ID", t.reqIDFn())
    req.Header.Set("X-Forwarded-Proto", scheme(req))

    // Remove hop-by-hop headers
    removeHopByHopHeaders(req.Header)

    return t.base.RoundTrip(req)
}
```

**Response streaming:**

The proxy DOES NOT buffer the full response body in memory. Instead, it uses `io.Copy`
to stream from the upstream response body to the client response writer:

```go
// Simplified — actual code handles headers, status code, flush
io.Copy(clientWriter, upstreamResponse.Body)
```

This is critical for large responses (file downloads, streaming APIs). The response
protection layer (Layer 6) only inspects response headers and a bounded prefix of the
response body (for data masking). It does not need the full body in memory.

**Timeout hierarchy:**

```go
transport := &http.Transport{
    DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
    TLSHandshakeTimeout:  5 * time.Second,
    ResponseHeaderTimeout: 30 * time.Second,
    IdleConnTimeout:       90 * time.Second,
    MaxIdleConns:          100,
    MaxIdleConnsPerHost:   10,
}
```

| Timeout | Default | Purpose |
|---------|---------|---------|
| Connect | 5s | TCP connection establishment |
| TLS Handshake | 5s | TLS negotiation (if upstream is HTTPS) |
| Response Header | 30s | Time until first byte of response |
| Idle Connection | 90s | Keep-alive connection reuse window |

Each timeout is independently configurable. Timeouts cascade: if connect fails, TLS is
never attempted. If response header times out, the connection is closed and the circuit
breaker is notified.

### 7.2 Load Balancing

```
internal/proxy/loadbalancer.go
```

| Algorithm | Implementation | When to Use |
|-----------|---------------|------------|
| Round-robin | `atomic.AddUint64(&counter, 1) % len(backends)` | Default; equal-weight backends |
| Weighted | Weighted random: `rand(totalWeight)` → find bucket | Backends with different capacities |
| Least-connections | `atomic.LoadInt64(&backend.conns)` → pick minimum | Long-lived connections (WebSocket) |
| IP-hash | `fnv32(clientIP) % len(backends)` | Session affinity without cookies |

**Backend exclusion:** All algorithms skip backends marked unhealthy. If all backends are
unhealthy, the load balancer returns an error (503 to client).

**Why FNV for IP-hash?** FNV-1a is simple (3 lines of code), fast (~2 ns for an IPv4
address), and provides good distribution. We don't need cryptographic properties —
just a consistent mapping from IP to backend index. The stdlib `hash/fnv` package
provides this.

### 7.3 Health Checks

```
internal/proxy/healthcheck.go
```

**State machine per backend:**

```
  ┌─────────┐  N consecutive failures   ┌───────────┐
  │ Healthy  │ ────────────────────────► │ Unhealthy │
  │          │                           │           │
  └─────────┘                           └─────┬─────┘
       ▲                                      │
       │  probe succeeds                      │ cooldown expires
       │                                      │
  ┌────┴──────┐                          ┌────▼──────┐
  │           │◄─────────────────────────│ HalfOpen  │
  │           │  success_threshold met   │ (1 probe) │
  └───────────┘                          └───────────┘
       │                                      │
       │                                      │ probe fails
       │                                      │
       │                                ┌─────▼─────┐
       └────────────────────────────────│ Unhealthy │
                                        └───────────┘
```

**Active health checks:** One goroutine per upstream (not per backend) runs a ticker.
Each tick, it probes all backends in that upstream sequentially:

```go
func (hc *HealthChecker) probeLoop(ctx context.Context, upstream *Upstream) {
    ticker := time.NewTicker(upstream.HealthCheck.Interval)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            for _, backend := range upstream.Backends {
                hc.probeBackend(ctx, backend)
            }
        }
    }
}
```

**Passive health checks:** The proxy transport tracks response codes. On a 5xx response:

```go
backend.consecutiveErrors.Add(1)
if backend.consecutiveErrors.Load() >= threshold {
    backend.state.Store(Unhealthy)
}
```

On a 2xx/3xx response:

```go
backend.consecutiveErrors.Store(0)
if backend.state.Load() == HalfOpen {
    backend.successCount.Add(1)
    if backend.successCount.Load() >= successThreshold {
        backend.state.Store(Healthy)
    }
}
```

### 7.4 Circuit Breaker

```
internal/proxy/circuitbreaker.go
```

**Per-upstream circuit breaker (not per-backend):** If ALL backends in an upstream are
failing, the circuit breaker opens. This prevents thundering-herd retries when the
entire upstream is down.

```go
type CircuitBreaker struct {
    state           atomic.Int32  // Closed=0, Open=1, HalfOpen=2
    failures        atomic.Int64
    lastFailureTime atomic.Int64

    failureThreshold  int64
    successThreshold  int64
    timeout           time.Duration
}

func (cb *CircuitBreaker) Allow() bool {
    switch State(cb.state.Load()) {
    case Closed:
        return true
    case Open:
        if time.Since(cb.lastFailureTime()) > cb.timeout {
            cb.state.Store(int32(HalfOpen))
            return true // allow one probe request
        }
        return false
    case HalfOpen:
        return true // allow probe requests
    }
    return false
}
```

**Why atomic operations instead of mutex?** The circuit breaker is checked on every
proxied request (hot path). `atomic.Load` is ~1 ns vs ~15 ns for an uncontended mutex
lock/unlock. At 50K RPS, this saves 700 us per second.

### 7.5 WebSocket Proxying

```
internal/proxy/websocket.go
```

**Detection:** Check for `Upgrade: websocket` header and `Connection: Upgrade`.

**Flow:**

```
  1. Client sends HTTP upgrade request
  2. WAF pipeline inspects the initial HTTP request (Layers 1-5)
  3. If allowed:
     a. Hijack client connection: clientConn, _, _ = w.(http.Hijacker).Hijack()
     b. Dial upstream: upstreamConn = net.Dial(backend.URL)
     c. Forward the original upgrade request to upstream
     d. Read upstream's 101 response, forward to client
     e. Start bidirectional copy:
        go io.Copy(upstreamConn, clientConn)  // client → upstream
        io.Copy(clientConn, upstreamConn)      // upstream → client (blocks)
     f. When either copy returns, close both connections
```

**WAF limitation:** Only the initial HTTP upgrade request is inspected. WebSocket frames
are NOT inspected — this would require implementing a WebSocket frame parser, and the
performance cost of inspecting every frame would be prohibitive for a proxy. This is
documented as a known limitation, consistent with how other WAFs (ModSecurity, Coraza)
handle WebSocket traffic.

---

## 8. TLS Implementation

### 8.1 ACME Client (HTTP-01 Challenge)

```
internal/tls/acme.go
```

**Why implement ACME from scratch?**

The Go ecosystem has `golang.org/x/crypto/acme` and `certmagic`, but both are external
dependencies. The zero-dependency constraint requires a custom implementation.

ACME HTTP-01 is the simplest challenge type and requires only:
- HTTP client (`net/http` — stdlib)
- JSON encoding (`encoding/json` — stdlib)
- RSA/ECDSA key generation (`crypto/rsa`, `crypto/ecdsa` — stdlib)
- Certificate parsing (`crypto/x509` — stdlib)
- Base64url encoding (`encoding/base64` — stdlib)
- SHA-256 hashing (`crypto/sha256` — stdlib)

**ACME flow:**

```
  ┌─────────────────┐
  │ 1. Generate     │  crypto/ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  │    account key  │  Store in cache_dir/account.key
  └────────┬────────┘
           │
  ┌────────▼────────┐
  │ 2. Register     │  POST /acme/new-acct
  │    account      │  Body: { "termsOfServiceAgreed": true, "contact": [...] }
  └────────┬────────┘
           │
  ┌────────▼────────┐
  │ 3. Request cert │  POST /acme/new-order
  │    (new order)  │  Body: { "identifiers": [{ "type":"dns", "value":"example.com" }] }
  └────────┬────────┘
           │
  ┌────────▼────────┐
  │ 4. Get authz    │  GET order.authorizations[0]
  │    challenges   │  Find challenge with type == "http-01"
  └────────┬────────┘
           │
  ┌────────▼────────┐
  │ 5. Serve token  │  Listen on /.well-known/acme-challenge/{token}
  │                 │  Respond with: token.thumbprint(accountKey)
  └────────┬────────┘
           │
  ┌────────▼────────┐
  │ 6. Notify ACME  │  POST challenge.url
  │    server       │  Body: {}
  └────────┬────────┘
           │
  ┌────────▼────────┐
  │ 7. Poll order   │  GET order.url until status == "valid" or "invalid"
  │    status       │  Exponential backoff: 1s, 2s, 4s, 8s, max 30s
  └────────┬────────┘
           │
  ┌────────▼────────┐
  │ 8. Generate CSR │  crypto/x509.CreateCertificateRequest(...)
  │                 │  Key: crypto/ecdsa.GenerateKey(P256)
  └────────┬────────┘
           │
  ┌────────▼────────┐
  │ 9. Finalize     │  POST order.finalize
  │    order        │  Body: { "csr": base64url(der-encoded CSR) }
  └────────┬────────┘
           │
  ┌────────▼────────┐
  │ 10. Download    │  GET order.certificate
  │     cert chain  │  Parse PEM blocks → tls.Certificate
  └────────┬────────┘
           │
  ┌────────▼────────┐
  │ 11. Store cert  │  Write to cache_dir/{domain}.crt and .key
  │     and key     │  Load into tls.Config
  └─────────────────┘
```

**ACME request signing (JWS):**

Every ACME request is signed with the account key using JWS (JSON Web Signature) compact
serialization. This requires:

```go
func signJWS(payload []byte, key *ecdsa.PrivateKey, nonce string, url string) ([]byte, error) {
    header := map[string]any{
        "alg":   "ES256",
        "nonce": nonce,
        "url":   url,
        "jwk":   jwkFromKey(&key.PublicKey), // for registration
        // or "kid": accountURL             // after registration
    }
    protected := base64url(jsonEncode(header))
    payloadB64 := base64url(payload)
    sigInput := protected + "." + payloadB64

    hash := sha256.Sum256([]byte(sigInput))
    r, s, _ := ecdsa.Sign(rand.Reader, key, hash[:])

    sig := base64url(append(pad(r, 32), pad(s, 32)...))

    return jsonEncode(map[string]string{
        "protected": protected,
        "payload":   payloadB64,
        "signature": sig,
    })
}
```

**Certificate renewal:**

A background goroutine checks certificate expiry every 12 hours:

```go
func (m *CertManager) renewalLoop(ctx context.Context) {
    ticker := time.NewTicker(12 * time.Hour)
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            for domain, cert := range m.certificates {
                if time.Until(cert.Leaf.NotAfter) < 30*24*time.Hour {
                    newCert, err := m.acmeClient.ObtainCertificate(domain)
                    if err != nil {
                        log.Printf("ACME renewal failed for %s: %v", domain, err)
                        continue // retry in 12h
                    }
                    m.mu.Lock()
                    m.certificates[domain] = newCert
                    m.mu.Unlock()
                }
            }
        }
    }
}
```

### 8.2 SNI Routing

```
internal/tls/sni.go
```

```go
tlsConfig := &tls.Config{
    GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
        // 1. Compute and store JA3 fingerprint
        ja3 := computeJA3(hello)
        ja3Store.Store(hello.Conn.RemoteAddr().String(), ja3)

        // 2. Look up certificate for this SNI
        cert, ok := certManager.GetCertificate(hello.ServerName)
        if !ok {
            return nil, nil // use default cert
        }

        return &tls.Config{
            Certificates: []tls.Certificate{cert},
        }, nil
    },
}
```

Certificate lookup is a simple `map[string]*tls.Certificate` protected by `RWMutex`.
Wildcard certificates are supported by checking both the exact name and `*.domain` form.

---

## 9. Dashboard Architecture

### 9.1 Embedded Static Files

```
internal/dashboard/static/
```

```go
//go:embed static/*
var staticFS embed.FS
```

**File structure:**

```
static/
├── index.html      # Single HTML file, all pages
├── app.js          # ~2000 lines of vanilla JS
└── style.css       # ~1000 lines, CSS variables for theming
```

**Why a single HTML file?** The dashboard is a single-page application (SPA). All "pages"
are `<div>` sections that are shown/hidden via JavaScript. This eliminates HTTP round-
trips for page navigation and keeps the embed simple.

**Why vanilla JS, no framework?** Zero dependencies means no React, Vue, or Svelte.
Vanilla JS is 100% dependency-free, has zero build tooling requirements, and results
in a ~50KB payload (gzipped). Modern browsers have excellent DOM API support.

**CSS theming:**

```css
:root {
    --bg-primary: #ffffff;
    --bg-secondary: #f5f5f5;
    --text-primary: #1a1a1a;
    --accent: #2563eb;
    /* ... */
}

[data-theme="dark"] {
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --text-primary: #e2e8f0;
    --accent: #3b82f6;
}
```

Theme preference is stored in `localStorage` and applied on page load to prevent flash
of wrong theme.

### 9.2 SSE (Server-Sent Events)

```
internal/dashboard/sse.go
```

**Why SSE over WebSocket?** SSE is simpler (unidirectional), works through all proxies
and firewalls (it's just HTTP), auto-reconnects, and is sufficient for our use case
(server pushes updates to dashboard). WebSocket would be needed only if the dashboard
sent real-time data back to the server, which it doesn't (all actions go through the
REST API).

**Broadcaster pattern:**

```go
type SSEBroadcaster struct {
    clients    map[chan SSEEvent]struct{}
    mu         sync.RWMutex
    register   chan chan SSEEvent
    unregister chan chan SSEEvent
    broadcast  chan SSEEvent
}

func (b *SSEBroadcaster) run(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            // Close all client channels
            b.mu.Lock()
            for ch := range b.clients {
                close(ch)
            }
            b.mu.Unlock()
            return

        case ch := <-b.register:
            b.mu.Lock()
            b.clients[ch] = struct{}{}
            b.mu.Unlock()

        case ch := <-b.unregister:
            b.mu.Lock()
            delete(b.clients, ch)
            close(ch)
            b.mu.Unlock()

        case event := <-b.broadcast:
            b.mu.RLock()
            for ch := range b.clients {
                select {
                case ch <- event:
                default:
                    // Client too slow, skip this event
                    // (bounded channel, non-blocking send)
                }
            }
            b.mu.RUnlock()
        }
    }
}
```

**Event types:**

| Event | Frequency | Data |
|-------|-----------|------|
| `stats_update` | Every 1s | RPS, blocks/sec, total counts |
| `new_block` | Per block event | Event JSON (truncated) |
| `new_event` | Per logged event | Event JSON (truncated) |
| `config_reload` | On config change | Timestamp only |

The `stats_update` event is sent every second regardless of whether stats changed. This
provides a heartbeat that keeps the connection alive and gives the dashboard a consistent
refresh rate.

### 9.3 API Authentication

```go
func (d *Dashboard) authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Skip auth for static files
        if strings.HasPrefix(r.URL.Path, "/static/") {
            next.ServeHTTP(w, r)
            return
        }

        // Check API key in header
        key := r.Header.Get("X-GuardianWAF-Key")
        if key == "" {
            // Check query parameter (for SSE connections from browser)
            key = r.URL.Query().Get("api_key")
        }

        if !secureCompare(key, d.apiKey) {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        next.ServeHTTP(w, r)
    })
}
```

**API key generation on first run:**

```go
func generateAPIKey() string {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        panic("crypto/rand failed: " + err.Error())  // only panic: system broken
    }
    return hex.EncodeToString(b)
}
```

The generated key is written back to the config file (or a separate state file) so it
persists across restarts. `secureCompare` uses `crypto/subtle.ConstantTimeCompare` to
prevent timing attacks.

---

## 10. MCP Server Implementation

```
internal/mcp/server.go
```

**Protocol:** JSON-RPC 2.0 over stdio (stdin/stdout).

**Message framing:** Newline-delimited JSON. Each JSON-RPC message is a single line
terminated by `\n`. This is the standard MCP transport for stdio.

**Server loop:**

```go
func (s *MCPServer) Serve(ctx context.Context) error {
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB max message

    for scanner.Scan() {
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }

        line := scanner.Bytes()
        var req JSONRPCRequest
        if err := json.Unmarshal(line, &req); err != nil {
            s.sendError(nil, -32700, "Parse error")
            continue
        }

        // Dispatch to handler
        result, err := s.dispatch(req.Method, req.Params)
        if err != nil {
            s.sendError(req.ID, err.Code, err.Message)
            continue
        }

        s.sendResult(req.ID, result)
    }
    return scanner.Err()
}
```

**Tool registration:**

```go
func (s *MCPServer) registerTools() {
    s.tools = map[string]Tool{
        "guardianwaf_get_stats": {
            Description: "Get current WAF statistics",
            InputSchema: JSONSchema{Type: "object", Properties: map[string]JSONSchema{}},
            Handler:     s.handleGetStats,
        },
        "guardianwaf_get_events": {
            Description: "Search and filter WAF events",
            InputSchema: JSONSchema{
                Type: "object",
                Properties: map[string]JSONSchema{
                    "limit":  {Type: "integer", Description: "Max events to return"},
                    "offset": {Type: "integer", Description: "Pagination offset"},
                    "action": {Type: "string", Enum: []string{"blocked", "logged", "allowed"}},
                    "ip":     {Type: "string", Description: "Filter by IP address"},
                },
            },
            Handler: s.handleGetEvents,
        },
        // ... remaining tools
    }
}
```

**Error codes:** Standard JSON-RPC error codes:
- `-32700`: Parse error
- `-32600`: Invalid request
- `-32601`: Method not found
- `-32602`: Invalid params
- `-32603`: Internal error

Application-specific errors use codes in the `-32000` to `-32099` range:
- `-32000`: WAF engine error
- `-32001`: Invalid IP address
- `-32002`: Rule not found
- `-32003`: Config validation failed

---

## 11. Performance Optimization Strategy

### 11.1 Hot Path Optimization

The "hot path" is the code executed for every request. Optimizations here have the
highest leverage.

**Optimization priority list (by measured impact):**

| # | Optimization | Expected Impact | Implementation |
|---|-------------|-----------------|----------------|
| 1 | sync.Pool for RequestContext | -200 bytes alloc/req | Pool with pre-allocated fields |
| 2 | Hand-written SQL tokenizer | 10-100x faster than regex | State machine lexer |
| 3 | Trie-based keyword lookup | 2x faster than map | Pre-built at init |
| 4 | Atomic operations for counters | No lock contention | atomic.Int64, atomic.Uint64 |
| 5 | In-place byte slice normalization | Zero-copy transforms | Modify []byte, single string() |
| 6 | String interning for methods/headers | Eliminate repeated allocs | Package-level constants |
| 7 | sync.Pool for token slices | -1.5KB alloc/req | Pool with cap 64 |
| 8 | Early return on block | Skip expensive layers | Pipeline short-circuit |
| 9 | RWMutex → atomic.Value for config | Zero-cost config reads | atomic.Value swap |
| 10 | Non-blocking event channel | No writer stalls pipeline | Buffered channel with select |

**What we explicitly do NOT optimize:**

- Startup time (happens once; readability > speed)
- Config parsing (happens rarely; correctness > speed)
- Dashboard rendering (separate HTTP server; not on WAF hot path)
- Event serialization (off hot path, in background goroutine)

### 11.2 Benchmarking Approach

**Individual layer benchmarks:**

```go
func BenchmarkIPACL_Lookup_1K_Rules(b *testing.B) {
    tree := buildRadixTree(generateCIDRs(1000))
    ip := net.ParseIP("192.168.50.1")
    b.ResetTimer()
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        tree.Lookup(ip)
    }
}

func BenchmarkRateLimiter_ExistingBucket(b *testing.B) {
    rl := newRateLimiter(defaultConfig)
    // Pre-warm with 100K IPs
    for i := 0; i < 100_000; i++ {
        rl.Allow(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
    }
    b.ResetTimer()
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        rl.Allow("10.0.50.1")
    }
}

func BenchmarkSQLiTokenizer_ShortInput(b *testing.B) {
    input := "' OR 1=1 --"
    tokenizer := newTokenizer()
    b.ResetTimer()
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        tokens := tokenizer.Tokenize(input)
        tokenizer.ReturnTokens(tokens)
    }
}
```

**Full pipeline benchmarks:**

```go
func BenchmarkFullPipeline_CleanGET(b *testing.B) {
    engine := setupEngine(defaultConfig)
    req := httptest.NewRequest("GET", "/api/users?page=1&limit=20", nil)
    req.Header.Set("User-Agent", "Mozilla/5.0 ...")
    b.ResetTimer()
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        w := httptest.NewRecorder()
        engine.ServeHTTP(w, req)
    }
}

func BenchmarkFullPipeline_SQLiAttack(b *testing.B) {
    engine := setupEngine(defaultConfig)
    req := httptest.NewRequest("GET", "/search?q='+OR+1%3D1+--", nil)
    b.ResetTimer()
    b.ReportAllocs()
    for i := 0; i < b.N; i++ {
        w := httptest.NewRecorder()
        engine.ServeHTTP(w, req)
    }
}
```

**Performance budget enforcement:**

```go
func TestPerformanceBudget(t *testing.T) {
    result := testing.Benchmark(BenchmarkFullPipeline_CleanGET)

    nsPerOp := result.NsPerOp()
    allocsPerOp := result.AllocsPerOp()

    if nsPerOp > 1_000_000 { // 1ms
        t.Errorf("Pipeline latency %dns exceeds 1ms budget", nsPerOp)
    }
    if allocsPerOp > 0 {
        t.Errorf("Pipeline made %d allocations (target: 0)", allocsPerOp)
    }
}
```

This test runs in CI and fails the build if performance regresses beyond the budget.

---

## 12. Error Handling Strategy

### 12.1 Error Classification

| Error Class | Example | Response | Internal Action |
|------------|---------|----------|-----------------|
| Client error | Invalid URL, oversized header | 400 Bad Request | Log at debug level |
| Block | Attack detected | 403 Forbidden | Log at info level, create Event |
| Rate limit | Too many requests | 429 Too Many Requests | Log at info level, create Event |
| Upstream error | Backend returned 502 | 502 Bad Gateway | Log at warn level, circuit breaker notified |
| Upstream timeout | Backend didn't respond | 504 Gateway Timeout | Log at warn level, circuit breaker notified |
| Internal error | Panic in detector | 500 (generic page) | Log at error level with stack trace |
| Config error | Invalid YAML | Startup failure (or reload rejection) | Log at error level, exit (startup) or continue with old config (reload) |

### 12.2 Panic Recovery

```go
func (p *Pipeline) Execute(ctx *RequestContext) {
    defer func() {
        if r := recover(); r != nil {
            // Log the panic with stack trace
            buf := make([]byte, 4096)
            n := runtime.Stack(buf, false)
            log.Printf("PANIC in pipeline: %v\n%s", r, buf[:n])

            // Set a safe response
            ctx.Action = Allow // fail open — controversial but correct
            ctx.BlockReason = ""

            // Record as internal error event
            emitInternalError(ctx, r)
        }
    }()

    for _, layer := range p.layers {
        action := layer.Process(ctx)
        if action == Block {
            return
        }
    }
}
```

**Why fail-open on panic?** A panic in the WAF should not prevent legitimate traffic from
reaching the application. The alternative (fail-closed) would mean a bug in the WAF
blocks all traffic — a worse outcome than allowing a potentially malicious request through.
The panic is logged with full stack trace for immediate investigation.

**Panic prevention:** Each detector is additionally wrapped with its own defer/recover,
so a panic in the SQLi detector does not prevent the XSS detector from running. The
finding from the panicking detector is lost, but all other detectors still contribute
their scores.

### 12.3 Layer Error Contract

```go
type Layer interface {
    // Process inspects the request and may add findings to ctx.
    // Returns the recommended action (Allow, Log, Block).
    // MUST NOT panic.
    // If an internal error occurs, log it and return Allow (fail open).
    Process(ctx *RequestContext) Action

    // Name returns the layer name for logging and metrics.
    Name() string

    // OnConfigReload is called when configuration changes.
    // It MUST NOT block for more than 1 second.
    OnConfigReload(cfg *Config)
}
```

---

## 13. Security Considerations

### 13.1 Dashboard Security

| Measure | Implementation |
|---------|---------------|
| HTTPS only | Dashboard listener always uses TLS. If no cert provided, auto-generate self-signed cert at startup |
| API key auth | 32-byte random key, constant-time comparison |
| Rate limiting | Dashboard endpoints rate-limited (10 req/s per IP) to prevent brute-force |
| SameSite cookies | `SameSite=Strict` on session cookie (if used) |
| CSRF protection | API key requirement serves as CSRF token (not in cookie) |
| CSP headers | `Content-Security-Policy: default-src 'self'; script-src 'self'` |

### 13.2 Log Safety

**Default: no body logging.** The `log_body: false` default prevents sensitive data
(passwords, credit cards, API keys) from appearing in logs. Operators can enable it for
debugging but are warned in the configuration documentation.

**Evidence truncation:** Finding evidence is capped at 128 bytes (see Section 2.2).

**IP anonymization:** Not enabled by default, but the architecture supports it. A future
enhancement could hash or mask the last octet of logged IPs for GDPR compliance.

### 13.3 Data Masking (Response Protection)

```go
func maskCreditCard(input []byte) []byte {
    // Scan for sequences of 13-19 digits (with optional spaces/dashes)
    // Validate with Luhn algorithm
    // Replace middle digits with '*': 4111-****-****-1234
}

func maskSSN(input []byte) []byte {
    // Scan for NNN-NN-NNNN pattern
    // Replace with ***-**-NNNN (keep last 4)
}

func maskAPIKeys(input []byte) []byte {
    // Scan for common patterns:
    //   "api_key": "..." → mask value
    //   "Authorization: Bearer ..." → mask token
    //   Strings matching [A-Za-z0-9]{32,} after key-like names
}
```

Data masking runs on the response body stream. It operates on a bounded buffer (8 KB
lookahead) to handle patterns that span chunk boundaries without buffering the full
response.

### 13.4 Supply Chain Security

The zero-dependency constraint is itself a security measure:
- No transitive dependencies that could be compromised (cf. `event-stream`, `ua-parser-js`).
- No dependency confusion attacks possible.
- Reproducible builds: `go build` with same Go version produces identical binary.
- Binary can be verified with `go build -trimpath` and checksum comparison.

---

## 14. Testing Architecture

### 14.1 Test Layers

```
  ┌──────────────────────────────────────────────────────────────┐
  │  Layer 4: Integration Tests                                   │
  │  Full HTTP client → WAF → mock backend → response             │
  │  Tests complete request lifecycle, config reload, etc.         │
  ├──────────────────────────────────────────────────────────────┤
  │  Layer 3: Fuzz Tests                                          │
  │  Random/mutated inputs → detectors → must not panic           │
  │  Uses Go native fuzzing (go test -fuzz)                       │
  ├──────────────────────────────────────────────────────────────┤
  │  Layer 2: Detector Accuracy Tests                             │
  │  Known attacks → must detect (score >= threshold)             │
  │  Known benign → must not block (score < log_threshold)        │
  │  Edge cases → document expected behavior                      │
  ├──────────────────────────────────────────────────────────────┤
  │  Layer 1: Unit Tests                                          │
  │  Individual functions, data structures, algorithms            │
  │  Radix tree operations, token bucket math, YAML parsing       │
  └──────────────────────────────────────────────────────────────┘
```

### 14.2 Test Fixture Format

Each detector has three fixture files in JSON format:

```json
// testdata/attacks/sqli.json
{
  "payloads": [
    {
      "input": "' OR 1=1 --",
      "location": "query",
      "min_score": 50,
      "description": "Classic tautology SQLi",
      "source": "OWASP Testing Guide"
    },
    {
      "input": "' UNION SELECT username, password FROM users --",
      "location": "query",
      "min_score": 90,
      "description": "Union-based data extraction",
      "source": "Real-world attack pattern"
    }
  ]
}

// testdata/benign/sqli.json
{
  "payloads": [
    {
      "input": "O'Brien",
      "location": "query",
      "max_score": 24,
      "description": "Irish name with apostrophe"
    },
    {
      "input": "SELECT the best product for your needs",
      "location": "body",
      "max_score": 24,
      "description": "Marketing copy containing SQL keyword"
    }
  ]
}
```

**Why JSON for test fixtures?** Go stdlib has `encoding/json` but no YAML parser (and our
custom YAML parser is itself under test, creating a circular dependency). JSON is parsed
natively and is simple enough for structured test data.

### 14.3 Benchmark CI Integration

The CI pipeline runs benchmarks on every PR:

```
1. Run benchmarks on base branch → save results
2. Run benchmarks on PR branch → save results
3. Compare: benchstat base.txt pr.txt
4. Fail if any benchmark regresses by > 10%
5. Warn if allocations increase
```

This catches performance regressions before they reach the main branch.

---

## 15. Package Dependency Graph

```
                                 cmd/guardianwaf/main.go
                                         │
                         ┌───────────────┼───────────────┐
                         │               │               │
                         ▼               ▼               ▼
                   internal/        internal/       internal/
                   dashboard/       mcp/            proxy/
                         │               │               │
                         └───────┬───────┘               │
                                 │                       │
                                 ▼                       ▼
                          internal/engine/ ◄─────────────┘
                                 │
                    ┌────────────┼────────────┐
                    │            │            │
                    ▼            ▼            ▼
             internal/     internal/    internal/
             layers/       events/      analytics/
                │
    ┌───────┬──┴──┬────────┬──────────┬──────────┐
    │       │     │        │          │          │
    ▼       ▼     ▼        ▼          ▼          ▼
  ipacl  ratelimit sanitizer detection botdetect response
                              │
               ┌──────┬──────┼──────┬──────┬──────┐
               │      │      │      │      │      │
               ▼      ▼      ▼      ▼      ▼      ▼
             sqli   xss    lfi    cmdi   xxe    ssrf

                          internal/config/  (used by all packages)
                          internal/tls/     (used by proxy and dashboard)
```

**Public API surface** (the library mode entrypoint):

```
  guardianwaf.go           → New(), NewFromFile(), Config struct
  options.go               → functional options: WithMode(), WithThreshold(), etc.
                                    │
                                    ▼
                             internal/engine/
```

The public API in the root package is a thin facade over `internal/engine`. This keeps
the public surface minimal while allowing the internal packages full flexibility.

**Dependency rules:**
- `internal/layers/*` packages MUST NOT import each other (horizontal isolation).
- `internal/engine` imports `internal/layers/*` but not vice versa.
- `internal/config` is imported by everything (config types are shared).
- `internal/proxy` imports `internal/engine` (to run the WAF pipeline).
- `internal/dashboard` imports `internal/engine` and `internal/events`.
- `internal/mcp` imports `internal/engine`.
- No package imports `cmd/guardianwaf` (the entrypoint imports everything, nothing imports it).

---

## Appendix A: Decision Log

| # | Decision | Alternatives | Rationale |
|---|----------|-------------|-----------|
| D1 | sync.Pool for RequestContext | Per-request alloc | GC pressure at 50K RPS unacceptable |
| D2 | Patricia trie for IP ACL | HashMap, sorted slice, bloom filter | Only data structure supporting CIDR + longest-prefix match |
| D3 | Token bucket for rate limiting | Sliding window, leaky bucket, fixed window | Best burst handling + constant memory + no background goroutine |
| D4 | Hand-written SQL tokenizer | regexp, ANTLR-like parser | 10-100x faster, zero allocation, deterministic |
| D5 | sync.Map for rate limit buckets | map + RWMutex, sharded map | Optimal for append-mostly pattern |
| D6 | Ring buffer for events | Unbounded slice, database | Bounded memory, O(1) write |
| D7 | SSE over WebSocket for dashboard | WebSocket, polling | Simpler, auto-reconnect, sufficient for unidirectional updates |
| D8 | Line-by-line YAML parser | Recursive descent, PEG | Simplest correct approach for the supported subset |
| D9 | FNV hash for IP-hash LB | SHA256, CRC32, xxHash | Fast, stdlib, good distribution for this use case |
| D10 | Fail-open on panic | Fail-closed | WAF bug should not block all production traffic |
| D11 | Manual config field mapping | Reflection-based | Compile-time safety, clear error messages |
| D12 | 128-byte evidence truncation | Full payload, no evidence | Balance between debuggability and log safety |
| D13 | atomic.Value for config | RWMutex, channel-based | Zero-cost reads on hot path |
| D14 | ECDSA P-256 for ACME | RSA 2048, RSA 4096 | Faster signing, smaller key, same security level |
| D15 | Bounded path set (256 slots) | HyperLogLog, exact map | Simple, bounded memory, sufficient accuracy |
| D16 | Single-writer event channel | Mutex-protected ring buffer | No lock on write path, natural backpressure |
| D17 | os.Stat polling for config watch | fsnotify, inotify | Cross-platform, zero-dependency, 5s granularity sufficient |
| D18 | Inline `[6]time.Duration` array | Slice, map | Zero allocation, no pointer indirection |
| D19 | Per-detector panic recovery | Single pipeline recovery | One buggy detector doesn't disable others |
| D20 | JSON test fixtures (not YAML) | YAML fixtures | Avoids circular dependency with custom YAML parser |

---

## Appendix B: Performance Budget Summary

```
┌────────────────────────────────────────────────────────────────┐
│                    Per-Request Time Budget                       │
│                                                                 │
│  Layer 1: IP ACL ────────────── 100 ns  ─  ██                  │
│  Layer 2: Rate Limiter ──────── 500 ns  ─  ██████              │
│  Layer 3: Sanitizer ──────────  50 μs   ─  ██████████████████  │
│  Layer 4: Detection ──────────  500 μs  ─  ████████████████... │
│    ├─ SQLi tokenizer ────────── 200 μs  ─  ████████████        │
│    ├─ XSS scanner ───────────── 150 μs  ─  ████████            │
│    ├─ LFI checker ───────────── 30 μs   ─  ██                  │
│    ├─ CMDi checker ──────────── 50 μs   ─  ███                 │
│    ├─ XXE checker ───────────── 20 μs   ─  █                   │
│    └─ SSRF checker ──────────── 50 μs   ─  ███                 │
│  Layer 5: Bot Detection ──────  100 μs  ─  ██████              │
│    ├─ JA3 lookup ────────────── 50 μs   ─  ███                 │
│    ├─ UA analysis ───────────── 20 μs   ─  █                   │
│    └─ Behavior check ────────── 30 μs   ─  ██                  │
│  Layer 6: Response ───────────  10 μs   ─  █                   │
│                                                                 │
│  Pipeline overhead ───────────  10 μs   ─  █                   │
│  ─────────────────────────────────────────                      │
│  TOTAL (clean request) ────── ~670 μs       Budget: < 1 ms     │
│  TOTAL (attack, early exit) ─ ~100 μs       (blocked at L1/L2) │
│  TOTAL (attack, full scan) ── ~700 μs       Budget: < 2 ms     │
└────────────────────────────────────────────────────────────────┘
```

---

## Appendix C: Concurrency Primitives Cheat Sheet

| Component | Primitive | Hot Path? | Rationale |
|-----------|-----------|-----------|-----------|
| Config access | `atomic.Value` | Yes | Lock-free reads |
| IP ACL trees | `sync.RWMutex` | Yes (read) | Many readers, rare writers |
| Rate limit buckets (map) | `sync.Map` | Yes | Append-mostly pattern |
| Rate limit bucket (individual) | `sync.Mutex` | Yes | Short critical section per bucket |
| Behavior tracker map | `sync.RWMutex` | Yes (read) | Many readers, periodic cleanup |
| Event ring buffer (write) | Buffered channel | No (background) | Single-writer serialization |
| Event ring buffer (read) | `sync.RWMutex` | No (dashboard) | Infrequent dashboard queries |
| Circuit breaker state | `atomic.Int32` | Yes | Single field, atomic sufficient |
| Health check state | `atomic.Int32` | Yes | Single field, atomic sufficient |
| Backend connection count | `atomic.Int64` | Yes | Least-connections LB needs atomic counter |
| JA3 store (conn→hash) | `sync.Map` | Yes | Write on TLS handshake, read on request |
| SSE client registry | `sync.RWMutex` | No (dashboard) | Register/unregister are rare |
| Analytics counters | `atomic.Uint64` | No (background) | Counters incremented from event writer |
| TopK heap | `sync.Mutex` | No (background) | Short critical section, low frequency |
| RequestContext pool | `sync.Pool` | Yes | Built-in GC integration |

---

*This document is the authoritative reference for all implementation decisions in
GuardianWAF. Code that deviates from these decisions must update this document first.*
