# GuardianWAF — Technical Specification

> **Version:** 1.0.0-draft
> **Author:** Ersin Koc / ECOSTACK TECHNOLOGY OU
> **Repository:** `github.com/guardianwaf/guardianwaf`
> **Domain:** guardianwaf.com
> **Status:** Specification Phase

---

## 1. Overview

### 1.1 Project Identity

| Field | Value |
|-------|-------|
| Project Name | GuardianWAF |
| Binary Name | `guardianwaf` |
| Go Module | `github.com/guardianwaf/guardianwaf` |
| Config File | `guardianwaf.yaml` or `guardianwaf.yml` |
| Short Name | `gwaf` (for CLI aliases) |
| Tagline | "Zero-dependency WAF. One binary. Total protection." |
| Min Go Version | 1.22 |
| License | Apache 2.0 |

### 1.2 Value Proposition

GuardianWAF is the **only** open-source WAF that satisfies all of the following constraints simultaneously:

- **Zero external dependencies** — no `go.mod` `require` entries beyond the standard library. Every component (YAML parser, radix tree, ACME client, HTTP router, dashboard templates, JA3 fingerprinting) is implemented from scratch.
- **Single binary** — one `go build` produces a fully self-contained executable. No sidecar databases, no Lua/PCRE runtimes, no external rule files required at startup.
- **Three deployment modes** — standalone reverse proxy, embeddable Go middleware library, and minimal sidecar proxy, all from the same codebase.
- **Tokenizer-based detection** — hand-written lexers for SQL, HTML/JS, shell, and XML produce typed token streams. Pattern matching operates on tokens, not raw regex. This enables graduated scoring with dramatically fewer false positives.
- **Built-in web dashboard** — embedded HTML/CSS/JS served from the binary. Real-time stats, event log, configuration editing, no external frontend build required.
- **MCP server** — Model Context Protocol endpoint so AI assistants can query WAF state, review events, and adjust configuration.

### 1.3 Competitive Positioning

| Feature | GuardianWAF | SafeLine | Coraza | ModSecurity | NAXSI |
|---------|-------------|----------|--------|-------------|-------|
| **Language** | Go (pure) | Go + ? | Go | C/C++ | C (nginx module) |
| **External Dependencies** | 0 | Many | Many | libpcre, libxml2, libyajl | nginx only |
| **Deployment: Standalone** | Yes | Yes | No (library) | No (module) | No (module) |
| **Deployment: Library** | Yes | No | Yes | No | No |
| **Deployment: Sidecar** | Yes | No | No | No | No |
| **Detection Method** | Tokenizer + Scoring | Semantic + ML | Regex (CRS rules) | Regex (CRS rules) | Regex + Scoring |
| **UI Dashboard** | Built-in (embedded) | Separate container | None | None | None |
| **MCP Server** | Built-in | No | No | No | No |
| **Configuration** | YAML (custom parser) | Web UI | Go API / directives | SecLang directives | nginx directives |
| **False Positive Mgmt** | Score multipliers per-detector | ML-based | Anomaly scoring | Anomaly scoring | Score thresholds |
| **Single Binary** | Yes | No (Docker) | N/A (library) | No (module) | No (module) |
| **TLS Fingerprinting** | JA3/JA4 built-in | Unknown | No | No | No |
| **Auto-TLS (ACME)** | Built-in | Via proxy | N/A | N/A | N/A |


---

## 2. Architecture

### 2.1 Three Deployment Modes

#### Mode 1: Standalone Reverse Proxy

```
Command:  guardianwaf serve
```

This is the primary deployment mode. GuardianWAF operates as a full reverse proxy sitting between clients and upstream application servers.

**Capabilities:**
- TLS termination with automatic certificate management via built-in ACME client (Let's Encrypt / ZeroSSL)
- Manual TLS with user-provided certificates
- HTTP/1.1 and HTTP/2 support (via Go standard library)
- Built-in web dashboard on configurable admin port
- REST API for programmatic control
- MCP server for AI assistant integration
- Event storage and querying
- Real-time metrics and statistics
- Hot-reload of configuration via SIGHUP or API

**Use case:** Drop-in WAF in front of any HTTP backend without modifying application code.

#### Mode 2: Embeddable Go Library

```go
import "github.com/guardianwaf/guardianwaf/engine"

waf, err := engine.New(engine.WithConfigFile("guardianwaf.yaml"))
// or
waf, err := engine.New(
    engine.WithBlockThreshold(50),
    engine.WithSQLiDetector(true),
    engine.WithXSSDetector(true),
)

http.Handle("/", waf.Wrap(myHandler))
```

**Capabilities:**
- Standard `http.Handler` middleware wrapper
- Zero overhead when disabled (short-circuit check)
- Configuration via Go API (functional options) or YAML file
- Findings available in request context for application-level decisions
- No goroutines spawned when idle
- No dashboard, no MCP, no admin API (application provides its own)

**Use case:** Embed WAF protection directly into Go applications, equivalent to how Coraza is used.

#### Mode 3: Sidecar Proxy

```
Command:  guardianwaf sidecar --upstream localhost:8080
```

**Capabilities:**
- Minimal footprint: < 20MB memory, < 100ms cold start
- No dashboard, no MCP server, no admin API
- Configuration via YAML file or environment variables
- Stdout/stderr structured logging only
- Health check endpoint (`/healthz`)
- Graceful shutdown on SIGTERM

**Use case:** Kubernetes sidecar container, Docker Compose service, systemd unit alongside application.

#### Architecture Diagram

```
+---------------------------------------------------------------------+
|                        DEPLOYMENT MODES                              |
|                                                                      |
|  +-------------------+  +--------------------+  +------------------+ |
|  |   STANDALONE      |  |   EMBEDDABLE       |  |   SIDECAR        | |
|  |   REVERSE PROXY   |  |   GO LIBRARY       |  |   PROXY          | |
|  |                   |  |                    |  |                  | |
|  |  guardianwaf      |  |  engine.New()      |  |  guardianwaf     | |
|  |  serve            |  |  waf.Wrap(h)       |  |  sidecar         | |
|  |                   |  |                    |  |                  | |
|  |  + Dashboard      |  |  - Dashboard       |  |  - Dashboard     | |
|  |  + MCP Server     |  |  - MCP Server      |  |  - MCP Server    | |
|  |  + REST API       |  |  - REST API        |  |  - REST API      | |
|  |  + ACME/TLS       |  |  - ACME/TLS        |  |  + ACME/TLS opt  | |
|  |  + Event Store    |  |  + Event Store     |  |  - Event Store   | |
|  |  + Admin Port     |  |  - Admin Port      |  |  + Health Check  | |
|  +--------+----------+  +--------+-----------+  +--------+---------+ |
|           |                      |                       |           |
|           +----------------------+-----------------------+           |
|                                  |                                   |
|                                  v                                   |
|  +--------------------------------------------------------------+   |
|  |                       CORE ENGINE                             |   |
|  |                                                               |   |
|  |   +----------+  +----------+  +----------+  +------------+   |   |
|  |   | IP ACL   |->| Rate     |->| Request  |->| Detection  |   |   |
|  |   | Layer    |  | Limiter  |  | Sanitizer|  | Engine     |   |   |
|  |   |          |  |          |  |          |  |            |   |   |
|  |   | Radix    |  | Token    |  | Normalize|  | SQLi       |   |   |
|  |   | Tree     |  | Bucket   |  | Validate |  | XSS        |   |   |
|  |   | O(k)     |  | Per-Scope|  | Clean    |  | LFI        |   |   |
|  |   +----------+  +----------+  +----------+  | CMDi       |   |   |
|  |                                              | XXE        |   |   |
|  |   +----------+  +----------+                 | SSRF       |   |   |
|  |   | Bot      |->| Response |                 +------------+   |   |
|  |   | Detection|  | Protection                                  |   |
|  |   |          |  |          |                                   |   |
|  |   | JA3/JA4  |  | Headers  |                                  |   |
|  |   | UA Parse |  | Masking  |                                  |   |
|  |   | Behavior |  | Errors   |                                  |   |
|  |   +----------+  +----------+                                  |   |
|  +--------------------------------------------------------------+   |
+---------------------------------------------------------------------+
```

### 2.2 Core Engine — 6-Layer Pipeline

Every HTTP request passes through a strict 6-layer pipeline. Each layer is an independent Go package implementing the `Layer` interface. Layers execute sequentially; any layer can short-circuit the pipeline by returning `ActionBlock`.

```
                            REQUEST
                               |
                               v
                  +------------------------+
             1    |   IP ACCESS CONTROL    |  Radix tree lookup
                  |   internal/layers/     |  O(k) where k = prefix bits
                  |   ipacl/               |
                  +-----------+------------+
                       PASS   |   BLOCK -> 403
                              v
                  +------------------------+
             2    |    RATE LIMITER        |  Token bucket per scope
                  |    internal/layers/    |  (IP, IP+path, global)
                  |    ratelimit/          |
                  +-----------+------------+
                       PASS   |   BLOCK -> 429
                              v
                  +------------------------+
             3    |  REQUEST SANITIZER     |  Normalize, validate, clean
                  |  internal/layers/      |  URL decode, null bytes,
                  |  sanitizer/            |  path canonicalization
                  +-----------+------------+
                       PASS   |   BLOCK -> 400 (malformed)
                              v
                  +------------------------+
             4    |  DETECTION ENGINE      |  SQLi, XSS, LFI, CMDi,
                  |  internal/layers/      |  XXE, SSRF tokenizers
                  |  detection/            |  Score accumulation
                  +-----------+------------+
                       PASS   |   BLOCK -> 403 (score >= threshold)
                              v
                  +------------------------+
             5    |   BOT DETECTION        |  JA3/JA4, UA analysis,
                  |   internal/layers/     |  behavioral scoring
                  |   botdetect/           |
                  +-----------+------------+
                       PASS   |   BLOCK -> 403 / CHALLENGE
                              v
                +----------------------------+
                |     UPSTREAM PROXY         |  Forward to backend
                |     (reverse proxy)        |  Wait for response
                +-----------+----------------+
                            |
                            v
                  +------------------------+
             6    |  RESPONSE PROTECTION   |  Security headers,
                  |  internal/layers/      |  data masking,
                  |  response/             |  error sanitization
                  +-----------+------------+
                              |
                              v
                           RESPONSE
```

**Layer Properties:**

| # | Layer | Package | Short-Circuit | HTTP Code | Input |
|---|-------|---------|---------------|-----------|-------|
| 1 | IP Access Control | `internal/layers/ipacl` | Yes | 403 | Remote IP |
| 2 | Rate Limiter | `internal/layers/ratelimit` | Yes | 429 | Remote IP + path |
| 3 | Request Sanitizer | `internal/layers/sanitizer` | Yes (malformed) | 400 | Full request |
| 4 | Detection Engine | `internal/layers/detection` | Yes (score threshold) | 403 | Normalized request |
| 5 | Bot Detection | `internal/layers/botdetect` | Yes | 403 / Challenge | TLS info + headers + behavior |
| 6 | Response Protection | `internal/layers/response` | No (post-proxy) | — | Upstream response |

**Layer Independence Contract:**
- Each layer is its own Go package under `internal/layers/`
- Each layer implements the `Layer` interface
- Each layer has its own config section in YAML
- Each layer can be independently enabled, disabled, or set to monitor mode
- Each layer produces `Finding` structs that accumulate in `RequestContext`
- Each layer has its own test suite with >90% coverage target
- No layer imports another layer's package (communicate only via `RequestContext`)

### 2.3 Interface Definitions

All core types live in `pkg/types/`. Every layer and detector depends on these types. No circular imports.

#### Layer Interface

```go
package types

type Layer interface {
    Name() string
    Process(ctx *RequestContext) LayerResult
    Enabled() bool
    SetEnabled(enabled bool)
    Mode() LayerMode
    SetMode(mode LayerMode)
    Reload(config interface{}) error
}

type LayerMode string
const (
    LayerModeEnforce  LayerMode = "enforce"
    LayerModeMonitor  LayerMode = "monitor"
    LayerModeDisabled LayerMode = "disabled"
)

type LayerResult struct {
    Action   Action
    Findings []Finding
    Error    error
}

type Action int
const (
    ActionAllow Action = iota
    ActionBlock
    ActionLog
    ActionChallenge
)
```

#### Finding and Location

```go
type Finding struct {
    DetectorName string       // "sqli", "xss", "lfi", "cmdi", "xxe", "ssrf", "botdetect"
    RuleName     string       // "union-select", "script-tag", etc.
    Score        int          // 0-100
    Evidence     string       // Truncated input (max 200 chars)
    Location     Location
    Description  string       // Human-readable
}

type Location struct {
    Type  LocationType // path, query_param, body, header, cookie
    Name  string       // Parameter/header/cookie name
    Value string       // Matched value (truncated)
}

type LocationType string
const (
    LocationPath       LocationType = "path"
    LocationQueryParam LocationType = "query_param"
    LocationBody       LocationType = "body"
    LocationHeader     LocationType = "header"
    LocationCookie     LocationType = "cookie"
)
```

#### RequestContext

```go
type RequestContext struct {
    // Original request
    Request    *http.Request
    RemoteIP   net.IP
    RequestID  string    // UUIDv4
    ReceivedAt time.Time

    // Normalized (populated by sanitizer)
    NormalizedPath    string
    NormalizedQuery   map[string][]string
    NormalizedBody    []byte
    NormalizedHeaders map[string][]string

    // TLS (for bot detection)
    TLSInfo *TLSInfo

    // Accumulated results
    Findings   []Finding
    TotalScore int
    Action     Action

    // Internal
    bodyRead bool
    pool     *sync.Pool
}

type TLSInfo struct {
    Version      uint16
    CipherSuites []uint16
    Extensions   []uint16
    Curves       []tls.CurveID
    Points       []uint8
    ServerName   string
    JA3Hash      string  // MD5(SSLVersion,Ciphers,Extensions,Curves,Points)
}
```

#### Detector Interface

```go
type Detector interface {
    Name() string
    Detect(ctx *RequestContext, input string, location Location) []Finding
    Enabled() bool
    SetEnabled(enabled bool)
    Multiplier() float64       // Default 1.0, range 0.0-5.0
    SetMultiplier(m float64)
}
```

#### Event and EventStore

```go
type Event struct {
    ID           string    `json:"id"`
    Timestamp    time.Time `json:"timestamp"`
    RemoteIP     string    `json:"remote_ip"`
    Method       string    `json:"method"`
    Path         string    `json:"path"`
    Query        string    `json:"query"`
    UserAgent    string    `json:"user_agent"`
    TotalScore   int       `json:"total_score"`
    Action       string    `json:"action"`
    Findings     []Finding `json:"findings"`
    RequestID    string    `json:"request_id"`
    ResponseCode int       `json:"response_code"`
}

type EventStore interface {
    Store(event Event) error
    Query(filter EventFilter) ([]Event, int, error)
    Get(id string) (*Event, error)
    Close() error
}

type EventFilter struct {
    Limit     int
    Offset    int
    Since     time.Time
    Until     time.Time
    Action    string     // "", "blocked", "logged", "allowed"
    RemoteIP  string
    MinScore  int
    Detectors []string
    SortBy    string     // "timestamp", "score"
    SortOrder string     // "asc", "desc"
}
```

#### Result (Public API)

```go
type Result struct {
    Blocked    bool          `json:"blocked"`
    Logged     bool          `json:"logged"`
    TotalScore int           `json:"total_score"`
    Findings   []Finding     `json:"findings"`
    Action     string        `json:"action"`
    RequestID  string        `json:"request_id"`
    Duration   time.Duration `json:"duration"`
}
```


---

## 3. Scoring System

### 3.1 Score Mechanics

Every detection rule produces a **threat score** in the range 0 to 100. Scores from all active detectors accumulate per request. The total score determines the final action.

**Decision logic:**

```
total_score = sum(finding.Score * detector.Multiplier for each finding)

if total_score >= block_threshold:    -> Block (respond 403)
elif total_score >= log_threshold:    -> Log (allow, record event)
else:                                 -> Allow (silently pass)
```

**Default thresholds:**

| Threshold | Default Value | Config Key | Range |
|-----------|--------------|------------|-------|
| Block | 50 | `engine.block_threshold` | 1-200 |
| Log | 25 | `engine.log_threshold` | 0-199 |

**Constraints:**
- `block_threshold` must be > `log_threshold`
- Both are configurable per-deployment in YAML
- Can be overridden per-path via path rules (see Section 9)

### 3.2 Score Multipliers

Each detector has a configurable **multiplier** that scales its raw scores.

| Multiplier | Effect | Use Case |
|------------|--------|----------|
| 0.0 | Score 0 (effectively disabled) | Disable noisy detector |
| 0.5 | Half sensitivity | Reduce false positives |
| 1.0 | Default — raw scores as-is | Normal operation |
| 1.5 | 50% more sensitive | High-value targets |
| 2.0 | Double sensitivity | Paranoia mode |
| 5.0 | Hard upper limit | Extreme cases only |

**Formula:** `final_score = min(100, int(raw_score * multiplier))`

### 3.3 Why Scoring Beats Binary Rules

Graduated response eliminates most false positives:

| Input | Tokens Found | Score | Action (threshold=50) |
|-------|-------------|-------|-----------------------|
| `O'Brien` | STRING_LITERAL | 10 | Allow — common name |
| `O'Brien OR` | STRING_LITERAL + KEYWORD(OR) | 30 | Log — suspicious |
| `' OR 1=1` | STRING_LITERAL + KEYWORD(OR) + tautology | 85 | Block — definite SQLi |
| `' OR 1=1--` | + tautology + COMMENT | 90 | Block — classic SQLi |
| `' UNION SELECT * FROM users--` | UNION + SELECT + WILDCARD + FROM + COMMENT | 95 | Block — union-based |

### 3.4 Score Capping

- **Per-finding cap:** 100 (after multiplier)
- **Per-detector-per-location:** highest score wins (no double-counting within same detector for same location)
- **Cross-detector:** always accumulate (different detectors add up)
- **Total score:** no upper cap (SQLi 50 + XSS 30 + bot 40 = 120)


---

## 4. Detector Specifications

All detectors live under `internal/layers/detection/`. Each is its own sub-package implementing the `Detector` interface.

### 4.1 SQL Injection Detector (`internal/layers/detection/sqli/`)

#### 4.1.1 Tokenizer

Hand-written lexer parsing input into SQL token stream. Token types: STRING_LITERAL, NUMERIC_LITERAL, KEYWORD (SELECT, UNION, OR, AND, DROP, INSERT, UPDATE, DELETE, FROM, WHERE, HAVING, GROUP BY, ORDER BY, LIMIT, INTO, EXEC, EXECUTE, DECLARE, SET, TRUNCATE, ALTER, CREATE, NULL, NOT, EXISTS, CASE, WHEN, THEN, ELSE, END, JOIN, TABLE, DATABASE, SCHEMA, IF, WHILE, WAITFOR, DELAY, GRANT, REVOKE), OPERATOR (=, <>, !=, >=, <=, LIKE, IN, BETWEEN, IS), FUNCTION (COUNT, SUM, AVG, MAX, MIN, SLEEP, BENCHMARK, WAITFOR, DELAY, LOAD_FILE, OUTFILE, DUMPFILE, CHAR, CONCAT, SUBSTRING, ASCII, ORD, HEX, UNHEX, MD5, SHA1, CONVERT, CAST, GROUP_CONCAT, EXTRACTVALUE, UPDATEXML, XMLTYPE, UTL_HTTP, DBMS_PIPE), COMMENT (--, #, /* */), PAREN_OPEN, PAREN_CLOSE, SEMICOLON, COMMA, WILDCARD, DOT, OTHER.

#### 4.1.2 Pattern Scoring Rules

| Pattern | Score | Reason |
|---------|-------|--------|
| STRING_LITERAL + KEYWORD(OR/AND) | 30 | Partial match |
| + tautology (1=1, 2>1) | +55 | SQLi tautology |
| UNION + SELECT | 90 | Union-based injection |
| SEMICOLON + DROP/DELETE/TRUNCATE | 95 | Stacked destructive query |
| SEMICOLON + INSERT/UPDATE/ALTER | 85 | Stacked modification |
| FUNCTION(SLEEP/BENCHMARK/WAITFOR) | 90 | Blind/time-based |
| FUNCTION(LOAD_FILE/OUTFILE/DUMPFILE) | 100 | File access — critical |
| INTO + OUTFILE/DUMPFILE | 100 | Data exfiltration |
| COMMENT after STRING_LITERAL | 35 | Evasion technique |
| EXEC/EXECUTE + STRING_LITERAL | 80 | Stored procedure |
| CHAR/CONCAT + nested parens | 50 | Obfuscation |
| EXTRACTVALUE/UPDATEXML/XMLTYPE | 85 | Error-based injection |
| Hex literal in comparison | 40 | Obfuscation |
| Isolated SQL keyword | 10 | Benign/contextual |
| Double-encoded chars | 75 | Encoding evasion |
| INFORMATION_SCHEMA / system tables | 80 | Schema enumeration |
| GROUP_CONCAT + FROM | 75 | Data extraction |

#### 4.1.3 Evasion Handling

- **Delimiters:** single quote, double quote, backtick (MySQL), bracket (MSSQL)
- **Multi-DB keywords:** union of MySQL, PostgreSQL, MSSQL, SQLite, Oracle
- **Whitespace:** comments as whitespace (UNION/**/SELECT), tabs, newlines, multi-space
- **Case insensitivity:** select = SELECT = SeLeCt
- **Encoding:** %27, %2527 (double), %u0027, \x27, &#39;, &#x27;
- **Comment injection:** UN/**/ION, SE/**/LECT, nested MySQL comments
- **Null bytes:** stripped by sanitizer, defense-in-depth strip in detector

#### 4.1.4 Scan Locations

URL path, query params (each value), form body (each field), JSON body (each string recursively), cookie values, Referer header, User-Agent header (multiplier 0.5).

### 4.2 XSS Detector (`internal/layers/detection/xss/`)

#### 4.2.1 Detection Approach

Lightweight HTML-aware tokenizer identifying tag boundaries, attribute names/values. Targets reflected and stored XSS.

#### 4.2.2 Pattern Scoring Rules

| Pattern | Score | Reason |
|---------|-------|--------|
| `<script` tag | 90 | Script injection |
| Complete `<script>...</script>` | 95 | Full script tag |
| HTML tag + on[event]= handler | 85 | Event handler injection |
| `javascript:` protocol | 80 | JS protocol handler |
| `vbscript:` protocol | 80 | VBScript (IE legacy) |
| `data:text/html` | 75 | Data URI HTML |
| `data:application/javascript` | 80 | Data URI JS |
| `expression(` | 70 | IE CSS expression |
| `document.cookie` | 60 | Cookie theft |
| DOM write methods | 55 | DOM injection |
| `innerHTML`/`outerHTML` | 50 | DOM property injection |
| `window.location` | 45 | Navigation manipulation |
| `Function(` constructor | 60 | Code execution |
| Timed execution with string arg | 55 | Delayed execution |
| `<iframe` | 50 | Frame injection |
| `<object`/`<embed`/`<applet` | 45 | Plugin injection |
| `<form` + `action=` | 40 | Form hijack |
| `<base` + `href=` | 60 | Base URL hijack |
| `<meta http-equiv=refresh` | 50 | Redirect injection |
| `on[a-z]+=` generic handler | 70 | Event handler |
| SVG + onload | 85 | SVG payload |
| Encoded `<` (\x3c, \u003c, entities) | +20 | Evasion bonus |
| Template syntax | 45 | SSTI indicator |

#### 4.2.3 Evasion Handling

- Case variations, attribute encoding, null bytes, whitespace in tags
- SVG-specific: onload, animate/onbegin, set element
- Template injection: Jinja2, JS template literals, ERB, Freemarker

### 4.3 Path Traversal Detector (`internal/layers/detection/lfi/`)

| Pattern | Score | Reason |
|---------|-------|--------|
| `../` single | 30 | Could be legit |
| `../../` double | 45 | Suspicious |
| `../../..` triple+ | 65 | Almost certainly malicious |
| `/etc/passwd` | 90 | Classic LFI target |
| `/etc/shadow` | 95 | Shadow passwords |
| `/proc/self/environ` | 90 | Credential theft |
| `/proc/self/fd/` | 85 | File descriptor access |
| Windows paths (`C:\`, `\windows\system32`) | 55-80 | OS-specific |
| Encoded traversal (%2f, %252f) | 75-80 | URL encoding evasion |
| Overlong UTF-8 (%c0%af, %c1%9c) | 95 | Deliberate evasion |
| Filter bypass (`....//`, `..;/`) | 65-70 | Bypass techniques |
| PHP wrappers (php://, expect://) | 85-90 | Code execution |
| Normalization evasion bonus | +25 | Raw != normalized with `..` |

Embedded sensitive file lists: Linux (~30 paths), Windows (~20 paths), macOS (~15 paths).

### 4.4 Command Injection Detector (`internal/layers/detection/cmdi/`)

| Pattern | Score | Reason |
|---------|-------|--------|
| `;` + command | 75 | Semicolon chaining |
| `\|` + command | 65 | Pipe |
| Backtick/`$(...)` subshell | 80 | Subshell execution |
| `&&`/`\|\|` + command | 65 | Logical chaining |
| Redirect (`>`, `>>`, `<`) | 40-45 | I/O redirection |
| Recon commands (id, whoami) | 65 | Info gathering |
| Network commands (nc, curl, wget) | 75 | Exfiltration |
| Shell paths (/bin/sh, /bin/bash) | 90 | Explicit shell |
| Windows shell (cmd.exe, powershell) | 90 | Windows shell |
| Interpreter -c/-e flags | 80 | Code execution |
| base64 + pipe | 85 | Obfuscated payload |
| Newline injection | 55-60 | Header splitting |
| Environment vars ($PATH, IFS) | 50 | Probing/evasion |
| Permission/process cmds | 60-75 | System modification |
| Isolated keyword | 15 | Low confidence |

60+ embedded command keywords covering Unix, Windows, databases, network tools.

### 4.5 XXE Detector (`internal/layers/detection/xxe/`)

Conditional detector — activated only when Content-Type contains `xml`, `soap`, or `rss`.

| Pattern | Score | Reason |
|---------|-------|--------|
| `<!DOCTYPE` | 25 | Could be legitimate |
| `<!ENTITY` | 65 | Suspicious in user input |
| SYSTEM + file:// | 95 | Local file inclusion |
| SYSTEM + http(s):// | 70-75 | SSRF via XXE |
| SYSTEM + expect:// | 95 | Command execution |
| SYSTEM + php:// | 90 | PHP wrapper |
| SYSTEM + gopher:// | 90 | Internal service access |
| Parameter entity (`<!ENTITY %`) | 80 | Advanced OOB XXE |
| ENTITY + SYSTEM combined | 85 | External entity |
| SSI (`<!--#include`) | 65 | Server-side include |
| XInclude (`<xi:include`) | 70 | Alternative inclusion |
| XSLT (`<xsl:`) | 60 | XSLT injection |
| CDATA with suspicious content | 40 | Obfuscation |

Scan strategy: check Content-Type, read body, scan raw patterns (never parse XML).

### 4.6 SSRF Detector (`internal/layers/detection/ssrf/`)

Scans URL-like values in query params, JSON bodies, XML content.

| Pattern | Score | Reason |
|---------|-------|--------|
| localhost/127.0.0.1/[::1] | 80-85 | Loopback |
| 169.254.169.254 | 95 | AWS/GCP metadata |
| metadata.google.internal | 95 | GCP metadata |
| Cloud metadata endpoints | 85-90 | Various providers |
| Private IP ranges (10/8, 172.16/12, 192.168/16) | 65 | Internal network |
| Decimal/Octal/Hex IP encoding | 80-85 | Obfuscated localhost |
| URL with `@` | 70 | Credential bypass |
| DNS rebinding candidates | 50 | Suspicious domain |
| Non-HTTP schemes (file, gopher, dict) | 65-85 | Protocol abuse |
| Short URLs / redirectors | 40 | SSRF hop |

**IP Range Detection:** Pure arithmetic, no DNS. Supports decimal, octal, hex, mixed notation, IPv6-mapped addresses.


---

## 5. Request Sanitizer (`internal/layers/sanitizer/`)

Layer 3 in the pipeline. Normalizes, validates, and cleans requests before detection.

### 5.1 Normalization Pipeline

Runs **before** detection. Original preserved in `RequestContext.Request`; normalized values stored separately.

| Step | Operation | Details |
|------|-----------|---------|
| 1 | **URL decode** | `%xx` -> char. Recursive max 3 iterations. Reject if still encoded. |
| 2 | **Null byte removal** | Strip `%00`, `\0`, `\x00`. Never legitimate in HTTP params. |
| 3 | **Path canonicalization** | Resolve `/../`, `/./`, `//`. Trailing dots/spaces (Windows). `\` -> `/`. |
| 4 | **Unicode normalization** | NFC form via Go's `unicode/norm` stdlib. |
| 5 | **HTML entity decode** | `&#x27;` -> `'`, `&lt;` -> `<`, etc. For detection only. |
| 6 | **Case normalization** | Lowercase copy for comparison. Original case preserved. |
| 7 | **Whitespace normalization** | Collapse multiple spaces/tabs. Decode %09, %0a, %0d. Trim. |
| 8 | **Backslash normalization** | `\` -> `/` in paths. Defeats Windows traversal on Unix. |

**Evasion detection bonus:** If normalized != original AND suspicious patterns present, +25 score bonus.

### 5.2 Validation Rules

| Check | Default | Config Key | Configurable |
|-------|---------|------------|--------------|
| Max URL length | 8192 bytes | `sanitizer.max_url_length` | Yes |
| Max header size | 8 KB/header | `sanitizer.max_header_size` | Yes |
| Max header count | 100 | `sanitizer.max_header_count` | Yes |
| Max body size | 10 MB | `sanitizer.max_body_size` | Yes, per-path |
| Max cookie size | 4 KB | `sanitizer.max_cookie_size` | Yes |
| Max cookie count | 50 | `sanitizer.max_cookie_count` | Yes |
| Max query length | 4096 bytes | `sanitizer.max_query_length` | Yes |
| Max query params | 100 | `sanitizer.max_query_params` | Yes |
| Allowed methods | GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS | `sanitizer.allowed_methods` | Yes |
| Allowed Content-Types | All | `sanitizer.allowed_content_types` | Yes |
| Hop-by-hop stripping | Enabled | `sanitizer.strip_hop_by_hop` | Yes |

Hop-by-hop headers stripped: Connection, Keep-Alive, Proxy-Authenticate, Proxy-Authorization, TE, Trailers, Transfer-Encoding, Upgrade.

Per-path body size override example:
```yaml
sanitizer:
  max_body_size: 10485760  # 10MB default
  path_overrides:
    - path: "/api/upload"
      max_body_size: 104857600  # 100MB
    - path: "/api/webhook"
      max_body_size: 1048576    # 1MB
```


---

## 6. Bot Detection (`internal/layers/botdetect/`)

Layer 5. Combines three signal sources: TLS fingerprinting, User-Agent analysis, behavioral analysis.

### 6.1 TLS Fingerprinting (JA3/JA4)

Captured via `tls.Config.GetConfigForClient` callback.

**JA3:** `MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)`

| Category | Examples | Score |
|----------|---------|-------|
| Known good browsers | Chrome 120+, Firefox 120+, Safari 17+, Edge 120+ | 0 |
| Known scanners | Python requests, Go net/http, curl, sqlmap, nikto, nmap, masscan, nuclei, httpx, gobuster, ffuf, wfuzz | 80 |
| Suspicious automation | Headless Chrome, Selenium, Puppeteer, PhantomJS, playwright | 50 |
| Unknown | JA3 not in database | 20 |

**Mismatch detection:** JA3 says Chrome but UA says otherwise -> Score 65.
**No TLS:** Score 10 (many setups terminate TLS at load balancer).

### 6.2 User-Agent Analysis

| Pattern | Score | Notes |
|---------|-------|-------|
| Empty UA | 40 | Common for bots |
| Missing UA entirely | 45 | More suspicious |
| Known scanner substring | 85 | Offensive tool |
| Outdated browser (Chrome < 100) | 25 | Possibly spoofed |
| UA length > 512 | 20 | Unusual |
| UA length > 1024 | 35 | Very suspicious |
| Contains "bot"/"crawler" | 0-70 | Check good bot list first |

Known good bots (score 0): Googlebot, Bingbot, Slurp, DuckDuckBot, Baiduspider, YandexBot, Applebot, Twitterbot, LinkedInBot, Slackbot, WhatsApp, TelegramBot, Discordbot, etc.

### 6.3 Behavioral Analysis (Sliding Window Per IP)

Default window: 60 seconds. Fixed-size ring buffer per IP.

| Metric | Threshold | Score |
|--------|-----------|-------|
| Requests/sec | > 10 sustained | 50 |
| Requests/sec | > 50 burst | 70 |
| Unique paths/min | > 50 | 60 |
| Unique paths/min | > 200 | 80 |
| 4xx error rate | > 30% (min 10 req) | 45 |
| 4xx error rate | > 60% (min 10 req) | 65 |
| Timing stddev | < 10ms (min 20 req) | 55 |
| Missing Accept-Encoding | every request | 15 |
| Missing Referer on internal | pattern detected | 15 |
| Sequential resource IDs | detected | 50 |
| Same endpoint, different params | > 20/min | 45 |
| HEAD requests only | > 5 in window | 30 |

**Memory:** ~512 bytes/IP, max 100K IPs (configurable), LRU eviction, 30s cleanup interval.


---

## 7. Response Protection (`internal/layers/response/`)

Layer 6 — post-proxy. Modifies upstream response before sending to client.

### 7.1 Security Headers

| Header | Default Value | Config Key |
|--------|--------------|------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | `response.headers.hsts` |
| `X-Content-Type-Options` | `nosniff` | `response.headers.content_type_options` |
| `X-Frame-Options` | `SAMEORIGIN` | `response.headers.frame_options` |
| `X-XSS-Protection` | `0` (disabled — modern browsers use CSP) | `response.headers.xss_protection` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | `response.headers.referrer_policy` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | `response.headers.permissions_policy` |
| `Content-Security-Policy` | Not set (application-specific) | `response.headers.csp` |
| `X-Request-ID` | request_id from context | `response.headers.request_id` |

- Upstream headers take precedence unless `response.headers.override: true`
- `Server` header optionally replaced or removed
- `X-Powered-By` stripped by default

### 7.2 Data Masking (in Response Bodies)

When `response.masking.enabled: true` (disabled by default — expensive):

| Pattern | Replacement | Notes |
|---------|-------------|-------|
| Visa (4xxx...) | `4***-****-****-last4` | Preserves last 4 |
| Mastercard (5[1-5]xx...) | `5***-****-****-last4` | Preserves last 4 |
| Amex (3[47]xx...) | `3***-******-*last4` | Preserves last 4 |
| Discover (6xxx...) | `6***-****-****-last4` | Preserves last 4 |
| SSN (XXX-XX-XXXX) | `***-**-last4` | Preserves last 4 |
| API key patterns | `first4****...` | Preserves first 4 |
| AWS Access Key (AKIA...) | `AKIA****...` | AWS format |
| Private Key blocks | `[PRIVATE KEY REDACTED]` | Full redaction |

Constraints: text/* and application/json only, per-path config, max 1MB body, recalculates Content-Length.

### 7.3 Error Pages

- **Production mode:** Generic page, no internals, X-Request-ID for correlation
- **Development mode:** Detailed findings (score, detector, evidence)
- **Custom templates:** Per status code (403, 429, 400)

Template variables: `RequestID`, `StatusCode`, `StatusText`, `Timestamp`, `Message`.
Default pages embedded via `embed.FS`.


---

## 8. IP Access Control (`internal/layers/ipacl/`)

Layer 1 — first check, fastest layer. Operates only on remote IP.

### 8.1 Radix Tree

Compressed Patricia trie for IPv4 (32-bit) and IPv6 (128-bit).

- O(k) lookup where k = prefix bits (max 32 IPv4, 128 IPv6)
- Typical: 5-10 node traversals with compression
- Thread-safe: `sync.RWMutex` (reads concurrent, writes exclusive)

```go
type radixNode struct {
    prefix    []byte         // compressed bit prefix
    prefixLen int            // number of bits in prefix
    children  [2]*radixNode  // left (0) and right (1)
    value     *aclEntry      // non-nil if terminal
}

type aclEntry struct {
    action  Action     // Allow or Block
    reason  string     // "whitelist", "blacklist", "auto-ban"
    expires time.Time  // zero = permanent
}
```

### 8.2 Whitelist

Checked **first**. Match -> bypass ALL remaining layers, forward to upstream.

- Individual IPs: `192.168.1.100`
- CIDR ranges: `10.0.0.0/8`
- IPv6: `::1`, `fd00::/8`
- Permanent (no TTL)
- Use cases: monitoring, health checks, trusted partners, CI/CD

```yaml
ipacl:
  whitelist:
    - "127.0.0.1"
    - "::1"
    - "10.0.0.0/8"
    - "192.168.1.50"
```

### 8.3 Blacklist

Checked after whitelist. Match (and not whitelisted) -> immediate 403.

- Individual IPs and CIDR ranges
- Permanent unless auto-ban
- Generic "Access Denied" response
- All remaining layers skipped

```yaml
ipacl:
  blacklist:
    - "198.51.100.0/24"
    - "203.0.113.42"
```

### 8.4 Auto-Ban

Dynamic temporary blacklist based on runtime behavior.

**Triggers:**
1. Rate limit violations > `auto_ban_after` within `auto_ban_window`
2. Repeated blocked requests (score >= threshold) > `auto_ban_after` within window

**Properties:**
- TTL: default 1h, min 1m, max 24h
- In-memory only (not persisted across restarts)
- Lazy expiry + periodic cleanup
- Same radix tree as blacklist (with TTL)
- Events logged for dashboard

```yaml
ipacl:
  auto_ban:
    enabled: true
    after: 5               # violations before ban
    window: "5m"           # counting window
    ttl: "1h"              # ban duration
    max_entries: 10000     # max concurrent bans
```

**Lifecycle:**
1. IP triggers block or rate limit
2. Violation counter incremented
3. Counter >= threshold -> auto-ban
4. Subsequent requests -> immediate 403 (Layer 1)
5. TTL expires -> removed, counter resets

**API:**
- `GET /api/v1/autoban` — list auto-banned IPs
- `DELETE /api/v1/autoban/{ip}` — remove entry
- `POST /api/v1/autoban` — manually add with custom TTL


---
## 9. Rate Limiter (`internal/layers/ratelimit/`)

### 9.1 Token Bucket Algorithm
- Lazy refill on access (no background goroutine per bucket)
- Per-bucket: last_refill_time, token_count
- Configurable: limit (tokens per window), window duration, burst size

### 9.2 Scope Resolution
- `"ip"` → key = RemoteIP
- `"ip+path"` → key = RemoteIP + matched path pattern

### 9.3 Rule Matching
- Rules matched by path pattern (glob)
- Most specific path match wins
- Multiple rules can apply (e.g., global + path-specific)

### 9.4 Actions on Limit Exceeded
- `"block"` → 429 Too Many Requests
- `"log"` → Allow but log
- auto_ban_after: N → after N rate limit blocks, add IP to auto-ban

### 9.5 Configuration
```yaml
rate_limit:
  enabled: true
  rules:
    - id: "global"
      scope: "ip"
      limit: 1000
      window: "1m"
      burst: 50
      action: "block"
    - id: "login"
      scope: "ip+path"
      paths: ["/login", "/auth/*"]
      limit: 10
      window: "1m"
      burst: 3
      action: "block"
      auto_ban_after: 5
```

## 10. Standalone Mode

### 10.1 Reverse Proxy
Full HTTP/1.1 and HTTP/2 reverse proxy with:
- Multiple upstream backends per route
- Load balancing: round-robin, weighted, least-connections, IP-hash
- Health checks: active (periodic HTTP GET) and passive (response code monitoring)
- Circuit breaker: configurable failure threshold, half-open retry
- Connection pooling: keep-alive to upstreams, configurable pool size
- Timeout configuration: connect, read, write, idle
- Request/response streaming (no full buffering)
- WebSocket proxying (Upgrade header handling)
- X-Forwarded-For / X-Real-IP header injection
- Request ID generation (UUID v4) and propagation

### 10.2 TLS Termination
- Automatic TLS via ACME (Let's Encrypt) — HTTP-01 challenge from scratch
- Manual certificate configuration (cert + key PEM files)
- SNI-based certificate selection (multiple domains)
- TLS 1.2 and 1.3 support
- Configurable cipher suites
- OCSP stapling (if feasible with stdlib)
- Certificate auto-renewal (background goroutine, check every 12h, renew 30 days before expiry)

### 10.3 Web Dashboard (embedded via go:embed)

#### Pages:
1. **Dashboard** — Real-time stats: requests/sec, blocks/sec, top attack types, top blocked IPs, response time percentiles
2. **Events** — Searchable, filterable WAF event log with evidence, pagination
3. **Rules** — Manage IP whitelist/blacklist, rate limit rules, detection exclusions (CRUD)
4. **Configuration** — Edit YAML config in browser, apply without restart
5. **Analytics** — Charts: attack trends (24h/7d/30d), detector breakdown, geographic distribution

#### Tech Stack:
- Pure HTML + CSS + vanilla JavaScript (no framework, embedded in binary)
- Server-Sent Events (SSE) for real-time updates
- Minimal, modern design (dark/light theme via CSS variables)
- Mobile-responsive

### 10.4 REST API

All endpoints require authentication via `X-GuardianWAF-Key` header or `?api_key=` query parameter.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/stats | Dashboard statistics |
| GET | /api/v1/events | Paginated WAF events |
| GET | /api/v1/events/:id | Single event detail |
| GET | /api/v1/rules/whitelist | List whitelist rules |
| POST | /api/v1/rules/whitelist | Add whitelist entry |
| DELETE | /api/v1/rules/whitelist/:id | Remove whitelist entry |
| GET | /api/v1/rules/blacklist | List blacklist rules |
| POST | /api/v1/rules/blacklist | Add blacklist entry |
| DELETE | /api/v1/rules/blacklist/:id | Remove blacklist entry |
| GET | /api/v1/rules/ratelimit | List rate limit rules |
| POST | /api/v1/rules/ratelimit | Add rate limit rule |
| DELETE | /api/v1/rules/ratelimit/:id | Remove rate limit rule |
| GET | /api/v1/rules/exclusions | List detection exclusions |
| POST | /api/v1/rules/exclusions | Add detection exclusion |
| DELETE | /api/v1/rules/exclusions/:id | Remove exclusion |
| GET | /api/v1/config | Current configuration |
| PUT | /api/v1/config | Update configuration (hot reload) |
| POST | /api/v1/config/reload | Force configuration reload |
| GET | /api/v1/health | Health check endpoint |
| GET | /api/v1/version | Version information |

#### Request/Response Formats:
- All responses: JSON with `Content-Type: application/json`
- Pagination: `?page=1&per_page=50`
- Filtering: `?action=blocked&since=2024-01-01T00:00:00Z&detector=sqli`
- Sorting: `?sort=timestamp&order=desc`
- Error format: `{"error": {"code": "not_found", "message": "Event not found"}}`

### 10.5 MCP Server

Built-in MCP (Model Context Protocol) server for AI agent integration.

Transport: stdio (for Claude Code integration)
Protocol: JSON-RPC 2.0 as per MCP specification

#### Tools:
| Tool | Description | Parameters |
|------|-------------|------------|
| guardianwaf_get_stats | WAF statistics | timeframe (optional) |
| guardianwaf_get_events | Search/filter WAF events | action, since, until, detector, ip, limit |
| guardianwaf_add_whitelist | Add IP to whitelist | ip, cidr, reason, ttl |
| guardianwaf_remove_whitelist | Remove IP from whitelist | id |
| guardianwaf_add_blacklist | Add IP to blacklist | ip, cidr, reason, ttl |
| guardianwaf_remove_blacklist | Remove IP from blacklist | id |
| guardianwaf_add_ratelimit | Create rate limit rule | scope, paths, limit, window, burst, action |
| guardianwaf_remove_ratelimit | Remove rate limit rule | id |
| guardianwaf_add_exclusion | Create detection exclusion | path, detectors, reason |
| guardianwaf_remove_exclusion | Remove detection exclusion | id |
| guardianwaf_set_mode | Change WAF mode | mode (monitor/enforce/disabled) |
| guardianwaf_get_config | Get current configuration | section (optional) |
| guardianwaf_test_request | Test request (dry-run) | url, method, headers, body |
| guardianwaf_get_top_ips | Top blocked/monitored IPs | timeframe, limit |
| guardianwaf_get_detectors | List detectors and status | (none) |

## 11. Embeddable Library Mode

### 11.1 Public API

```go
package guardianwaf

// Create engine with YAML config
engine, err := guardianwaf.NewFromFile("guardianwaf.yaml")

// Create engine with programmatic config
engine, err := guardianwaf.New(guardianwaf.Config{
    Mode: guardianwaf.ModeEnforce,
    Detection: guardianwaf.DetectionConfig{
        SQLi:          guardianwaf.DetectorConfig{Enabled: true, Multiplier: 1.0},
        XSS:           guardianwaf.DetectorConfig{Enabled: true, Multiplier: 1.0},
        PathTraversal: guardianwaf.DetectorConfig{Enabled: true, Multiplier: 1.0},
        CmdInjection:  guardianwaf.DetectorConfig{Enabled: true, Multiplier: 1.0},
        XXE:           guardianwaf.DetectorConfig{Enabled: true, Multiplier: 1.0},
        SSRF:          guardianwaf.DetectorConfig{Enabled: true, Multiplier: 1.0},
    },
    Threshold: guardianwaf.ThresholdConfig{
        Block: 50,
        Log:   25,
    },
})

// Use as HTTP middleware
mux := http.NewServeMux()
mux.HandleFunc("/api/", apiHandler)
http.ListenAndServe(":8080", engine.Middleware(mux))

// Manual request checking
result := engine.Check(guardianwaf.Request{
    Method:   "GET",
    Path:     "/search",
    Query:    "q=' OR 1=1 --",
    Headers:  map[string][]string{"User-Agent": {"Mozilla/5.0"}},
    RemoteIP: "1.2.3.4",
})

// Event subscription
engine.OnEvent(func(event guardianwaf.Event) {
    // Send to SIEM, log, etc.
})

// Functional options
engine, err := guardianwaf.New(config,
    guardianwaf.WithMode(guardianwaf.ModeMonitor),
    guardianwaf.WithThreshold(60, 30),
    guardianwaf.WithDetector("sqli", true, 1.5),
)
```

### 11.2 Performance Requirements
| Metric | Target |
|--------|--------|
| Middleware overhead (clean request) | < 200μs p99 |
| Middleware overhead (attack detected) | < 1ms p99 |
| Memory baseline | < 5MB |
| Memory per 10K tracked IPs | < 10MB |
| Goroutine count | 2 (cleanup + behavioral analysis) |
| Zero allocations on hot path | Target (sync.Pool) |

## 12. Sidecar Mode

### 12.1 CLI
```bash
guardianwaf sidecar --upstream localhost:8080 --listen :9090
guardianwaf sidecar --config guardianwaf.yaml
GWAF_UPSTREAM=localhost:8080 GWAF_LISTEN=:9090 guardianwaf sidecar
```

### 12.2 Constraints
- No dashboard, no MCP, no REST API
- Config via YAML file or environment variables
- Minimal memory footprint (< 20MB)
- Fast startup (< 100ms to ready)
- Docker healthcheck endpoint: `GET /healthz` → 200

## 13. Configuration Reference

Full YAML configuration with every field shown with defaults:

```yaml
# GuardianWAF Configuration — Complete Reference

# General
mode: "enforce"                      # "enforce", "monitor", "disabled"
listen: ":8080"

tls:
  enabled: false
  listen: ":8443"
  cert_file: ""
  key_file: ""
  acme:
    enabled: false
    email: ""
    domains: []
    cache_dir: "/var/lib/guardianwaf/acme"

# Upstream backends (standalone/sidecar mode)
upstreams:
  - name: "default"
    targets:
      - url: "http://localhost:3000"
        weight: 100
    health_check:
      enabled: true
      interval: "10s"
      timeout: "2s"
      path: "/health"
    load_balancer: "round_robin"     # "round_robin", "weighted", "least_conn", "ip_hash"

# Routing (standalone mode)
routes:
  - path: "/*"
    upstream: "default"
    strip_prefix: false
    methods: ["*"]

# WAF Layers
waf:
  ip_acl:
    enabled: true
    whitelist: []
    blacklist: []
    auto_ban:
      enabled: true
      default_ttl: "1h"
      max_ttl: "24h"

  rate_limit:
    enabled: true
    rules:
      - id: "global"
        scope: "ip"
        limit: 1000
        window: "1m"
        burst: 50
        action: "block"
      - id: "login"
        scope: "ip+path"
        paths: ["/login", "/auth/*"]
        limit: 10
        window: "1m"
        burst: 3
        action: "block"
        auto_ban_after: 5

  sanitizer:
    enabled: true
    max_url_length: 8192
    max_header_size: 8192
    max_header_count: 100
    max_body_size: 10485760          # 10MB
    max_cookie_size: 4096
    block_null_bytes: true
    normalize_encoding: true
    strip_hop_by_hop: true
    allowed_methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    path_overrides:
      - path: "/upload/*"
        max_body_size: 104857600     # 100MB

  detection:
    enabled: true
    threshold:
      block: 50
      log: 25
    detectors:
      sqli:  { enabled: true, multiplier: 1.0 }
      xss:   { enabled: true, multiplier: 1.0 }
      lfi:   { enabled: true, multiplier: 1.0 }
      cmdi:  { enabled: true, multiplier: 1.0 }
      xxe:   { enabled: true, multiplier: 1.0 }
      ssrf:  { enabled: true, multiplier: 1.0 }
    exclusions:
      - path: "/api/webhook/*"
        detectors: ["sqli"]
        reason: "Webhook payloads may contain SQL"

  bot_detection:
    enabled: true
    mode: "monitor"
    tls_fingerprint:
      enabled: true
      known_bots_action: "block"
      unknown_action: "log"
      mismatch_action: "log"
    user_agent:
      enabled: true
      block_empty: true
      block_known_scanners: true
    behavior:
      enabled: true
      window: "5m"
      rps_threshold: 10
      error_rate_threshold: 30

  response:
    security_headers:
      enabled: true
      hsts: { enabled: true, max_age: 31536000, include_subdomains: true }
      x_content_type_options: true
      x_frame_options: "SAMEORIGIN"
      referrer_policy: "strict-origin-when-cross-origin"
      permissions_policy: "camera=(), microphone=(), geolocation=()"
    data_masking:
      enabled: true
      mask_credit_cards: true
      mask_ssn: true
      mask_api_keys: true
      strip_stack_traces: true
    error_pages:
      enabled: true
      mode: "production"

# Dashboard (standalone mode only)
dashboard:
  enabled: true
  listen: ":9443"
  api_key: ""                        # Generated on first run if empty
  tls: true

# MCP Server (standalone mode only)
mcp:
  enabled: true
  transport: "stdio"

# Logging
logging:
  level: "info"
  format: "json"                     # "json" or "text"
  output: "stdout"                   # "stdout", "stderr", or file path
  log_allowed: false
  log_blocked: true
  log_body: false

# Events storage
events:
  storage: "memory"                  # "memory" or "file"
  max_events: 100000
  file_path: "/var/log/guardianwaf/events.jsonl"
```

## 14. CLI Interface

```
guardianwaf — Zero-dependency WAF. One binary. Total protection.

USAGE:
  guardianwaf <command> [options]

COMMANDS:
  serve       Start in standalone reverse proxy mode (full features)
  sidecar     Start in lightweight sidecar proxy mode
  check       Test a request against the WAF (dry-run)
  validate    Validate a configuration file
  version     Print version information
  help        Show help

SERVE OPTIONS:
  --config, -c     Path to config file (default: guardianwaf.yaml)
  --listen, -l     Override listen address
  --mode, -m       Override WAF mode (enforce/monitor/disabled)
  --dashboard      Override dashboard listen address
  --log-level      Override log level

SIDECAR OPTIONS:
  --config, -c     Path to config file
  --upstream, -u   Upstream address (required if no config)
  --listen, -l     Listen address (default: :9090)
  --mode, -m       WAF mode (default: enforce)

CHECK OPTIONS:
  --config, -c     Path to config file
  --url            URL to test
  --method         HTTP method (default: GET)
  --header         Headers (repeatable: --header "Key: Value")
  --body           Request body
  --body-file      Path to request body file
  --verbose, -v    Show detailed detection results

EXAMPLES:
  guardianwaf serve -c guardianwaf.yaml
  guardianwaf sidecar -u localhost:3000 -l :9090
  guardianwaf check --url "http://example.com/search?q=' OR 1=1 --"
  guardianwaf validate -c guardianwaf.yaml
```

## 15. Performance Requirements

| Metric | Target |
|--------|--------|
| IP ACL lookup | < 100ns |
| Rate limit check | < 500ns |
| Request sanitization | < 50μs |
| SQLi detection | < 200μs p95 |
| XSS detection | < 150μs p95 |
| All detectors combined | < 500μs p95 |
| Bot detection (no behavioral) | < 100μs |
| Response header injection | < 10μs |
| **Total WAF pipeline (clean request)** | **< 1ms p99** |
| **Total WAF pipeline (attack)** | **< 2ms p99** |
| Reverse proxy overhead | < 500μs p99 |
| Memory baseline (standalone) | < 30MB |
| Memory baseline (library) | < 5MB |
| Startup time (sidecar) | < 100ms |
| Max concurrent connections | 50,000+ |

## 16. Testing Strategy

### 16.1 Detection Accuracy Tests
For EACH detector, maintain three test fixture files:
- `testdata/attacks/<detector>.json` — Known attack payloads (MUST detect, score >= block_threshold)
- `testdata/benign/<detector>.json` — Legitimate inputs (MUST NOT block, score < log_threshold)
- `testdata/edge_cases/<detector>.json` — Tricky inputs (document expected scores)

### 16.2 Benchmark Tests
```go
func BenchmarkFullPipeline_CleanRequest(b *testing.B) {}
func BenchmarkFullPipeline_SQLiAttack(b *testing.B) {}
func BenchmarkSQLiTokenizer(b *testing.B) {}
func BenchmarkRadixTree_10K_Rules(b *testing.B) {}
func BenchmarkRateLimiter_100K_IPs(b *testing.B) {}
func BenchmarkJA3_Computation(b *testing.B) {}
```

### 16.3 Fuzz Tests
```go
func FuzzSQLiDetector(f *testing.F) {}
func FuzzXSSDetector(f *testing.F) {}
func FuzzURLNormalizer(f *testing.F) {}
func FuzzYAMLParser(f *testing.F) {}
```

### 16.4 Integration Tests
Full request lifecycle: HTTP client → GuardianWAF → mock backend → response.
Test all six layers in sequence. Test whitelist bypass. Test rate limiting across time windows. Test hot config reload.

## 17. Project Structure

Include the COMPLETE directory tree:
```
guardianwaf/
├── cmd/guardianwaf/main.go
├── internal/
│   ├── engine/ (engine.go, engine_test.go, config.go, context.go, event.go, finding.go, layer.go, pipeline.go)
│   ├── layers/
│   │   ├── ipacl/ (ipacl.go, radix.go, radix_test.go, ipacl_test.go)
│   │   ├── ratelimit/ (ratelimit.go, bucket.go, bucket_test.go, ratelimit_test.go)
│   │   ├── sanitizer/ (sanitizer.go, normalize.go, validate.go, normalize_test.go, sanitizer_test.go)
│   │   ├── detection/ (detection.go, detector.go)
│   │   │   ├── sqli/ (sqli.go, tokenizer.go, keywords.go, patterns.go, sqli_test.go, testdata/)
│   │   │   ├── xss/ (xss.go, parser.go, patterns.go, xss_test.go, testdata/)
│   │   │   ├── lfi/ (lfi.go, sensitive_paths.go, lfi_test.go, testdata/)
│   │   │   ├── cmdi/ (cmdi.go, commands.go, shell.go, cmdi_test.go, testdata/)
│   │   │   ├── xxe/ (xxe.go, xxe_test.go, testdata/)
│   │   │   └── ssrf/ (ssrf.go, ipcheck.go, ssrf_test.go, testdata/)
│   │   ├── botdetect/ (botdetect.go, ja3.go, fingerprints.go, useragent.go, behavior.go, ja3_test.go, botdetect_test.go)
│   │   └── response/ (response.go, headers.go, masking.go, errorpage.go, response_test.go)
│   ├── proxy/ (proxy.go, loadbalancer.go, healthcheck.go, circuitbreaker.go, websocket.go, proxy_test.go)
│   ├── tls/ (manager.go, acme.go, sni.go, tls_test.go)
│   ├── dashboard/ (dashboard.go, api.go, sse.go, auth.go, static/, dashboard_test.go)
│   ├── mcp/ (server.go, tools.go, handlers.go, mcp_test.go)
│   ├── config/ (config.go, yaml.go, yaml_test.go, validate.go, defaults.go)
│   ├── events/ (store.go, memory.go, file.go, store_test.go)
│   └── analytics/ (analytics.go, topk.go, ringbuffer.go, analytics_test.go)
├── guardianwaf.go
├── guardianwaf_test.go
├── options.go
├── testdata/ (attacks/, benign/, configs/)
├── examples/ (standalone/, library/, sidecar/, kubernetes/)
├── docs/
├── scripts/ (build.sh, benchmark.sh)
├── go.mod, Makefile, Dockerfile, docker-compose.yml
├── .github/workflows/ (ci.yml, release.yml)
├── .golangci.yml, .goreleaser.yml
└── llms.txt
```

## 18. Events & Logging

### 18.1 Event Storage
- **Memory mode:** Ring buffer, fixed size (default 100K events), O(1) insert, oldest events evicted
- **File mode:** JSONL (one JSON object per line), append-only, buffered channel writer

### 18.2 Logging
- Structured logging (JSON or text format)
- Levels: debug, info, warn, error
- Output: stdout, stderr, or file path
- Configurable: log_allowed (false), log_blocked (true), log_body (false — security risk)
