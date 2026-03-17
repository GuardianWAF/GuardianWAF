# GuardianWAF — Claude Code Prompt

> **A zero-dependency, modular Web Application Firewall written in Go.**
> Single binary. Three deployment modes. Tokenizer-based detection with scoring engine.
> The WAF that doesn't need a PhD to deploy.

**Author:** Ersin Koç / ECOSTACK TECHNOLOGY OÜ
**Repository:** `github.com/guardianwaf/guardianwaf`
**License:** MIT (core) + Commercial (enterprise features, future)
**Domain:** guardianwaf.com

---

## Instructions for Claude Code

You are building **GuardianWAF** from scratch — a production-grade Web Application Firewall in Go with zero external dependencies.

### Workflow (STRICT ORDER — do not skip)

1. **Read this entire prompt first.** Understand the full scope before writing anything.

2. **Create `SPECIFICATION.md`** — Complete technical specification covering every component, interface, configuration option, and behavior. This is the contract. Expand on everything in this prompt with your own technical depth. The spec should be comprehensive enough that another developer could implement GuardianWAF from it alone.

3. **Create `IMPLEMENTATION.md`** — Architecture decisions, algorithm choices, data structure selections, performance trade-offs, and rationale for every non-obvious decision. This bridges "what" (spec) to "how" (tasks).

4. **Create `TASKS.md`** — Ordered, numbered implementation tasks. Each task references specific files to create or modify. Tasks are granular enough to be completed in a single coding session. Include estimated complexity (S/M/L/XL) for each task.

5. **Create `BRANDING.md`** — Project identity: tagline, description variants (one-liner, paragraph, full), README structure, badge list, comparison table vs competitors, social media copy.

6. **Only after all documents are complete**, begin implementing code by following TASKS.md sequentially.

### Non-Negotiable Rules

- **Zero external dependencies.** Every algorithm, parser, data structure, HTTP server, TLS handler, YAML parser, JSON encoder — everything is implemented from scratch using only Go's standard library. The only imports allowed are `"net"`, `"net/http"`, `"crypto/tls"`, `"encoding/json"`, `"regexp"`, `"sync"`, `"context"`, `"os"`, `"fmt"`, `"log"`, `"strings"`, `"strconv"`, `"bytes"`, `"io"`, `"time"`, `"sort"`, `"math"`, `"hash"`, `"crypto/md5"`, `"crypto/sha256"`, `"encoding/hex"`, `"encoding/base64"`, `"net/url"`, `"path"`, `"errors"`, `"runtime"`, `"os/signal"`, `"syscall"`, `"flag"`, `"embed"`, `"text/template"`, `"compress/gzip"`, and sub-packages of these.
- **Single binary.** `go build` produces one executable. No sidecar processes, no Docker requirements (though Docker support is provided), no external databases.
- **Configuration via YAML.** Custom YAML parser (subset — no anchors/aliases needed, just maps, lists, scalars, comments).
- **100% test coverage target** for detection engine. Other packages target 80%+.
- **Go 1.22+ minimum.** Use modern Go features: range over int, enhanced routing patterns in net/http, etc.
- **No `any` or `interface{}` in public APIs.** Use generics or concrete types.
- **`golangci-lint` clean.** No linter warnings with default configuration.

---

## 1. Project Identity

### 1.1 Naming

| Field | Value |
|-------|-------|
| Project Name | GuardianWAF |
| Binary Name | `guardianwaf` |
| Go Module | `github.com/guardianwaf/guardianwaf` |
| Config File | `guardianwaf.yaml` or `guardianwaf.yml` |
| Short Name | `gwaf` (for CLI aliases) |
| Tagline | "Zero-dependency WAF. One binary. Total protection." |

### 1.2 Value Proposition

GuardianWAF occupies a unique position: it is the ONLY open-source WAF that is simultaneously:
1. **Zero-dependency** — single `go build`, no CGO, no external libraries
2. **Standalone** — runs as a reverse proxy with built-in management UI
3. **Embeddable** — import as a Go library into any `net/http` application
4. **Modular** — each protection layer is independently configurable
5. **Tokenizer-based** — predictable, testable, debuggable detection (no ML black box)

### 1.3 Competitive Positioning

| Feature | SafeLine | Coraza | ModSecurity | NAXSI | **GuardianWAF** |
|---------|----------|--------|-------------|-------|-----------------|
| Language | C++/Go mix | Go | C++ | C | **Go** |
| Dependencies | 7 Docker services | ModSec rules | Apache/Nginx | Nginx | **Zero** |
| Deployment | Docker only | Library only | Module only | Module only | **All three** |
| Detection | ML semantic | Rule engine | Rule engine | Whitelist | **Tokenizer+scoring** |
| UI Dashboard | Yes | No | No | No | **Yes (embedded)** |
| Single Binary | No | N/A | No | No | **Yes** |
| MCP Server | Yes (separate) | No | No | No | **Built-in** |
| Config | Postgres + UI | SecLang | SecLang | Nginx | **YAML** |
| False positive mgmt | Balance/Strict | Manual tuning | Manual tuning | Manual tuning | **Scoring threshold** |

---

## 2. Architecture Overview

### 2.1 Three Deployment Modes

GuardianWAF is built as a **layered architecture** where the core detection engine is a Go library, and deployment modes are thin wrappers around it:

```
┌─────────────────────────────────────────────────────────────┐
│                   Deployment Modes                          │
│                                                             │
│  ┌─────────────┐  ┌─────────────────┐  ┌────────────────┐  │
│  │  Standalone  │  │   Embeddable    │  │    Sidecar     │  │
│  │  Reverse     │  │   Go Library    │  │    HTTP        │  │
│  │  Proxy       │  │   (middleware)  │  │    Proxy       │  │
│  │  + Dashboard │  │                 │  │    (minimal)   │  │
│  │  + MCP       │  │                 │  │                │  │
│  │  + TLS       │  │                 │  │                │  │
│  └──────┬───────┘  └───────┬─────────┘  └───────┬────────┘  │
│         │                  │                    │            │
│         └──────────────────┼────────────────────┘            │
│                            │                                 │
│              ┌─────────────▼──────────────┐                  │
│              │    GuardianWAF Core Engine  │                  │
│              │                            │                  │
│              │  ┌────────────────────────┐│                  │
│              │  │   Detection Pipeline   ││                  │
│              │  │  IP ACL → Rate Limit   ││                  │
│              │  │  → Sanitizer → WAF     ││                  │
│              │  │  → Bot → Response      ││                  │
│              │  └────────────────────────┘│                  │
│              │                            │                  │
│              │  ┌────────┐ ┌───────────┐ │                  │
│              │  │ Config │ │  Events   │ │                  │
│              │  │ Engine │ │  & Logs   │ │                  │
│              │  └────────┘ └───────────┘ │                  │
│              └────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
```

**Mode 1: Standalone Reverse Proxy** (`guardianwaf serve`)
- Full reverse proxy with TLS termination
- Built-in web dashboard for monitoring and configuration
- Built-in MCP server for AI agent management
- REST API for programmatic control
- Auto-TLS via ACME (Let's Encrypt) — implemented from scratch
- This is the primary deployment mode, equivalent to SafeLine but as a single binary

**Mode 2: Embeddable Go Library** (`import "github.com/guardianwaf/guardianwaf/engine"`)
- Import the detection engine into any Go HTTP application
- Standard `http.Handler` middleware wrapper
- Zero overhead when disabled
- Configuration via Go API or YAML file
- This is the Coraza-equivalent mode

**Mode 3: Sidecar Proxy** (`guardianwaf sidecar --upstream localhost:8080`)
- Minimal reverse proxy without dashboard/MCP
- Designed for Docker/K8s sidecar deployment
- Tiny memory footprint (< 20MB)
- Configuration via YAML file or environment variables
- This is the lightweight deployment for containers

### 2.2 Core Engine Architecture

```
┌────────────────────────────────────────────────────┐
│                  Request Lifecycle                  │
│                                                    │
│  Incoming HTTP Request                             │
│       │                                            │
│       ▼                                            │
│  ┌──────────────────────────────┐                  │
│  │ Layer 1: IP Access Control   │ → 403 Forbidden  │
│  │ Radix tree, O(k) lookup     │                   │
│  └──────────────┬───────────────┘                  │
│                 ▼                                   │
│  ┌──────────────────────────────┐                  │
│  │ Layer 2: Rate Limiter        │ → 429 Too Many   │
│  │ Token bucket per scope       │                   │
│  └──────────────┬───────────────┘                  │
│                 ▼                                   │
│  ┌──────────────────────────────┐                  │
│  │ Layer 3: Request Sanitizer   │ → 400 Bad Req    │
│  │ Normalize, validate, clean   │                   │
│  └──────────────┬───────────────┘                  │
│                 ▼                                   │
│  ┌──────────────────────────────┐                  │
│  │ Layer 4: Detection Engine    │ → 403 Forbidden  │
│  │ SQLi, XSS, LFI, RCE, SSRF  │                   │
│  │ Tokenizer + scoring engine   │                   │
│  └──────────────┬───────────────┘                  │
│                 ▼                                   │
│  ┌──────────────────────────────┐                  │
│  │ Layer 5: Bot Detection       │ → 403/Challenge  │
│  │ JA3, UA, behavior analysis   │                   │
│  └──────────────┬───────────────┘                  │
│                 ▼                                   │
│  ┌──────────────────────────────┐                  │
│  │ Layer 6: Response Protection │ ← post-proxy     │
│  │ Headers, masking, errors     │                   │
│  └──────────────┬───────────────┘                  │
│                 ▼                                   │
│  Upstream / Application                            │
└────────────────────────────────────────────────────┘
```

Each layer is:
- An independent Go package under `internal/engine/`
- Implements the `Layer` interface
- Has its own configuration section in YAML
- Can be independently enabled/disabled/set to monitor mode
- Produces `Finding` structs that feed into the scoring engine
- Has its own comprehensive test suite

---

## 3. Detection Engine — Deep Specification

### 3.1 Scoring System

Every detection rule produces a **threat score** from 0 to 100. Scores from all detectors accumulate per-request. The total score is compared against configurable thresholds:

```
Total Score >= block_threshold (default: 50) → Block request (403)
Total Score >= log_threshold (default: 25)   → Log as suspicious, allow
Total Score < log_threshold                  → Allow silently
```

**Why scoring beats binary rules:**
- A single apostrophe in input scores 10 (could be "O'Brien")
- An apostrophe + OR keyword scores 35 (suspicious but could be legit)
- An apostrophe + OR + 1=1 scores 85 (definitely SQLi)
- This graduated response eliminates most false positives

**Score multipliers:** Each detector has a configurable multiplier (default 1.0). Setting SQLi multiplier to 1.5 makes it more sensitive. Setting it to 0.5 makes it more lenient. Setting to 0 effectively disables it.

### 3.2 Detector Implementations

#### 3.2.1 SQL Injection Detector (`detection/sqli`)

**Tokenizer approach:** Parse input into SQL token stream, then match dangerous sequences.

Token types:
```
STRING_LITERAL   → 'value', "value"
NUMERIC_LITERAL  → 123, 0x1A, 0b1010
KEYWORD          → SELECT, UNION, OR, AND, DROP, INSERT, UPDATE, DELETE,
                   FROM, WHERE, HAVING, GROUP BY, ORDER BY, LIMIT, INTO,
                   EXEC, EXECUTE, DECLARE, SET, TRUNCATE, ALTER, CREATE
OPERATOR         → =, <>, !=, >=, <=, >, <, LIKE, IN, BETWEEN, IS
FUNCTION         → COUNT, SUM, AVG, SLEEP, BENCHMARK, WAITFOR, DELAY,
                   LOAD_FILE, OUTFILE, DUMPFILE, CHAR, CONCAT, SUBSTRING,
                   ASCII, ORD, HEX, UNHEX, MD5, SHA1, CONVERT, CAST
COMMENT          → --, #, /* ... */
PAREN_OPEN       → (
PAREN_CLOSE      → )
SEMICOLON        → ;
COMMA            → ,
WILDCARD         → *
WHITESPACE       → space, tab, newline, %09, %0a, %0d
OTHER            → anything else
```

Pattern scoring rules (non-exhaustive — expand in spec):

```
┌──────────────────────────────────────────────────────────────┐
│ Pattern                                    │ Score │ Reason  │
├──────────────────────────────────────────────────────────────┤
│ STRING_LITERAL + KEYWORD(OR/AND)           │  30   │ Partial │
│ + NUMERIC = NUMERIC (tautology)            │ +55   │ SQLi    │
│ KEYWORD(UNION) + KEYWORD(SELECT)           │  90   │ Union   │
│ SEMICOLON + KEYWORD(DROP/DELETE/TRUNCATE)  │  95   │ Stacked │
│ FUNCTION(SLEEP/BENCHMARK/WAITFOR)          │  90   │ Blind   │
│ FUNCTION(LOAD_FILE/OUTFILE/DUMPFILE)       │ 100   │ File    │
│ KEYWORD(INTO) + KEYWORD(OUTFILE/DUMPFILE)  │ 100   │ Exfil   │
│ COMMENT after STRING_LITERAL               │  35   │ Evasion │
│ KEYWORD(EXEC/EXECUTE) + STRING_LITERAL     │  80   │ Proc    │
│ FUNCTION(CHAR/CONCAT) + nested             │  50   │ Obfusc  │
│ Hex literal (0x...) in comparison          │  40   │ Obfusc  │
│ Isolated SQL keyword                       │  10   │ Benign  │
│ Double-encoded SQL characters              │  75   │ Evasion │
└──────────────────────────────────────────────────────────────┘
```

The tokenizer must handle:
- Standard SQL string delimiters: `'`, `"`, backtick
- Multi-database keyword sets (MySQL, PostgreSQL, MSSQL, SQLite, Oracle — union of all)
- Whitespace variations: `UNION/**/SELECT`, tabs, newlines as separators
- Case insensitivity for keywords
- Encoded variants: `%27` for `'`, `%2527` for double-encoded `'`
- Comment injection: `UN/**/ION`, `SE/**/LECT`
- Null byte injection (post-sanitizer, for defense-in-depth)

Scan locations: URL path, query parameters (each value separately), request body (form data values, JSON string values), Cookie values, Referer header, User-Agent header (lower priority — multiplier 0.5).

#### 3.2.2 XSS Detector (`detection/xss`)

**Approach:** Detect HTML tag injection, event handlers, and JavaScript protocol handlers.

Patterns and scores:
```
<script                        → 90  (script tag opening)
<script>...</script>           → 95  (complete script tag)
<img/svg/body/div + on[event]= → 85  (event handler injection)
javascript:                    → 80  (JS protocol in href/src)
data:text/html                 → 75  (data URI HTML)
expression(                    → 70  (IE CSS expression)
document.cookie                → 60  (cookie theft attempt)
document.write                 → 55  (DOM injection)
innerHTML                      → 50  (DOM injection)
eval(                          → 65  (code execution)
<iframe                        → 50  (frame injection)
<object                        → 45  (object injection)
<embed                         → 45  (embed injection)
<form + action=                → 40  (form hijack)
<meta http-equiv=refresh       → 50  (redirect injection)
on[a-z]+=                      → 70  (any event handler pattern)
\x3c, \u003c, &#x3C;, &#60;  → +20  (encoded < — evasion bonus)
```

The detector must handle:
- Case variations: `<ScRiPt>`, `<SCRIPT>`, `<script>`
- Attribute encoding: `onerror=&#97;lert(1)`
- Null bytes between tag characters (defense-in-depth)
- Template injection: `{{`, `${`, `#{`
- SVG-specific vectors: `<svg/onload=`, `<svg><animate onbegin=`

#### 3.2.3 Path Traversal Detector (`detection/lfi`)

Patterns and scores:
```
../                                → 30  (single level — could be legit)
../../..                           → 65  (3+ levels)
/etc/passwd                        → 90  (Linux password file)
/etc/shadow                        → 95  (shadow password)
/proc/self/                        → 85  (proc filesystem)
/var/log/                          → 60  (log access)
C:\ or C:/                         → 55  (Windows path)
\windows\system32                  → 80  (Windows system)
..%2f, ..%252f                     → 75  (encoded traversal)
..%c0%af                           → 95  (overlong UTF-8 bypass)
....// or ....\\                   → 70  (double-dot bypass)
file://                            → 65  (file protocol)
php://filter, php://input          → 85  (PHP wrapper)
expect://                          → 90  (expect wrapper)
Normalized ≠ raw AND contains ..   → +25 (normalization detected evasion)
```

Maintain embedded lists of sensitive file paths for Linux, Windows, and macOS.

#### 3.2.4 Command Injection Detector (`detection/cmdi`)

Patterns and scores:
```
; + command_keyword                → 75  (command chaining)
| + command_keyword                → 65  (pipe to command)
` (backtick) content `             → 80  (subshell execution)
$( command )                       → 80  (subshell)
&& or || + command_keyword         → 65  (logical chaining)
> or >> (redirect)                 → 45  (output redirect)
Known recon commands (id, whoami)  → 65  (info gathering)
Known network cmds (nc, curl, wget)→ 75  (data exfil)
Shell paths (/bin/sh, /bin/bash)   → 90  (explicit shell)
Interpreter -c/-e (python, perl)   → 80  (code execution)
base64 + pipe (decode chains)      → 85  (obfuscated payload)
Newline injection (%0a, %0d)       → 60  (HTTP header splitting)
```

Command keyword database (embedded):
```
cat, ls, dir, whoami, id, uname, hostname, ifconfig, ip, 
netstat, ss, ps, env, set, echo, printf, 
wget, curl, nc, ncat, netcat, socat,
python, python3, perl, ruby, php, node, 
bash, sh, zsh, dash, csh, ksh, cmd, powershell,
chmod, chown, chgrp, kill, pkill, nohup,
tar, zip, unzip, gzip, gunzip, base64,
find, grep, awk, sed, xargs, tee,
mysql, psql, sqlite3, mongo, redis-cli
```

#### 3.2.5 XXE Detector (`detection/xxe`)

Only triggered when Content-Type contains "xml", "soap", or "rss":

```
<!DOCTYPE                          → 25  (could be legit)
<!ENTITY                           → 65  (entity definition)
SYSTEM "file://                    → 95  (local file inclusion)
SYSTEM "http://                    → 75  (SSRF via XXE)
SYSTEM "expect://                  → 95  (command execution)
SYSTEM "php://                     → 90  (PHP wrapper)
<!ENTITY % (parameter entity)      → 80  (advanced XXE)
<!ENTITY + SYSTEM combined         → 85  (external entity)
<!--#include                       → 65  (SSI injection)
<xi:include                        → 70  (XInclude)
CDATA with suspicious content      → 40  (obfuscation)
```

#### 3.2.6 SSRF Detector (`detection/ssrf`)

Scan URL-like values in query params, JSON bodies, and XML content:

```
http://127.0.0.1                   → 80  (localhost)
http://localhost                    → 80  (localhost)
http://0.0.0.0                     → 85  (all interfaces)
http://[::1]                       → 85  (IPv6 localhost)
http://169.254.169.254             → 95  (AWS/GCP metadata)
http://metadata.google.internal    → 95  (GCP metadata)
http://100.100.100.200             → 90  (Alibaba metadata)
http://10.0.0.0/8                  → 65  (private class A)
http://172.16.0.0/12               → 65  (private class B)
http://192.168.0.0/16              → 65  (private class C)
Decimal IP (http://2130706433)     → 85  (obfuscated 127.0.0.1)
Octal IP (http://0177.0.0.1)      → 85  (obfuscated)
URL with @ (http://a@127.0.0.1)   → 70  (credential bypass)
DNS rebinding candidates           → 50  (suspicious domain patterns)
Short URLs / redirectors            → 40  (potential SSRF hop)
```

The SSRF detector must resolve private IP ranges without actually making DNS lookups. Check for IP-in-various-encodings (decimal, octal, hex, mixed notation) using pure arithmetic.

### 3.3 Request Sanitizer

Runs BEFORE the detection engine. Normalizes input to prevent encoding-based bypasses:

```
1. URL decode (%xx → char) — handle recursive: %2527 → %27 → '
   Max 3 decode iterations, then reject if still encoded
2. Null byte removal (%00, \0, \x00)
3. Path canonicalization: remove /../, /./,  //, trailing dots on Windows
4. Unicode normalization (NFC form via Go's unicode/norm — stdlib!)
5. HTML entity decode (&#x27; → ', &#39; → ', &lt; → <) for detection
6. Case normalization (for detection comparison only, preserve original)
7. Whitespace normalization (collapse multiple spaces, decode %09 %0a %0d)
8. Backslash normalization (\ → /)
```

Plus validation:
```
- Max URL length (default: 8192)
- Max header size (default: 8KB per header)
- Max header count (default: 100)
- Max body size (default: 10MB, configurable per-path)
- Max cookie size (default: 4KB)
- Allowed HTTP methods
- Allowed Content-Types
- Hop-by-hop header stripping
```

### 3.4 Bot Detection

#### TLS Fingerprinting (JA3/JA4)

Extract from `tls.ClientHelloInfo` in `tls.Config.GetConfigForClient`:
- TLS version
- Cipher suites (ordered list)
- Extensions (ordered list)
- Elliptic curves
- EC point formats

Compute JA3 hash: `MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)`

Maintain embedded fingerprint database:
```
Known good:  Chrome 120+, Firefox 120+, Safari 17+, Edge 120+
Known bad:   Python requests, Go default client, curl (default),
             sqlmap, nikto, nmap, masscan, nuclei, httpx
Suspicious:  Headless Chrome, Selenium, Puppeteer, PhantomJS
```

Scoring:
```
JA3 matches known scanner       → 80
JA3 unknown                     → 20
JA3 says Chrome but UA ≠ Chrome → 65 (fingerprint mismatch)
No TLS (plain HTTP)             → 10
```

#### User-Agent Analysis

```
Empty UA                         → 40
Known scanner UA (sqlmap, nikto) → 85
Outdated browser (Chrome < 100)  → 25
UA length > 512                  → 20 (unusual)
UA contains "bot" or "crawler"   → 0-70 (check against known good bots)
```

#### Behavioral Analysis (sliding window per IP)

```
Requests/second > 10             → 50 (sustained)
Unique paths/minute > 50         → 60 (scanning)
4xx error rate > 30%             → 45 (blind probing)
Timing stddev < 10ms             → 55 (machine-like precision)
No Accept-Encoding header        → 15 (minor indicator)
No Referer on internal links     → 15 (minor indicator)
Sequential resource IDs          → 50 (/user/1, /user/2, /user/3...)
```

---

## 4. Standalone Mode — Reverse Proxy

### 4.1 Reverse Proxy

Full HTTP/1.1 and HTTP/2 reverse proxy with:
- Multiple upstream backends per route
- Load balancing: round-robin, weighted, least-connections, IP-hash
- Health checks: active (periodic HTTP GET) and passive (response code monitoring)
- Circuit breaker: configurable failure threshold, half-open retry
- Connection pooling: keep-alive to upstreams, configurable pool size
- Timeout configuration: connect, read, write, idle
- Request/response streaming (no full buffering for large bodies)
- WebSocket proxying (Upgrade header handling)
- X-Forwarded-For / X-Real-IP header injection
- Request ID generation and propagation

### 4.2 TLS Termination

- Automatic TLS via ACME (Let's Encrypt) — implement ACME HTTP-01 challenge from scratch
- Manual certificate configuration (cert + key files)
- SNI-based certificate selection (multiple domains)
- TLS 1.2 and 1.3 support
- Configurable cipher suites
- OCSP stapling (if feasible with stdlib)
- Certificate auto-renewal (background goroutine)

### 4.3 Web Dashboard

Embedded web UI (compiled into binary via `embed`):
- **Dashboard page:** Real-time stats — requests/sec, blocks/sec, top attack types, top blocked IPs, response time percentiles
- **Events page:** Searchable, filterable WAF event log with evidence
- **Rules page:** Manage IP whitelist/blacklist, rate limit rules, detection exclusions
- **Configuration page:** Edit YAML config, apply without restart
- **Analytics page:** Charts — attack trends (24h/7d/30d), detector breakdown, geographic distribution

Tech stack for dashboard:
- Pure HTML + CSS + vanilla JavaScript (no framework — embedded in binary)
- Server-Sent Events (SSE) for real-time updates
- Minimal, modern design (dark/light theme)
- Mobile-responsive

### 4.4 REST API

```
GET    /api/v1/stats              → Dashboard statistics
GET    /api/v1/events             → Paginated WAF events
GET    /api/v1/events/:id         → Single event detail
GET    /api/v1/rules/whitelist    → List whitelist rules
POST   /api/v1/rules/whitelist    → Add whitelist entry
DELETE /api/v1/rules/whitelist/:id→ Remove whitelist entry
GET    /api/v1/rules/blacklist    → List blacklist rules
POST   /api/v1/rules/blacklist    → Add blacklist entry
DELETE /api/v1/rules/blacklist/:id→ Remove blacklist entry
GET    /api/v1/rules/ratelimit    → List rate limit rules
POST   /api/v1/rules/ratelimit    → Add rate limit rule
DELETE /api/v1/rules/ratelimit/:id→ Remove rate limit rule
GET    /api/v1/rules/exclusions   → List detection exclusions
POST   /api/v1/rules/exclusions   → Add detection exclusion
DELETE /api/v1/rules/exclusions/:id→ Remove exclusion
GET    /api/v1/config             → Current configuration
PUT    /api/v1/config             → Update configuration (hot reload)
POST   /api/v1/config/reload      → Force configuration reload
GET    /api/v1/health             → Health check endpoint
GET    /api/v1/version            → Version information
```

API authentication: API key in `X-GuardianWAF-Key` header or `?api_key=` query parameter.

### 4.5 MCP Server

Built-in MCP (Model Context Protocol) server for AI agent integration:

```
Tools:
  guardianwaf_get_stats         → WAF statistics
  guardianwaf_get_events        → Search/filter WAF events
  guardianwaf_add_whitelist     → Add IP to whitelist
  guardianwaf_remove_whitelist  → Remove IP from whitelist
  guardianwaf_add_blacklist     → Add IP to blacklist
  guardianwaf_remove_blacklist  → Remove IP from blacklist
  guardianwaf_add_ratelimit     → Create rate limit rule
  guardianwaf_remove_ratelimit  → Remove rate limit rule
  guardianwaf_add_exclusion     → Create detection exclusion
  guardianwaf_remove_exclusion  → Remove detection exclusion
  guardianwaf_set_mode          → Change WAF mode (monitor/enforce/disabled)
  guardianwaf_get_config        → Get current configuration
  guardianwaf_test_request      → Test a request against the WAF (dry-run)
  guardianwaf_get_top_ips       → Top blocked/monitored IPs
  guardianwaf_get_detectors     → List detectors and their status

Transport: stdio (for Claude Code integration)
Protocol: JSON-RPC 2.0 as per MCP specification
```

---

## 5. Embeddable Library Mode

### 5.1 API Design

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
    Method:  "GET",
    Path:    "/search",
    Query:   "q=' OR 1=1 --",
    Headers: map[string][]string{"User-Agent": {"Mozilla/5.0"}},
    RemoteIP: "1.2.3.4",
})
if result.Blocked {
    log.Printf("Blocked: score=%d findings=%v", result.TotalScore, result.Findings)
}

// Event subscription
engine.OnEvent(func(event guardianwaf.Event) {
    // Handle WAF events (send to SIEM, log, etc.)
})
```

### 5.2 Performance Requirements for Library Mode

```
Middleware overhead (clean request):     < 200μs p99
Middleware overhead (attack detected):   < 1ms p99
Memory baseline:                         < 5MB
Memory per 10K tracked IPs:              < 10MB
Goroutine count:                         2 (cleanup + behavioral analysis)
Zero allocations on hot path:            Target (use sync.Pool for request context)
```

---

## 6. Sidecar Mode

### 6.1 CLI

```bash
# Minimal sidecar proxy
guardianwaf sidecar --upstream localhost:8080 --listen :9090

# With config file
guardianwaf sidecar --config guardianwaf.yaml

# With environment variables
GWAF_UPSTREAM=localhost:8080 GWAF_LISTEN=:9090 guardianwaf sidecar
```

### 6.2 Constraints

- No dashboard, no MCP, no API (these are standalone-only)
- Config via YAML file or environment variables
- Minimal memory footprint (< 20MB)
- Fast startup (< 100ms to ready)
- Docker healthcheck endpoint: `GET /healthz` → 200

---

## 7. Configuration

### 7.1 Full Configuration Reference

```yaml
# GuardianWAF Configuration
# All fields shown with defaults

# General
mode: "enforce"                      # "enforce", "monitor", "disabled"
listen: ":8080"                      # Listen address
tls:
  enabled: false
  listen: ":8443"
  cert_file: ""                      # Path to cert PEM
  key_file: ""                       # Path to key PEM
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
  - path: "/*"                       # Glob pattern
    upstream: "default"
    strip_prefix: false
    methods: ["*"]                   # or specific: ["GET", "POST"]

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
      sqli:      { enabled: true, multiplier: 1.0 }
      xss:       { enabled: true, multiplier: 1.0 }
      lfi:       { enabled: true, multiplier: 1.0 }
      cmdi:      { enabled: true, multiplier: 1.0 }
      xxe:       { enabled: true, multiplier: 1.0 }
      ssrf:      { enabled: true, multiplier: 1.0 }
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
      mode: "production"             # "production" = generic, "development" = passthrough

# Dashboard (standalone mode only)
dashboard:
  enabled: true
  listen: ":9443"
  api_key: ""                        # Generated on first run if empty
  tls: true                         # Dashboard always served over HTTPS

# MCP Server (standalone mode only)
mcp:
  enabled: true
  transport: "stdio"                 # "stdio" for Claude Code

# Logging
logging:
  level: "info"
  format: "json"                     # "json" or "text"
  output: "stdout"                   # "stdout", "stderr", or file path
  log_allowed: false
  log_blocked: true
  log_body: false                    # Security risk — disabled by default

# Events storage
events:
  storage: "memory"                  # "memory" (ring buffer) or "file"
  max_events: 100000                 # Ring buffer size
  file_path: "/var/log/guardianwaf/events.jsonl"
```

---

## 8. CLI Interface

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
  # Start standalone mode
  guardianwaf serve -c guardianwaf.yaml

  # Start sidecar protecting localhost:3000
  guardianwaf sidecar -u localhost:3000 -l :9090

  # Test SQL injection detection
  guardianwaf check --url "http://example.com/search?q=' OR 1=1 --"

  # Validate config
  guardianwaf validate -c guardianwaf.yaml
```

---

## 9. Project Structure

```
guardianwaf/
├── cmd/
│   └── guardianwaf/
│       └── main.go                  # CLI entry point, flag parsing, mode routing
│
├── internal/
│   ├── engine/                      # Core WAF engine (shared by all modes)
│   │   ├── engine.go                # Engine struct, middleware wrapper, Check()
│   │   ├── engine_test.go
│   │   ├── config.go                # Config struct, defaults, validation
│   │   ├── context.go               # RequestContext builder
│   │   ├── event.go                 # Event struct, event bus
│   │   ├── finding.go               # Finding struct, scoring logic
│   │   ├── layer.go                 # Layer interface definition
│   │   └── pipeline.go              # Pipeline composition of layers
│   │
│   ├── layers/
│   │   ├── ipacl/                   # Layer 1: IP Access Control
│   │   │   ├── ipacl.go
│   │   │   ├── radix.go             # Radix tree for CIDR matching
│   │   │   ├── radix_test.go
│   │   │   └── ipacl_test.go
│   │   │
│   │   ├── ratelimit/               # Layer 2: Rate Limiter
│   │   │   ├── ratelimit.go
│   │   │   ├── bucket.go            # Token bucket implementation
│   │   │   ├── bucket_test.go
│   │   │   └── ratelimit_test.go
│   │   │
│   │   ├── sanitizer/               # Layer 3: Request Sanitizer
│   │   │   ├── sanitizer.go
│   │   │   ├── normalize.go         # URL/encoding normalization
│   │   │   ├── validate.go          # Header/body validation
│   │   │   ├── normalize_test.go
│   │   │   └── sanitizer_test.go
│   │   │
│   │   ├── detection/               # Layer 4: Detection Engine
│   │   │   ├── detection.go         # Runs all detectors, accumulates scores
│   │   │   ├── detector.go          # Detector interface
│   │   │   ├── sqli/
│   │   │   │   ├── sqli.go
│   │   │   │   ├── tokenizer.go
│   │   │   │   ├── keywords.go      # SQL keyword database
│   │   │   │   ├── patterns.go      # Pattern matching rules
│   │   │   │   ├── sqli_test.go
│   │   │   │   └── testdata/        # attacks.json, benign.json, edge_cases.json
│   │   │   ├── xss/
│   │   │   │   ├── xss.go
│   │   │   │   ├── parser.go        # HTML-like tag parser
│   │   │   │   ├── patterns.go
│   │   │   │   ├── xss_test.go
│   │   │   │   └── testdata/
│   │   │   ├── lfi/
│   │   │   │   ├── lfi.go
│   │   │   │   ├── sensitive_paths.go
│   │   │   │   ├── lfi_test.go
│   │   │   │   └── testdata/
│   │   │   ├── cmdi/
│   │   │   │   ├── cmdi.go
│   │   │   │   ├── commands.go      # Known command database
│   │   │   │   ├── shell.go         # Shell metacharacter analysis
│   │   │   │   ├── cmdi_test.go
│   │   │   │   └── testdata/
│   │   │   ├── xxe/
│   │   │   │   ├── xxe.go
│   │   │   │   ├── xxe_test.go
│   │   │   │   └── testdata/
│   │   │   └── ssrf/
│   │   │       ├── ssrf.go
│   │   │       ├── ipcheck.go       # Private IP range detection
│   │   │       ├── ssrf_test.go
│   │   │       └── testdata/
│   │   │
│   │   ├── botdetect/               # Layer 5: Bot Detection
│   │   │   ├── botdetect.go
│   │   │   ├── ja3.go               # JA3/JA4 fingerprinting
│   │   │   ├── fingerprints.go      # Embedded fingerprint database
│   │   │   ├── useragent.go
│   │   │   ├── behavior.go
│   │   │   ├── ja3_test.go
│   │   │   └── botdetect_test.go
│   │   │
│   │   └── response/                # Layer 6: Response Protection
│   │       ├── response.go
│   │       ├── headers.go
│   │       ├── masking.go
│   │       ├── errorpage.go
│   │       └── response_test.go
│   │
│   ├── proxy/                       # Reverse proxy (standalone/sidecar)
│   │   ├── proxy.go                 # HTTP reverse proxy
│   │   ├── loadbalancer.go          # LB algorithms
│   │   ├── healthcheck.go           # Active/passive health checks
│   │   ├── circuitbreaker.go        # Circuit breaker
│   │   ├── websocket.go             # WebSocket upgrade handling
│   │   └── proxy_test.go
│   │
│   ├── tls/                         # TLS management
│   │   ├── manager.go               # Certificate manager
│   │   ├── acme.go                  # ACME client (Let's Encrypt)
│   │   ├── sni.go                   # SNI routing
│   │   └── tls_test.go
│   │
│   ├── dashboard/                   # Web UI (standalone only)
│   │   ├── dashboard.go             # HTTP handlers
│   │   ├── api.go                   # REST API handlers
│   │   ├── sse.go                   # Server-Sent Events
│   │   ├── auth.go                  # API key authentication
│   │   ├── static/                  # Embedded static files
│   │   │   ├── index.html
│   │   │   ├── app.js
│   │   │   └── style.css
│   │   └── dashboard_test.go
│   │
│   ├── mcp/                         # MCP server (standalone only)
│   │   ├── server.go                # MCP JSON-RPC server
│   │   ├── tools.go                 # Tool definitions
│   │   ├── handlers.go              # Tool handlers
│   │   └── mcp_test.go
│   │
│   ├── config/                      # Configuration
│   │   ├── config.go                # Config struct and loading
│   │   ├── yaml.go                  # Custom YAML parser (subset)
│   │   ├── yaml_test.go
│   │   ├── validate.go              # Config validation
│   │   └── defaults.go              # Default values
│   │
│   ├── events/                      # Event storage
│   │   ├── store.go                 # Event store interface
│   │   ├── memory.go                # Ring buffer in-memory store
│   │   ├── file.go                  # JSONL file store
│   │   └── store_test.go
│   │
│   └── analytics/                   # Analytics engine
│       ├── analytics.go             # Rolling counters, TopK tracker
│       ├── topk.go                  # Top-K with min-heap
│       ├── ringbuffer.go            # Time-bucketed ring buffer
│       └── analytics_test.go
│
├── guardianwaf.go                   # Public API for library mode
├── guardianwaf_test.go
├── options.go                       # Functional options for New()
│
├── testdata/                        # Integration test fixtures
│   ├── attacks/                     # Attack payload collections per detector
│   ├── benign/                      # Legitimate traffic samples
│   └── configs/                     # Test configuration files
│
├── examples/
│   ├── standalone/                  # Example standalone deployment
│   │   └── guardianwaf.yaml
│   ├── library/                     # Example Go library usage
│   │   └── main.go
│   ├── sidecar/                     # Example Docker sidecar
│   │   ├── Dockerfile
│   │   └── docker-compose.yml
│   └── kubernetes/                  # Example K8s sidecar injection
│       └── deployment.yaml
│
├── docs/
│   ├── getting-started.md
│   ├── configuration.md
│   ├── detection-engine.md
│   ├── deployment-modes.md
│   ├── api-reference.md
│   ├── mcp-integration.md
│   └── tuning-guide.md             # How to reduce false positives
│
├── scripts/
│   ├── build.sh                     # Cross-platform build
│   └── benchmark.sh                 # Run benchmarks
│
├── SPECIFICATION.md                 # (Generated by Claude Code)
├── IMPLEMENTATION.md                # (Generated by Claude Code)
├── TASKS.md                         # (Generated by Claude Code)
├── BRANDING.md                      # (Generated by Claude Code)
├── README.md                        # (Generated by Claude Code)
├── LICENSE                          # MIT
├── go.mod
├── Dockerfile
├── docker-compose.yml               # Example deployment
├── .github/
│   └── workflows/
│       ├── ci.yml                   # Test + lint + build
│       └── release.yml              # GoReleaser
├── .golangci.yml
├── .goreleaser.yml
└── Makefile
```

---

## 10. Performance Requirements

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

---

## 11. Testing Strategy

### 11.1 Detection Accuracy Tests

For EACH detector, maintain three test fixture files:

```
testdata/attacks/sqli.json      → Known SQLi payloads (MUST detect, score >= block_threshold)
testdata/benign/sqli.json       → Legitimate inputs (MUST NOT block, score < log_threshold)
testdata/edge_cases/sqli.json   → Tricky inputs (document expected scores)
```

Source payloads from:
- OWASP Testing Guide examples (manually curated, NOT imported)
- Real-world attack patterns from security research
- Known WAF bypass techniques
- Legitimate content that looks like attacks (O'Brien, SQL tutorials, etc.)

### 11.2 Benchmark Tests

```go
func BenchmarkFullPipeline_CleanRequest(b *testing.B) {}
func BenchmarkFullPipeline_SQLiAttack(b *testing.B) {}
func BenchmarkSQLiTokenizer(b *testing.B) {}
func BenchmarkRadixTree_10K_Rules(b *testing.B) {}
func BenchmarkRateLimiter_100K_IPs(b *testing.B) {}
func BenchmarkJA3_Computation(b *testing.B) {}
```

### 11.3 Fuzz Tests

```go
func FuzzSQLiDetector(f *testing.F) {}
func FuzzXSSDetector(f *testing.F) {}
func FuzzURLNormalizer(f *testing.F) {}
func FuzzYAMLParser(f *testing.F) {}
```

### 11.4 Integration Tests

Full request lifecycle: HTTP client → GuardianWAF → mock backend → response. Test all six layers in sequence. Test whitelist bypass. Test rate limiting across time windows. Test hot config reload.

---

## 12. Implementation Phases

### Phase 1: Foundation (Week 1-2)
- Project scaffolding (go.mod, Makefile, CI)
- YAML parser (subset)
- Configuration system
- Layer interface, pipeline composition
- Engine struct with middleware wrapper
- Event system (event bus, ring buffer store)
- RequestContext builder

### Phase 2: Core Detection (Week 3-5)
- Request sanitizer (normalization + validation)
- SQLi tokenizer and detector
- XSS detector
- Path traversal detector
- Command injection detector
- XXE detector
- SSRF detector
- Detection engine (score accumulation, threshold logic)
- Comprehensive test fixtures for all detectors

### Phase 3: IP ACL & Rate Limiting (Week 6-7)
- Radix tree implementation
- IP ACL layer (whitelist/blacklist/auto-ban)
- Token bucket rate limiter
- Rate limit rule matching
- Auto-ban integration

### Phase 4: Bot Detection & Response (Week 8-9)
- JA3 fingerprint computation
- User-Agent analyzer
- Behavioral analysis (sliding window)
- Bot detection layer
- Response protection (security headers, data masking, error pages)

### Phase 5: Reverse Proxy (Week 10-11)
- HTTP reverse proxy with connection pooling
- Load balancing algorithms
- Health check system
- Circuit breaker
- WebSocket proxying
- TLS termination and ACME

### Phase 6: Dashboard & API (Week 12-13)
- REST API handlers
- SSE real-time updates
- Web dashboard (HTML/CSS/JS)
- API key authentication
- Analytics engine (rolling counters, TopK)

### Phase 7: MCP & CLI (Week 14)
- CLI flag parsing and mode routing
- MCP server (stdio transport)
- MCP tool definitions and handlers
- `check` and `validate` subcommands

### Phase 8: Polish (Week 15-16)
- Sidecar mode
- Docker packaging
- Performance benchmarking and optimization
- Fuzz testing
- Documentation
- Examples (standalone, library, sidecar, K8s)
- BRANDING.md and README.md
- GoReleaser and GitHub Actions CI/CD

---

## 13. llms.txt

Create a `llms.txt` file in the project root:

```
# GuardianWAF

> Zero-dependency Web Application Firewall in Go. Single binary. Three deployment modes.

## What is GuardianWAF?
GuardianWAF is a production-grade WAF that compiles to a single Go binary with zero external dependencies. It protects web applications from SQL injection, XSS, path traversal, command injection, XXE, SSRF, and bot attacks using a tokenizer-based scoring engine.

## Quick Start
go install github.com/guardianwaf/guardianwaf/cmd/guardianwaf@latest
guardianwaf serve -c guardianwaf.yaml

## Deployment Modes
- Standalone: Full reverse proxy with dashboard and MCP server
- Library: Import as Go middleware for any net/http application
- Sidecar: Minimal proxy for Docker/Kubernetes sidecar pattern

## Key APIs
- guardianwaf.New(config) → Engine
- engine.Middleware(handler) → http.Handler
- engine.Check(request) → Result

## Configuration
All configuration via guardianwaf.yaml. See docs/configuration.md.

## MCP Tools
guardianwaf_get_stats, guardianwaf_get_events, guardianwaf_add_whitelist,
guardianwaf_add_blacklist, guardianwaf_add_ratelimit, guardianwaf_set_mode
```

---

## IMPORTANT REMINDERS

1. **Start with SPECIFICATION.md.** Do not write any code until all four documents are complete.
2. **Zero dependencies means ZERO.** Not "almost zero." Not "just one small library." ZERO. If you need YAML parsing, write a parser. If you need a radix tree, implement one.
3. **The scoring system is the core innovation.** Get it right. Every pattern needs a well-reasoned score. Document WHY each score is what it is.
4. **Test fixtures are as important as code.** The detection engine is only as good as its tests. Include real-world attack payloads and real-world benign inputs that LOOK like attacks.
5. **Performance is a feature.** If the WAF adds > 1ms latency, nobody will use it. Profile early, optimize the hot path, use sync.Pool.
6. **The dashboard is a differentiator.** SafeLine's dashboard is why it has 16K+ stars. Make GuardianWAF's dashboard beautiful, real-time, and useful.
7. **MCP integration is future-proof.** AI agents will manage infrastructure. GuardianWAF should be the first WAF that AI agents can fully operate.
