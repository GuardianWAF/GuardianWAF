# GuardianWAF Architecture Map

## 1. Tech Stack Detection

### Go Version & Dependencies
- **Go Version**: 1.25.0 (from `go.mod`)
- **Module**: `github.com/guardianwaf/guardianwaf`
- **Direct Dependency**: `github.com/quic-go/quic-go v0.59.0` (HTTP/3 support, build with `-tags http3`)
- **Indirect Dependencies**: `golang.org/x/crypto`, `golang.org/x/net`, `golang.org/x/sys`, `golang.org/x/text`
- **Build Tags**: `http3` enables QUIC support; stub implementation otherwise

### Zero-Dependency Constraint
GuardianWAF maintains a strict **zero external Go dependencies** policy (except quic-go for HTTP/3). All functionality uses Go standard library only.

### Build Targets
```
make build       # Binary with embedded React dashboard
make ui          # React dashboard only
make ui-dev      # Hot-reload dev mode (:5173, proxies API to :9443)
make docker-test # Full Docker Compose integration test
```

---

## 2. Entry Points

### CLI Entry Point
**File**: `cmd/guardianwaf/main.go` (platform-specific variants in `cmd/guardianwaf/main_default.go`)

```
Commands:
  guardianwaf serve     # Standalone reverse proxy (full features, dashboard on :9443)
  guardianwaf sidecar   # Lightweight proxy (no dashboard/MCP)
  guardianwaf check     # Dry-run request test
  guardianwaf validate   # Config file validation
```

### Public Library API
**Files**: `guardianwaf.go`, `options.go`

Key functions:
- `New(cfg Config, opts ...Option) (*Engine, error)` — programmatic creation
- `NewFromFile(path string, opts ...Option) (*Engine, error)` — from YAML
- `Middleware(http.Handler) http.Handler` — HTTP middleware wrapper
- `Check(*http.Request) Result` — dry-run scoring
- `OnEvent(func(Event))` — event callback
- `Stats()` / `Close()` — lifecycle

### HTTP Server Entry Points
1. **Proxy Server**: `:8088` (HTTP) / `:8443` (TLS) — WAF-protected traffic
2. **Dashboard API**: `:9443` — Admin REST API + React SPA
3. **MCP Server**: stdio / SSE — JSON-RPC 2.0 tool interface

---

## 3. Critical Attack Surfaces

### 3.1 Config Parsing (`internal/config/`)

**Files**:
- `yaml.go` — Custom zero-dependency YAML parser (no `gopkg.in/yaml` dependency)
- `config.go` — Config struct definitions
- `defaults.go` — Default configuration
- `validate.go` — Config validation
- `serialize.go` — YAML serialization

**Key Functions**:
- `LoadFile(path string) (*Config, error)` — loads YAML config
- `LoadDir(dir string) (*Config, error)` — loads from directory structure (`guardianwaf.yaml`, `rules.d/`, `domains.d/`, `tenants.d/`)
- `LoadEnv(cfg *Config)` — overlays `GWAF_*` environment variables
- `PopulateFromNode(cfg *Config, node *Node) error` — walks Node tree to populate Config

**Attack Surface**:
- **YAML Parser** (`yaml.go`): Custom parser handling maps, sequences, scalars, block scalars (`|`, `>`), flow collections, comments. **Does NOT support anchors, aliases, tags, or multi-document YAML** — reducing attack surface.
- **Env Var Interpolation** (`expandEnvVars`): Supports `${VAR}` and `${VAR:-default}` patterns. Validates var names (alphanumeric + underscore only) before calling `os.Getenv()`. Double-encoding attack mitigated.
- **File Loading** (`LoadDir`): Reads from subdirectories (`rules.d/*.yaml`, `domains.d/*.yaml`, `tenants.d/*.yaml`). Arrays are appended (not replaced).

**Vulnerability Hotspots**:
- `expandEnvVars()` at line 1114-1169: Environment variable expansion in YAML values
- `makeScalar()` at line 986-1028: Type coercion from YAML strings
- `parseKeyValue()` at line 872-929: Key-value pair parsing with quote handling

### 3.2 TLS Handling (`internal/tls/`)

**File**: `certstore.go`

**Key Types**:
- `CertStore` — manages TLS certificates with SNI-based selection and hot-reload
- `CertEntry` — loaded certificate with domain coverage and modification times

**Key Functions**:
- `LoadDefaultCert(certFile, keyFile string) error` — fallback certificate
- `LoadCert(domains []string, certFile, keyFile string) error` — per-domain certs
- `GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)` — SNI-based selection callback
- `TLSConfig() *tls.Config` — builds TLS config
- `StartReload(interval time.Duration)` — background cert hot-reload goroutine

**Security Properties**:
- Minimum TLS version: **TLS 1.3** (hardcoded, not configurable for TLS 1.3)
- HTTP/2 enabled via NextProtos negotiation (`h2`, `http/1.1`)
- Certificate hot-reload via file modification time polling (30s default interval)
- Panic recovery in reload goroutine (line 152-155)

**Vulnerability Hotspots**:
- `reloadIfChanged()` at line 210-256: File stat on every reload cycle
- `LoadCert()` at line 63-103: Certificate loading with file stat tracking

### 3.3 Proxy Handlers (`internal/proxy/`)

**Files**:
- `router.go` — Virtual host routing + path-based routing
- `target.go` — Single backend target with reverse proxy, circuit breaker, SSRF prevention
- `balancer.go` — Load balancing strategies (round_robin, weighted, least_conn, ip_hash)
- `circuit.go` — Circuit breaker implementation
- `health.go` — Health checking
- `grpc/proxy.go` — gRPC/gRPC-Web proxy

**Key Functions**:
- `Router.ServeHTTP(w http.ResponseWriter, r *http.Request)` — line 81
- `Target.ServeHTTP(w http.ResponseWriter, r *http.Request, stripPrefix string)` — line 205
- `NewTarget(rawURL string, weight int) (*Target, error)` — line 124

**SSRF Prevention** (`target.go`):
- `IsPrivateOrReservedIP(host string) error` — checks loopback, private, link-local ranges
- `SSRFDialContext() func(ctx context.Context, network, addr string) (net.Conn, error)` — DNS resolution validation at dial time (prevents DNS rebinding/TOCTOU)

**Vulnerability Hotspots**:
- `Target.ServeHTTP()` at line 205: Request proxying with strip prefix
- `Router.lookupRoutes()` at line 112: Virtual host lookup by Host header
- `stripPort()` at line 220: Host header port stripping (IPv6-aware)
- **Path normalization bypass prevention**: `path.Clean(r.URL.Path)` at line 85

### 3.4 Request Context & Client IP Extraction (`internal/engine/context.go`)

**Key Functions**:
- `AcquireContext(r *http.Request, paranoiaLevel int, maxBodySize int64) *RequestContext` — line 142
- `ReleaseContext(ctx *RequestContext)` — line 247
- `extractClientIP(r *http.Request) net.IP` — line 311

**Client IP Extraction Security**:
- Only trusts `X-Forwarded-For` / `X-Real-IP` when direct connection is from **trusted proxy**
- Uses rightmost non-trusted IP from `X-Forwarded-For` chain (not leftmost)
- `TrustedProxies` configuration controls which CIDRs are trusted
- When no trusted proxies configured: **always uses `RemoteAddr`**

**Untrusted Input Handled**:
- HTTP headers (capped at 100 headers to prevent exhaustion)
- Query parameters
- Cookies
- Request body (decompressed gzip/deflate with 100:1 ratio limit to prevent decompression bombs)
- TLS info (version, cipher suite, SNI)

**Vulnerability Hotspots**:
- `extractClientIP()` at line 311-346: IP extraction from proxy headers
- `AcquireContext()` body reading at line 192-228: Decompression bomb prevention
- Header cap at 100 (`len(ctx.Headers) >= 100` at line 169)

---

## 4. Data Flow — WAF Pipeline

### Pipeline Architecture (`internal/engine/pipeline.go`)

```
Request → Middleware (engine.Middleware)
            ↓
    AcquireContext (from sync.Pool)
            ↓
    TenantContext injection (optional)
            ↓
    Pipeline.Execute(ctx)
            ↓
    ┌───────────────────────────────────────────────┐
    │  Layer 100: IPACL                            │
    │  Layer 125: ThreatIntel                      │
    │  Layer 150: CORS / Custom Rules              │
    │  Layer 200: RateLimit                         │
    │  Layer 250: ATO Protection                   │
    │  Layer 275: APISecurity (JWT/API Key)        │
    │  Layer 280: APIValidation                     │
    │  Layer 300: Sanitizer                        │
    │  Layer 350: CRS (OWASP ModSecurity)          │
    │  Layer 400: Detection (sqli/xss/lfi/cmdi/    │
    │              xxe/ssrf)                       │
    │  Layer 450: VirtualPatch                       │
    │  Layer 475: DLP                              │
    │  Layer 500: BotDetect                        │
    │  Layer 590: ClientSide                       │
    │  Layer 600: Response                         │
    └───────────────────────────────────────────────┘
            ↓
    determineAction(score, thresholds)
            ↓
    [ActionBlock] → 403 + block page
    [ActionChallenge] → JS proof-of-work challenge
    [ActionLog] → log only
    [ActionPass] → next.ServeHTTP(w, r)
            ↓
    ReleaseContext (return to sync.Pool)
```

### Request Context Flow (`internal/engine/context.go`)

1. **AcquireContext** (line 142): Pooled allocation, populates all fields from HTTP request
2. **Body Processing** (line 192-228):
   - Read raw body (limited by `maxBodySize`)
   - Restore original body for proxying
   - Decompress gzip/deflate for WAF inspection (100:1 ratio limit)
3. **Context Released** (line 247): All fields cleared, returned to pool

### Layer Execution Order (`internal/engine/layer.go`)

| Order | Layer | Purpose |
|-------|-------|---------|
| 100 | IPACL | Radix tree CIDR matching, runtime add/remove, auto-ban |
| 125 | Threat Intel | IP/domain reputation feeds with LRU cache |
| 150 | CORS | Origin validation, preflight caching |
| 150 | Custom Rules | Geo-aware rule engine with dashboard CRUD |
| 200 | Rate Limit | Token bucket per IP/path, auto-ban |
| 250 | ATO Protection | Brute force, credential stuffing, password spray, impossible travel |
| 275 | API Security | JWT validation (RS256/ES256/HS256), API key auth |
| 280 | API Validation | Request/response schema validation (YAML-defined schemas) |
| 300 | Sanitizer | Normalize + validate requests |
| 350 | CRS | OWASP ModSecurity Core Rule Set parser and executor |
| 400 | Detection | 6 detectors: sqli, xss, lfi, cmdi, xxe, ssrf |
| 450 | Virtual Patch | Virtual patching layer |
| 475 | DLP | Data Loss Prevention (credit cards, SSNs, API keys, PII) |
| 500 | Bot Detection | JA3/JA4 TLS fingerprinting, UA, behavioral analysis |
| 590 | Client-Side | Client-side protection injection |
| 600 | Response | Security headers, data masking, branded block pages |

### Scoring System (`internal/engine/finding.go`)

- **ScoreAccumulator**: Accumulates findings from all layers
- **Paranoia multiplier**: 1 (0.5x), 2 (1.0x), 3 (1.5x), 4 (2.0x)
- **Score cap**: 10000 (prevents overflow)
- **Thresholds**: `block_threshold: 50`, `log_threshold: 25` (defaults)

---

## 5. Trust Boundaries

### 5.1 Dashboard Authentication (`internal/dashboard/auth.go`)

**Session Security**:
- **Cookie**: `gwaf_session` with `HttpOnly`, `Secure`, `SameSite=Strict`, 24h max age
- **HMAC-SHA256 signing**: `timestamp.creation_timestamp.signature` bound to client IP
- **Sliding expiry**: 24 hours
- **Absolute expiry**: 7 days
- **API Key**: Constant-time comparison via `subtle.ConstantTimeCompare`

**Key Functions**:
- `signSession(clientIP string) string` — line 62
- `verifySession(token, clientIP string) bool` — line 72
- `isAuthenticated(r *http.Request) bool` — line 121

**Trust Boundary**: Dashboard API at `:9443` — requires valid session or API key

### 5.2 Tenant Isolation (`internal/engine/engine.go`, `context.go`)

**TenantContext** (line 67-74 in `engine.go`):
```go
type TenantContext struct {
    ID            string
    WAFConfig    *config.WAFConfig
    VirtualHosts []config.VirtualHostConfig
}
```

**Tenant Resolution**: Via `WithTenantContext()` / `GetTenantContext()` from `context.Context`
**Multi-Tenant Isolation**: Per-tenant WAF config overrides via `RequestContext.TenantWAFConfig`

### 5.3 IP ACL (`internal/layers/ipacl/`)

- **Radix tree** CIDR matching for O(k) lookups (k = bits in address)
- **Whitelist/Blacklist** with auto-ban support
- **Auto-ban TTL**: configurable with `DefaultTTL` / `MaxTTL`

### 5.4 API Key Validation (`internal/layers/apisecurity/apikey.go`)

**Key Types**:
- `sha256:hex` — SHA-256 hash comparison
- `bcrypt:` — bcrypt hash (if enabled)

**Functions**:
- `Validate(key, path string) (*APIKeyConfig, error)` — standard validation
- `ValidateConstantTime(key, path string) (*APIKeyConfig, error)` — constant-time comparison

**Vulnerability Hotspot**: `Validate()` at line 65 — SHA-256 hash of provided key compared against stored hashes

### 5.5 JWT Validation (`internal/layers/apisecurity/`)

- Supports RS256, ES256, HS256 algorithms
- JWKS URL fetching with TLS
- Clock skew tolerance configurable
- Public key PEM or file loading

---

## 6. Authentication/Authorization Surfaces

### 6.1 Dashboard API (`internal/dashboard/`)

**Auth Methods**:
1. **API Key** via `X-API-Key` header (constant-time comparison)
2. **Session Cookie** via HMAC-SHA256 (IP-bound)

**Middleware Chain** (`middleware.go`):
- `RecoveryMiddleware` — panic recovery with JSON error response
- `LoggingMiddleware` — request logging
- `SecurityHeadersMiddleware` — CSP, HSTS, X-Frame-Options, etc.
- `CORSMiddleware` — same-origin only (no cross-origin Allow)
- `verifySameOrigin()` — CSRF protection for state-changing requests

**Protected Routes**: All `/api/*` endpoints require authentication

### 6.2 MCP Server (`internal/mcp/`)

**Transport**: stdio (JSON-RPC 2.0) or SSE

**Tool Handlers** (44 tools):
- `get_stats`, `get_events`, `add_blacklist`, `remove_blacklist`
- `get_top_ips`, `get_detectors`, `test_request`
- Alerting, CRS, Virtual Patch, API Validation, Client-Side, DLP management

**Security**: MCP tools expose privileged operations — access should be restricted to admin interfaces

### 6.3 Proxy Authentication (`internal/layers/apisecurity/`)

**JWT Validation**:
- Header: `Authorization: Bearer <token>`
- Supports multiple algorithms
- JWKS URL fetching

**API Key Validation**:
- Header: `X-API-Key` or query param (query param rejected — logs warning)
- Path-based restrictions via glob patterns
- Rate limiting per key

---

## 7. Vulnerability Hotspot Summary

### Critical Attack Surfaces

| Component | File | Function | Risk |
|-----------|------|----------|------|
| YAML Parsing | `config/yaml.go` | `Parse()`, `expandEnvVars()` | Injection via env var interpolation |
| Config Loading | `config/validate.go` | `LoadFile()`, `LoadDir()` | Path traversal in subdirectory loading |
| Client IP Extraction | `engine/context.go` | `extractClientIP()` | IP spoofing via X-Forwarded-For |
| Body Decompression | `engine/context.go` | `AcquireContext()` | Decompression bomb ( mitigated via 100:1 ratio cap) |
| Virtual Host Routing | `proxy/router.go` | `lookupRoutes()` | Host header injection |
| SSRF Prevention | `proxy/target.go` | `SSRFDialContext()` | DNS rebinding (mitigated via pre-dial DNS check) |
| Session Signing | `dashboard/auth.go` | `signSession()` | Session fixation/hijacking |
| API Key Hashing | `apisecurity/apikey.go` | `Validate()` | Timing attack (mitigated via constant-time comparison) |
| Path Normalization | `proxy/router.go` | line 85 | Path traversal bypass |
| Header Cap | `engine/context.go` | line 169 | Header exhaustion DoS |
| TLS Cert Reload | `tls/certstore.go` | `reloadIfChanged()` | TOCTOU race condition |

### Security Mitigations in Place

1. **SSRF Prevention**: DNS resolution at dial time, not at config time
2. **Decompression Bomb Prevention**: 100:1 ratio limit
3. **Header Exhaustion Prevention**: Cap at 100 headers
4. **Session Binding**: HMAC-SHA256 bound to client IP
5. **Constant-Time Comparison**: API key validation uses `subtle.ConstantTimeCompare`
6. **Score Cap**: 10000 max score prevents overflow attacks
7. **TLS 1.3 Minimum**: Cannot be downgraded
8. **No Query Param API Keys**: Rejected and logged
9. **Path Normalization**: `path.Clean()` prevents traversal bypass

---

## 8. Key File Reference

| Concern | File Path | Key Functions/Types |
|---------|-----------|-------------------|
| Public API | `guardianwaf.go` | `Engine`, `New()`, `Middleware()`, `Check()` |
| Options | `options.go` | `Option` functional options |
| Engine | `internal/engine/engine.go` | `Engine`, `Middleware()`, `Check()` |
| Pipeline | `internal/engine/pipeline.go` | `Pipeline`, `Execute()`, `AddLayer()` |
| Context | `internal/engine/context.go` | `RequestContext`, `AcquireContext()`, `extractClientIP()` |
| Findings | `internal/engine/finding.go` | `Finding`, `ScoreAccumulator` |
| Layer Interface | `internal/engine/layer.go` | `Layer`, `Action`, `Order*` constants |
| Events | `internal/engine/event.go` | `Event`, `NewEvent()` |
| Config Parsing | `internal/config/yaml.go` | `Parse()`, `Node`, `expandEnvVars()` |
| Config Loading | `internal/config/config.go` | `Config` structs |
| Config Validation | `internal/config/validate.go` | `Validate()`, `LoadFile()`, `LoadDir()` |
| Config Defaults | `internal/config/defaults.go` | `DefaultConfig()` |
| Proxy Router | `internal/proxy/router.go` | `Router`, `ServeHTTP()` |
| Proxy Target | `internal/proxy/target.go` | `Target`, `ServeHTTP()`, `SSRFDialContext()` |
| Load Balancer | `internal/proxy/balancer.go` | `Balancer`, strategies |
| Circuit Breaker | `internal/proxy/circuit.go` | `CircuitBreaker` |
| TLS Cert Store | `internal/tls/certstore.go` | `CertStore`, `GetCertificate()` |
| Dashboard Auth | `internal/dashboard/auth.go` | `signSession()`, `verifySession()`, `isAuthenticated()` |
| Dashboard Middleware | `internal/dashboard/middleware.go` | `RecoveryMiddleware`, `SecurityHeadersMiddleware` |
| Dashboard Routes | `internal/dashboard/dashboard.go` | HTTP handlers |
| API Security | `internal/layers/apisecurity/apikey.go` | `APIKeyValidator`, `Validate()` |
| Detection Layer | `internal/layers/detection/detector.go` | `Layer` interface |
| SQli Detector | `internal/layers/detection/sqli/` | Tokenizer-based detection |
| XSS Detector | `internal/layers/detection/xss/` | Parser-based detection |
| Sanitizer | `internal/layers/sanitizer/validate.go` | `ValidateRequest()` |
| MCP Server | `internal/mcp/server.go` | `Server`, `HandleRequestJSON()` |
| MCP Handlers | `internal/mcp/handlers.go` | Tool implementations |
| Event Store | `internal/events/memory.go` | `MemoryStore` |
| Event Bus | `internal/events/bus.go` | `EventBus` |

---

## 9. Data Flow Diagrams

### WAF Request Processing

```
Client Request
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ engine.Middleware (line 260 in engine.go)                   │
│  1. Panic recovery (defer recover)                        │
│  2. AcquireContext from pool                              │
│  3. Inject TenantContext if present                       │
│  4. Execute pipeline                                      │
│  5. Determine action from score + thresholds              │
│  6. Apply security headers                                │
│  7. ReleaseContext to pool                               │
│  8. Store + publish event                                │
│  9. Write response (block/challenge/pass)                 │
└─────────────────────────────────────────────────────────────┘
      │
      ▼ (if pass)
┌─────────────────────────────────────────────────────────────┐
│ Proxy Router (router.go:81)                               │
│  1. Normalize path (path.Clean)                          │
│  2. Lookup virtual host by Host header                    │
│  3. Match route by path prefix                           │
│  4. Select target via load balancer                       │
│  5. Strip prefix if configured                           │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│ Target.ServeHTTP (target.go:205)                          │
│  1. Check circuit breaker state                           │
│  2. Track active connections                              │
│  3. Clone request with strip prefix                       │
│  4. Proxy via httputil.ReverseProxy                       │
│  5. Custom Director: strip X-Forwarded-Host/Proto        │
│  6. SSRF-preventing DialContext                           │
│  7. ErrorHandler: drain body, record failure             │
│  8. ModifyResponse: record success/failure               │
└─────────────────────────────────────────────────────────────┘
      │
      ▼
Upstream Backend
```

### Detection Pipeline Detail

```
Detection Layer (Order 400)
      │
      ├── sqli/    ──► Tokenizer-based SQL injection detection
      │                 (keywords, patterns, token analysis)
      ├── xss/     ──► Parser-based XSS detection
      │                 (HTML parsing, script tag detection)
      ├── lfi/     ──► Local file inclusion detection
      │                 (path traversal patterns, sensitive paths)
      ├── cmdi/    ──► Command injection detection
      │                 (shell metacharacters, dangerous commands)
      ├── xxe/     ──► XML external entity detection
      │                 (XML parsing, entity expansion)
      └── ssrf/    ──► Server-side request forgery detection
                        (URL parsing, private IP ranges)

Each detector:
  1. Tokenizes/analyzes request components
  2. Returns []Finding with Score, Severity, Location
  3. ScoreAccumulator.AddMultiple() merges findings
  4. Final score compared against thresholds
```

---

## 10. Security Configuration Reference

### Default Thresholds
- **Block threshold**: 50
- **Log threshold**: 25
- **Paranoia level**: 2 (1.0x multiplier)

### Default Sanitizer Limits
- **MaxURLLength**: 8192 bytes
- **MaxHeaderSize**: 8192 bytes
- **MaxHeaderCount**: 100
- **MaxBodySize**: 10MB
- **MaxCookieSize**: 4096 bytes
- **BlockNullBytes**: true

### Default Detection Settings
- All 6 detectors enabled (sqli, xss, lfi, cmdi, xxe, ssrf)
- Multiplier: 1.0 for all
- Exclusions: none by default

### TLS Configuration
- **Minimum version**: TLS 1.3
- **HTTP/2**: enabled via ALPN (`h2`, `http/1.1`)
- **Certificate hot-reload**: 30s interval

### Session Security
- **Cookie name**: `gwaf_session`
- **Max age**: 24 hours (sliding)
- **Absolute max**: 7 days
- **Flags**: HttpOnly, Secure, SameSite=Strict
