export interface DocSection {
  id: string
  title: string
  subsections?: { id: string; title: string }[]
}

export interface DocContent {
  id: string
  title: string
  content: DocBlock[]
}

export type DocBlock =
  | { type: 'paragraph'; text: string }
  | { type: 'heading'; level: 2 | 3 | 4; text: string; id?: string }
  | { type: 'code'; code: string; language?: string; filename?: string }
  | { type: 'list'; items: string[]; ordered?: boolean }
  | { type: 'table'; headers: string[]; rows: string[][] }
  | { type: 'callout'; variant: 'info' | 'warning' | 'tip'; text: string }

export const docSections: DocSection[] = [
  {
    id: 'getting-started',
    title: 'Getting Started',
    subsections: [
      { id: 'installation', title: 'Installation' },
      { id: 'first-run', title: 'First Run' },
      { id: 'verify', title: 'Verify Installation' },
    ],
  },
  {
    id: 'configuration',
    title: 'Configuration',
    subsections: [
      { id: 'config-file', title: 'Config File' },
      { id: 'environment-vars', title: 'Environment Variables' },
      { id: 'cli-flags', title: 'CLI Flags' },
    ],
  },
  {
    id: 'security-layers',
    title: 'Security Layers',
    subsections: [
      { id: 'layer-pipeline', title: 'Pipeline Overview' },
      { id: 'ip-acl', title: 'IP ACL (100)' },
      { id: 'threat-intel', title: 'Threat Intel (125)' },
      { id: 'cors-layer', title: 'CORS (150)' },
      { id: 'rate-limit', title: 'Rate Limit (200)' },
      { id: 'ato-protection', title: 'ATO Protection (250)' },
      { id: 'api-security', title: 'API Security (275)' },
      { id: 'sanitizer', title: 'Sanitizer (300)' },
      { id: 'detection', title: 'Detection (400)' },
      { id: 'bot-detection', title: 'Bot Detection (500)' },
      { id: 'response-layer', title: 'Response (600)' },
    ],
  },
  {
    id: 'detection-engine',
    title: 'Detection Engine',
    subsections: [
      { id: 'tokenizer', title: 'Tokenizer' },
      { id: 'detectors', title: 'Detectors' },
      { id: 'scoring-system', title: 'Scoring System' },
    ],
  },
  {
    id: 'deployment-modes',
    title: 'Deployment Modes',
    subsections: [
      { id: 'standalone-proxy', title: 'Standalone Proxy' },
      { id: 'embedded-library', title: 'Embedded Library' },
      { id: 'sidecar-proxy', title: 'Sidecar Proxy' },
    ],
  },
  {
    id: 'api-reference',
    title: 'API Reference',
    subsections: [
      { id: 'core-api', title: 'Core API' },
      { id: 'middleware', title: 'Middleware' },
      { id: 'dashboard-api', title: 'Dashboard API' },
    ],
  },
  {
    id: 'mcp-integration',
    title: 'MCP Integration',
    subsections: [
      { id: 'mcp-overview', title: 'Overview' },
      { id: 'mcp-tools', title: 'Available Tools' },
      { id: 'mcp-setup', title: 'Setup' },
    ],
  },
  {
    id: 'tuning-guide',
    title: 'Tuning Guide',
    subsections: [
      { id: 'false-positives', title: 'Reducing False Positives' },
      { id: 'threshold-tuning', title: 'Threshold Tuning' },
      { id: 'custom-rules', title: 'Custom Rules' },
    ],
  },
]

export const docContents: DocContent[] = [
  {
    id: 'getting-started',
    title: 'Getting Started',
    content: [
      { type: 'paragraph', text: 'GuardianWAF is a production-grade Web Application Firewall written in pure Go with zero external dependencies. This guide will walk you through installation and your first deployment.' },
      { type: 'callout', variant: 'info', text: 'GuardianWAF requires Go 1.22+ if building from source. Pre-built binaries are available for Linux, macOS, and Windows.' },
      { type: 'heading', level: 2, text: 'Installation', id: 'installation' },
      { type: 'heading', level: 3, text: 'Pre-built Binaries' },
      { type: 'paragraph', text: 'Download the latest release for your platform:' },
      { type: 'code', language: 'bash', filename: 'Terminal', code: `# Linux (amd64)
curl -sL https://github.com/GuardianWAF/GuardianWAF/releases/latest/download/guardianwaf-linux-amd64 -o guardianwaf

# macOS (arm64)
curl -sL https://github.com/GuardianWAF/GuardianWAF/releases/latest/download/guardianwaf-darwin-arm64 -o guardianwaf

# Make executable
chmod +x guardianwaf` },
      { type: 'heading', level: 3, text: 'From Source' },
      { type: 'code', language: 'bash', filename: 'Terminal', code: `go install github.com/guardianwaf/guardianwaf/cmd/guardianwaf@latest` },
      { type: 'heading', level: 3, text: 'Docker' },
      { type: 'code', language: 'bash', filename: 'Terminal', code: `docker pull ghcr.io/guardianwaf/guardianwaf:latest` },
      { type: 'heading', level: 2, text: 'First Run', id: 'first-run' },
      { type: 'paragraph', text: 'Start GuardianWAF as a reverse proxy in front of your application:' },
      { type: 'code', language: 'bash', filename: 'Terminal', code: `./guardianwaf serve --listen :8088 --upstream http://localhost:3000` },
      { type: 'paragraph', text: 'GuardianWAF will start listening on port 8088 and forward clean requests to your application on port 3000. All requests are analyzed in real-time.' },
      { type: 'heading', level: 2, text: 'Verify Installation', id: 'verify' },
      { type: 'paragraph', text: 'Test that GuardianWAF is properly intercepting malicious requests:' },
      { type: 'code', language: 'bash', filename: 'Terminal', code: `# This should be blocked (SQL injection)
curl -i "http://localhost:8088/?id=1' OR 1=1--"

# This should pass through
curl -i "http://localhost:8088/api/health"` },
      { type: 'callout', variant: 'tip', text: 'Use --dry-run mode during initial deployment to monitor threats without blocking any traffic.' },
    ],
  },
  {
    id: 'configuration',
    title: 'Configuration',
    content: [
      { type: 'paragraph', text: 'GuardianWAF supports configuration through YAML files, environment variables, and CLI flags. Configuration sources are merged with the following precedence: CLI flags > environment variables > config file > defaults.' },
      { type: 'heading', level: 2, text: 'Config File', id: 'config-file' },
      { type: 'paragraph', text: 'Create a guardianwaf.yaml file:' },
      { type: 'code', language: 'yaml', filename: 'guardianwaf.yaml', code: `server:
  listen: ":8088"
  upstream: "http://localhost:3000"
  read_timeout: 30s
  write_timeout: 30s

detection:
  block_score: 80
  log_score: 40
  detectors:
    - sqli
    - xss
    - path_traversal
    - command_injection
    - protocol_anomaly
    - bot

dashboard:
  enabled: true
  listen: ":9090"

tls:
  enabled: false
  acme:
    enabled: false
    email: "admin@example.com"
    domains:
      - "example.com"

logging:
  level: "info"
  format: "json"
  output: "stdout"` },
      { type: 'heading', level: 2, text: 'Environment Variables', id: 'environment-vars' },
      { type: 'paragraph', text: 'All configuration options can be set via environment variables with the GUARDIANWAF_ prefix:' },
      { type: 'table', headers: ['Variable', 'Description', 'Default'], rows: [
        ['GUARDIANWAF_LISTEN', 'Listen address', ':8088'],
        ['GUARDIANWAF_UPSTREAM', 'Upstream server URL', '(required)'],
        ['GUARDIANWAF_BLOCK_SCORE', 'Score threshold for blocking', '80'],
        ['GUARDIANWAF_LOG_SCORE', 'Score threshold for logging', '40'],
        ['GUARDIANWAF_DRY_RUN', 'Enable dry-run mode', 'false'],
        ['GUARDIANWAF_DASHBOARD', 'Dashboard listen address', ':9090'],
        ['GUARDIANWAF_LOG_LEVEL', 'Log level (debug/info/warn/error)', 'info'],
        ['GUARDIANWAF_LOG_FORMAT', 'Log format (json/text)', 'json'],
      ] },
      { type: 'heading', level: 2, text: 'CLI Flags', id: 'cli-flags' },
      { type: 'code', language: 'bash', filename: 'Terminal', code: `./guardianwaf serve \\
  --config guardianwaf.yaml \\
  --listen :8088 \\
  --upstream http://localhost:3000 \\
  --block-score 80 \\
  --log-score 40 \\
  --dry-run \\
  --dashboard :9090 \\
  --log-level info` },
    ],
  },
  {
    id: 'detection-engine',
    title: 'Detection Engine',
    content: [
      { type: 'paragraph', text: 'The detection engine is the core of GuardianWAF. It uses a tokenizer-based approach that breaks down HTTP requests into semantic tokens, then runs multiple specialized detectors in parallel.' },
      { type: 'heading', level: 2, text: 'Tokenizer', id: 'tokenizer' },
      { type: 'paragraph', text: 'Unlike regex-based WAFs, GuardianWAF uses a custom tokenizer that understands the structure of HTTP requests. The tokenizer produces semantic tokens from:' },
      { type: 'list', items: [
        'URI path segments and query parameters',
        'Request headers (User-Agent, Referer, Cookie, etc.)',
        'Request body (form data, JSON, multipart)',
        'Decoded values (URL encoding, base64, unicode escapes)',
      ] },
      { type: 'paragraph', text: 'The tokenizer handles multi-layer encoding, ensuring that obfuscated payloads are properly decoded before analysis.' },
      { type: 'heading', level: 2, text: 'Detectors', id: 'detectors' },
      { type: 'paragraph', text: 'GuardianWAF ships with six built-in detectors:' },
      { type: 'table', headers: ['Detector', 'Targets', 'Technique'], rows: [
        ['SQLi', 'SQL injection attacks', 'Token pattern matching, tautology detection, UNION analysis'],
        ['XSS', 'Cross-site scripting', 'Tag/attribute analysis, event handler detection, JS context analysis'],
        ['Path Traversal', 'Directory traversal', 'Path normalization, null byte detection, encoding bypass detection'],
        ['Command Injection', 'OS command injection', 'Shell metacharacter detection, command chaining analysis'],
        ['Protocol Anomaly', 'HTTP protocol abuse', 'Header validation, method analysis, content-type verification'],
        ['Bot Detection', 'Automated scanners', 'User-Agent analysis, behavior patterns, known scanner fingerprints'],
      ] },
      { type: 'heading', level: 2, text: 'Scoring System', id: 'scoring-system' },
      { type: 'paragraph', text: 'Each detector returns a score from 0-100 for every request. The scoring engine aggregates these using configurable weights:' },
      { type: 'code', language: 'yaml', filename: 'guardianwaf.yaml', code: `detection:
  weights:
    sqli: 1.0
    xss: 1.0
    path_traversal: 0.8
    command_injection: 1.0
    protocol_anomaly: 0.5
    bot: 0.3

  # Final score = max(weighted_scores)
  # Actions based on score:
  block_score: 80    # Score >= 80: Block request
  log_score: 40      # Score >= 40: Log but allow` },
      { type: 'callout', variant: 'info', text: 'The scoring system uses the maximum weighted score, not an aggregate sum. This means a single high-confidence detection is enough to trigger blocking.' },
    ],
  },
  {
    id: 'deployment-modes',
    title: 'Deployment Modes',
    content: [
      { type: 'paragraph', text: 'GuardianWAF supports three deployment modes to fit any architecture. Each mode uses the same detection engine and scoring system.' },
      { type: 'heading', level: 2, text: 'Standalone Proxy', id: 'standalone-proxy' },
      { type: 'paragraph', text: 'Run GuardianWAF as a reverse proxy in front of your application. This is the simplest deployment mode and requires no code changes.' },
      { type: 'code', language: 'bash', filename: 'Terminal', code: `./guardianwaf serve --listen :8088 --upstream http://localhost:3000` },
      { type: 'list', items: [
        'Zero code changes required',
        'Works with any backend language/framework',
        'Built-in TLS termination and ACME support',
        'Full dashboard and API access',
      ] },
      { type: 'heading', level: 2, text: 'Embedded Library', id: 'embedded-library' },
      { type: 'paragraph', text: 'Import GuardianWAF as a Go library and wrap your HTTP handlers directly:' },
      { type: 'code', language: 'go', filename: 'main.go', code: `package main

import (
    "net/http"
    "github.com/guardianwaf/guardianwaf"
)

func main() {
    waf, err := guardianwaf.New(guardianwaf.Config{
        Mode:       guardianwaf.ModeLibrary,
        BlockScore: 80,
        LogScore:   40,
    })
    if err != nil {
        panic(err)
    }
    defer waf.Close()

    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, protected world!"))
    })

    http.ListenAndServe(":8088", waf.Handler(mux))
}` },
      { type: 'callout', variant: 'tip', text: 'Library mode adds virtually zero overhead since requests are analyzed in-process without network hops.' },
      { type: 'heading', level: 2, text: 'Sidecar Proxy', id: 'sidecar-proxy' },
      { type: 'paragraph', text: 'Deploy GuardianWAF as a sidecar container alongside your application. Ideal for Kubernetes and container orchestration platforms.' },
      { type: 'code', language: 'yaml', filename: 'kubernetes-pod.yaml', code: `apiVersion: v1
kind: Pod
metadata:
  name: my-app
spec:
  containers:
    - name: guardianwaf
      image: ghcr.io/guardianwaf/guardianwaf:latest
      ports:
        - containerPort: 8088
      env:
        - name: GUARDIANWAF_UPSTREAM
          value: "http://localhost:3000"
        - name: GUARDIANWAF_BLOCK_SCORE
          value: "80"
    - name: app
      image: my-app:latest
      ports:
        - containerPort: 3000` },
    ],
  },
  {
    id: 'security-layers',
    title: 'Security Layers',
    content: [
      { type: 'paragraph', text: 'GuardianWAF processes requests through a 10-layer security pipeline. Each layer runs in order and can pass, log, challenge, or block the request.' },
      { type: 'heading', level: 2, text: 'Pipeline Overview', id: 'layer-pipeline' },
      { type: 'code', language: 'text', filename: 'Pipeline Order', code: `Order 100: IP ACL          → Allow/deny by IP or CIDR
Order 125: Threat Intel    → IP/domain reputation checking
Order 150: CORS            → Cross-origin request validation
Order 200: Rate Limit      → Token bucket per IP/path
Order 250: ATO Protection  → Brute force & credential stuffing
Order 275: API Security    → JWT validation & API keys
Order 300: Sanitizer       → Request normalization
Order 400: Detection       → 6 detectors (SQLi, XSS, LFI, CMDi, XXE, SSRF)
Order 500: Bot Detection   → JA3/JA4 TLS fingerprinting, behavioral analysis
Order 600: Response        → Security headers, data masking` },
      { type: 'heading', level: 2, text: 'IP ACL (100)', id: 'ip-acl' },
      { type: 'paragraph', text: 'First line of defense. Allow or deny requests based on IP addresses or CIDR ranges using a radix tree for O(k) lookups.' },
      { type: 'code', language: 'yaml', filename: 'guardianwaf.yaml', code: `ip_acl:
  enabled: true
  allowlist:
    - "10.0.0.0/8"       # Internal network
    - "192.168.1.100"    # Admin IP
  blocklist:
    - "192.0.2.0/24"     # Known bad range
  default_action: "allow"` },
      { type: 'heading', level: 2, text: 'Threat Intelligence (125)', id: 'threat-intel' },
      { type: 'paragraph', text: 'Check IPs and domains against reputation feeds. Supports JSONL, CSV, and JSON formats with automatic refresh.' },
      { type: 'code', language: 'yaml', filename: 'guardianwaf.yaml', code: `threat_intel:
  enabled: true
  ip_reputation:
    enabled: true
    block_malicious: true
    score_threshold: 70
    sources:
      - type: "file"
        path: "/etc/guardian/threat_ips.jsonl"
        refresh_minutes: 60
  domain_reputation:
    enabled: true
    check_redirects: true` },
      { type: 'heading', level: 2, text: 'CORS Security (150)', id: 'cors-layer' },
      { type: 'paragraph', text: 'Validate cross-origin requests against an allowlist. Supports wildcard patterns and strict mode blocking.' },
      { type: 'code', language: 'yaml', filename: 'guardianwaf.yaml', code: `cors:
  enabled: true
  allow_origins:
    - "https://example.com"
    - "https://*.example.com"
  allow_methods:
    - GET
    - POST
    - PUT
    - DELETE
  allow_credentials: true
  max_age_seconds: 86400
  strict_mode: true` },
      { type: 'heading', level: 2, text: 'Rate Limit (200)', id: 'rate-limit' },
      { type: 'paragraph', text: 'Token bucket rate limiting per IP address or path. Protects against DDoS and abuse.' },
      { type: 'code', language: 'yaml', filename: 'guardianwaf.yaml', code: `rate_limit:
  enabled: true
  requests_per_second: 100
  burst: 200
  window: "1m"
  per_path:
    "/api/*":
      requests_per_second: 50
      burst: 100` },
      { type: 'heading', level: 2, text: 'ATO Protection (250)', id: 'ato-protection' },
      { type: 'paragraph', text: 'Account Takeover Protection detects brute force attacks, credential stuffing, password spray, and impossible travel patterns.' },
      { type: 'code', language: 'yaml', filename: 'guardianwaf.yaml', code: `ato_protection:
  enabled: true
  login_paths:
    - "/login"
    - "/api/auth"
  brute_force:
    enabled: true
    window_minutes: 15
    max_attempts_per_ip: 10
    block_duration_minutes: 30
  credential_stuffing:
    enabled: true
    distributed_threshold: 5
    window_minutes: 60
  impossible_travel:
    enabled: true
    max_distance_km: 500` },
      { type: 'heading', level: 2, text: 'API Security (275)', id: 'api-security' },
      { type: 'paragraph', text: 'JWT validation with JWKS support and API key authentication with path-based authorization.' },
      { type: 'code', language: 'yaml', filename: 'guardianwaf.yaml', code: `api_security:
  enabled: true
  jwt:
    enabled: true
    issuer: "https://auth.example.com"
    audience: "api.example.com"
    jwks_url: "https://auth.example.com/.well-known/jwks.json"
  api_keys:
    enabled: true
    header_name: "X-API-Key"
    keys:
      - name: "service-a"
        key_hash: "sha256:..."
        allowed_paths: ["/api/*"]` },
      { type: 'heading', level: 2, text: 'Sanitizer (300)', id: 'sanitizer' },
      { type: 'paragraph', text: 'Normalizes requests before detection. Handles URL encoding, unicode normalization, and removes null bytes.' },
      { type: 'heading', level: 2, text: 'Detection (400)', id: 'detection' },
      { type: 'paragraph', text: 'Core threat detection with 6 specialized detectors. See Detection Engine section for details.' },
      { type: 'heading', level: 2, text: 'Bot Detection (500)', id: 'bot-detection' },
      { type: 'paragraph', text: 'Identifies automated threats using JA3/JA4 TLS fingerprinting, User-Agent analysis, and behavioral patterns. Scores between 40-79 trigger JavaScript proof-of-work challenge.' },
      { type: 'heading', level: 2, text: 'Response (600)', id: 'response-layer' },
      { type: 'paragraph', text: 'Adds security headers to responses and masks sensitive data like credit cards and API keys.' },
      { type: 'callout', variant: 'info', text: 'Layers run in strict order. Early layers (IP ACL, Threat Intel) can block before expensive detection runs.' },
    ],
  },
  {
    id: 'api-reference',
    title: 'API Reference',
    content: [
      { type: 'paragraph', text: 'GuardianWAF provides both a Go API for library mode and an HTTP API for the dashboard and management.' },
      { type: 'heading', level: 2, text: 'Core API', id: 'core-api' },
      { type: 'code', language: 'go', filename: 'api.go', code: `// New creates a new WAF instance with the given configuration.
func New(config Config) (*WAF, error)

// Handler wraps an http.Handler with WAF protection.
func (w *WAF) Handler(next http.Handler) http.Handler

// Analyze inspects a request and returns the analysis result.
func (w *WAF) Analyze(r *http.Request) (*Result, error)

// Close gracefully shuts down the WAF and releases resources.
func (w *WAF) Close() error` },
      { type: 'heading', level: 3, text: 'Config Struct' },
      { type: 'code', language: 'go', filename: 'config.go', code: `type Config struct {
    Mode       Mode          // ModeProxy, ModeLibrary, ModeSidecar
    BlockScore int           // Score threshold for blocking (default: 80)
    LogScore   int           // Score threshold for logging (default: 40)
    DryRun     bool          // Log threats but don't block
    Detectors  []DetectorID  // Enabled detectors (default: all)
    Weights    WeightConfig  // Per-detector score weights
}` },
      { type: 'heading', level: 2, text: 'Middleware', id: 'middleware' },
      { type: 'paragraph', text: 'GuardianWAF provides standard Go middleware compatible with net/http:' },
      { type: 'code', language: 'go', filename: 'middleware.go', code: `// Use as standard middleware
mux := http.NewServeMux()
mux.HandleFunc("/", handler)

protected := waf.Handler(mux)
http.ListenAndServe(":8088", protected)

// Or use the HandlerFunc adapter
http.HandleFunc("/api/", waf.HandlerFunc(apiHandler))` },
      { type: 'heading', level: 2, text: 'Dashboard API', id: 'dashboard-api' },
      { type: 'paragraph', text: 'The dashboard exposes a REST API for monitoring and management:' },
      { type: 'table', headers: ['Endpoint', 'Method', 'Description'], rows: [
        ['GET /api/stats', 'GET', 'Real-time traffic statistics'],
        ['GET /api/threats', 'GET', 'Recent threat log entries'],
        ['GET /api/config', 'GET', 'Current WAF configuration'],
        ['PUT /api/config', 'PUT', 'Update WAF configuration'],
        ['GET /api/health', 'GET', 'Health check endpoint'],
        ['POST /api/rules', 'POST', 'Add custom detection rule'],
        ['DELETE /api/rules/:id', 'DELETE', 'Remove a custom rule'],
      ] },
    ],
  },
  {
    id: 'mcp-integration',
    title: 'MCP Integration',
    content: [
      { type: 'paragraph', text: 'GuardianWAF includes a built-in Model Context Protocol (MCP) server that enables AI-powered security analysis and automated tuning.' },
      { type: 'heading', level: 2, text: 'Overview', id: 'mcp-overview' },
      { type: 'paragraph', text: 'The MCP server exposes GuardianWAF capabilities as tools that AI assistants can use to analyze traffic, investigate threats, and tune detection rules.' },
      { type: 'callout', variant: 'info', text: 'MCP (Model Context Protocol) is an open standard for connecting AI assistants to external tools and data sources.' },
      { type: 'heading', level: 2, text: 'Available Tools', id: 'mcp-tools' },
      { type: 'table', headers: ['Tool', 'Description'], rows: [
        ['analyze_request', 'Analyze an HTTP request and return detailed threat assessment'],
        ['get_traffic_stats', 'Retrieve real-time traffic statistics and threat breakdown'],
        ['get_threat_log', 'Query recent threat log entries with filtering'],
        ['tune_threshold', 'Adjust detection thresholds based on traffic analysis'],
        ['explain_detection', 'Get detailed explanation of why a request was flagged'],
        ['suggest_rules', 'AI-generated rule suggestions based on traffic patterns'],
      ] },
      { type: 'heading', level: 2, text: 'Setup', id: 'mcp-setup' },
      { type: 'paragraph', text: 'Enable the MCP server in your configuration:' },
      { type: 'code', language: 'yaml', filename: 'guardianwaf.yaml', code: `mcp:
  enabled: true
  transport: stdio    # or "sse" for HTTP-based transport
  listen: ":8081"     # Only for SSE transport` },
      { type: 'paragraph', text: 'Configure your AI assistant to connect to GuardianWAF:' },
      { type: 'code', language: 'json', filename: 'claude_desktop_config.json', code: `{
  "mcpServers": {
    "guardianwaf": {
      "command": "./guardianwaf",
      "args": ["mcp", "--config", "guardianwaf.yaml"]
    }
  }
}` },
    ],
  },
  {
    id: 'tuning-guide',
    title: 'Tuning Guide',
    content: [
      { type: 'paragraph', text: 'Every application is different. This guide helps you tune GuardianWAF to minimize false positives while maintaining strong protection.' },
      { type: 'heading', level: 2, text: 'Reducing False Positives', id: 'false-positives' },
      { type: 'paragraph', text: 'Start with dry-run mode to understand your traffic patterns:' },
      { type: 'code', language: 'bash', filename: 'Terminal', code: `./guardianwaf serve --dry-run --dashboard :9090 --upstream http://localhost:3000` },
      { type: 'list', items: [
        'Monitor the dashboard for 24-48 hours to establish a baseline',
        'Review flagged requests to identify false positives',
        'Add path-based exclusions for known safe endpoints (e.g., CMS editors)',
        'Adjust detector weights for your specific application type',
      ] },
      { type: 'heading', level: 2, text: 'Threshold Tuning', id: 'threshold-tuning' },
      { type: 'paragraph', text: 'Adjust score thresholds based on your risk tolerance:' },
      { type: 'table', headers: ['Profile', 'Block Score', 'Log Score', 'Use Case'], rows: [
        ['Strict', '60', '20', 'High-security applications, financial services'],
        ['Balanced (default)', '80', '40', 'General web applications'],
        ['Permissive', '95', '60', 'Applications with complex user input (CMS, forums)'],
      ] },
      { type: 'heading', level: 2, text: 'Custom Rules', id: 'custom-rules' },
      { type: 'paragraph', text: 'Add application-specific rules to refine detection:' },
      { type: 'code', language: 'yaml', filename: 'guardianwaf.yaml', code: `rules:
  # Whitelist specific paths
  - id: allow-editor
    path: "/admin/editor"
    action: allow

  # Custom detection rule
  - id: block-sensitive-paths
    path: "/.env|/.git|/wp-admin"
    action: block
    score: 100

  # Rate limiting
  - id: rate-limit-api
    path: "/api/*"
    rate_limit:
      requests: 100
      window: 60s
      action: block` },
      { type: 'callout', variant: 'warning', text: 'Be cautious when whitelisting paths. Always validate that whitelisted endpoints cannot be exploited through parameter injection.' },
    ],
  },
]
