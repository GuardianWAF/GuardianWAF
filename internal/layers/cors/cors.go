// Package cors provides Cross-Origin Resource Sharing (CORS) security validation.
// It validates Origin headers against allowlists and enforces CORS policies.
package cors

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Config holds the configuration for the CORS layer.
type Config struct {
	Enabled               bool     `yaml:"enabled"`
	AllowOrigins          []string `yaml:"allow_origins"`
	AllowMethods          []string `yaml:"allow_methods"`
	AllowHeaders          []string `yaml:"allow_headers"`
	ExposeHeaders         []string `yaml:"expose_headers"`
	AllowCredentials      bool     `yaml:"allow_credentials"`
	MaxAgeSeconds         int      `yaml:"max_age_seconds"`
	StrictMode            bool     `yaml:"strict_mode"`
	PreflightCacheSeconds int      `yaml:"preflight_cache_seconds"`
}

// Layer implements engine.Layer for CORS validation.
type Layer struct {
	config       Config
	originRegex  []*regexp.Regexp // Compiled wildcard patterns
	exactOrigins map[string]bool  // Exact origin matches
	mu           sync.RWMutex
}

// NewLayer creates a new CORS layer from the given config.
func NewLayer(cfg *Config) (*Layer, error) {
	l := &Layer{
		config:       *cfg,
		originRegex:  make([]*regexp.Regexp, 0),
		exactOrigins: make(map[string]bool),
	}

	// Compile origin patterns
	for _, origin := range cfg.AllowOrigins {
		origin = normalizeOrigin(origin)
		if origin == "" {
			continue
		}
		// An all-origins wildcard plus credentials grants credentialed access
		// to every site: ACAO is reflected (never the literal "*"), so the
		// browser honors the combination. Fail closed at construction. The
		// check is structural (isAllOriginsWildcard) so every scheme spelling
		// of the all-hosts wildcard is rejected, not just "https://*" — a
		// spelling like "http://*" or "*://*" normalizes differently but
		// compiles to the same credentialed every-host regex.
		if cfg.AllowCredentials && isAllOriginsWildcard(origin) {
			return nil, errors.New("cors: AllowCredentials with the all-origins wildcard grants credentialed access to every site; use an explicit origin allowlist")
		}
		if strings.Contains(origin, "*") {
			// Wildcard pattern: "https://*.example.com"
			regex := compileWildcard(origin)
			if regex != nil {
				l.originRegex = append(l.originRegex, regex)
			}
		} else {
			// Exact match
			l.exactOrigins[origin] = true
		}
	}

	return l, nil
}

// normalizeOrigin canonicalizes an allowlist origin or wildcard pattern to
// match how browsers emit the Origin header: scheme and host are
// case-insensitive (browsers lowercase them) and the scheme's default port
// never appears on the wire (https:443 / http:80). A wildcard pattern
// without a scheme (e.g. "*.example.com") is treated as https-only,
// consistent with the "*://"-pattern handling in compileWildcard — without
// this, the pattern would compile to "^://..." and match nothing.
func normalizeOrigin(origin string) string {
	o := strings.ToLower(strings.TrimSpace(origin))

	if !strings.Contains(o, "://") && strings.Contains(o, "*") {
		o = "https://" + o
	}

	scheme, rest := "", o
	if idx := strings.Index(o, "://"); idx >= 0 {
		scheme, rest = o[:idx], o[idx+3:]
	}

	// Strip the scheme's default port from the host part (up to /, ?, or #).
	if scheme == "https" || scheme == "http" {
		def := ":443"
		if scheme == "http" {
			def = ":80"
		}
		hostEnd := strings.IndexAny(rest, "/?#")
		var host, tail string
		if hostEnd >= 0 {
			host, tail = rest[:hostEnd], rest[hostEnd:]
		} else {
			host = rest
		}
		if strings.HasSuffix(host, def) && len(host) > len(def) {
			rest = host[:len(host)-len(def)] + tail
		}
	}

	if scheme != "" {
		return scheme + "://" + rest
	}
	return rest
}

// isAllOriginsWildcard reports whether the normalized pattern is an
// all-origins wildcard — the wildcard IS the entire host component — under
// any scheme spelling: "https://*", "http://*", "*://*", or repeated-star
// forms like "https://**". compileWildcard turns each of these into a bare
// `^<scheme>://.+$` regex, so with AllowCredentials the layer would reflect
// credentialed CORS for every site of that scheme; the scheme spelling must
// not matter. Scoped patterns ("https://*.example.com") keep a non-star tail
// and stay allowed.
func isAllOriginsWildcard(normalized string) bool {
	idx := strings.Index(normalized, "://")
	if idx < 0 {
		return false
	}
	scheme, host := normalized[:idx], normalized[idx+3:]
	if end := strings.IndexAny(host, "/?#"); end >= 0 {
		host = host[:end]
	}
	if host == "" || strings.Trim(host, "*") != "" {
		return false
	}
	return scheme == "http" || scheme == "https" || scheme == "*"
}

// compileWildcard converts a wildcard pattern to a regex.
// Pattern: "https://*.example.com" → "^https://[^.]+\.example\.com$"
func compileWildcard(pattern string) *regexp.Regexp {
	// Handle multiple wildcards in subdomains
	// *.example.com → .+\.example\.com (matches any subdomain level)

	// Split into scheme and host
	var scheme, host string
	if idx := strings.Index(pattern, "://"); idx >= 0 {
		scheme = pattern[:idx]
		host = pattern[idx+3:]
	} else {
		host = pattern
	}

	// Handle wildcard in scheme (*:// → https:// only — HTTP is insecure)
	var schemeRegex string
	if scheme == "*" {
		schemeRegex = "https"
	} else {
		schemeRegex = regexp.QuoteMeta(scheme)
	}

	// Escape special regex chars in host part, except *
	escaped := regexp.QuoteMeta(host)
	// Replace escaped \* with regex pattern for subdomain (any level)
	// Use .+ to match any characters including dots for nested subdomains
	regexHost := strings.ReplaceAll(escaped, `\*`, `.+`)

	// Build full regex
	fullPattern := "^" + schemeRegex + "://" + regexHost + "$"
	return regexp.MustCompile(fullPattern)
}

// Name returns the layer name.
func (l *Layer) Name() string { return "cors" }

// Order returns the execution order.
func (l *Layer) Order() int { return engine.OrderCORS }

// snapshotConfig returns a copy of the current config under RLock.
func (l *Layer) snapshotConfig() Config {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.config
}

// Process validates CORS requests and sets response headers.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	start := time.Now()

	// Check if CORS is enabled (tenant config takes precedence)
	cfg := l.snapshotConfig()
	if ctx.TenantWAFConfig != nil && !ctx.TenantWAFConfig.CORS.Enabled {
		cfg.Enabled = false
	}
	if !cfg.Enabled {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}

	// Get Origin header
	origin := getHeader(ctx.Headers, "Origin")
	if origin == "" {
		// Not a CORS request
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}

	// Reject "null" origin when credentials are enabled — prevents sandbox iframe abuse
	// (sandboxed iframes and data: URIs send Origin: null, which should not be reflected
	// with Access-Control-Allow-Credentials: true)
	if origin == "null" && cfg.AllowCredentials {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)} // no CORS headers
	}

	// Validate origin against allowlist
	if !l.isOriginAllowed(origin) {
		if cfg.StrictMode {
			return engine.LayerResult{
				Action: engine.ActionBlock,
				Findings: []engine.Finding{{
					DetectorName: "cors",
					Category:     "policy",
					Severity:     engine.SeverityMedium,
					Score:        30,
					Description:  "Origin not in CORS allowlist",
					MatchedValue: origin,
					Location:     "header:Origin",
				}},
				Score:    30,
				Duration: time.Since(start),
			}
		}
		// Non-strict: pass but don't add CORS headers (browser will block)
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}

	// Preflight request (OPTIONS with Access-Control-Request-Method)
	if ctx.Method == "OPTIONS" && hasHeader(ctx.Headers, "Access-Control-Request-Method") {
		return l.handlePreflight(ctx, origin, &cfg, start)
	}

	// Regular CORS request - set CORS headers via metadata
	l.setCORSHeaders(ctx, origin, &cfg)
	return engine.LayerResult{Action: engine.ActionPass}
}

// isOriginAllowed checks if the origin matches any allowlist entry.
func (l *Layer) isOriginAllowed(origin string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// Normalize the wire origin the same way the allowlist was normalized at
	// load (case, default ports, scheme-less wildcards) — otherwise exact
	// entries still miss on case differences and explicit default ports.
	origin = normalizeOrigin(origin)

	// Check exact matches
	if l.exactOrigins[origin] {
		return true
	}

	// Check wildcard patterns
	for _, re := range l.originRegex {
		if re.MatchString(origin) {
			return true
		}
	}

	return false
}

// handlePreflight handles CORS preflight OPTIONS requests.
func (l *Layer) handlePreflight(ctx *engine.RequestContext, origin string, cfg *Config, start time.Time) engine.LayerResult {
	// Validate requested method
	reqMethod := getHeader(ctx.Headers, "Access-Control-Request-Method")
	if reqMethod != "" && len(cfg.AllowMethods) > 0 {
		if !contains(cfg.AllowMethods, reqMethod) {
			if cfg.StrictMode {
				return engine.LayerResult{
					Action: engine.ActionBlock,
					Findings: []engine.Finding{{
						DetectorName: "cors",
						Category:     "policy",
						Severity:     engine.SeverityMedium,
						Score:        25,
						Description:  "CORS method not allowed",
						MatchedValue: reqMethod,
						Location:     "header:Access-Control-Request-Method",
					}},
					Score: 25,
				}
			}
		}
	}

	// Validate requested headers
	reqHeaders := getHeader(ctx.Headers, "Access-Control-Request-Headers")
	if reqHeaders != "" && len(cfg.AllowHeaders) > 0 {
		headers := parseHeaderList(reqHeaders)
		for _, h := range headers {
			if !containsFold(cfg.AllowHeaders, h) {
				if cfg.StrictMode {
					return engine.LayerResult{
						Action: engine.ActionBlock,
						Findings: []engine.Finding{{
							DetectorName: "cors",
							Category:     "policy",
							Severity:     engine.SeverityLow,
							Score:        15,
							Description:  "CORS header not allowed",
							MatchedValue: h,
							Location:     "header:Access-Control-Request-Headers",
						}},
						Score: 15,
					}
				}
			}
		}
	}

	// Set preflight response headers via metadata
	l.setPreflightHeaders(ctx, origin, cfg)
	return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
}

// setCORSHeaders sets CORS headers for regular requests via response hook.
func (l *Layer) setCORSHeaders(ctx *engine.RequestContext, origin string, cfg *Config) {
	allowCreds := "false"
	if cfg.AllowCredentials {
		allowCreds = "true"
	}

	// CORS headers stored on RequestContext for applyResponseHook to apply.
	ctx.CORSHeaders = map[string]string{
		"Access-Control-Allow-Origin":      origin,
		"Access-Control-Allow-Credentials": allowCreds,
	}

	// Set expose headers
	if len(cfg.ExposeHeaders) > 0 {
		ctx.CORSExposeHeaders = strings.Join(cfg.ExposeHeaders, ", ")
	}
}

// setPreflightHeaders sets CORS headers for preflight responses.
func (l *Layer) setPreflightHeaders(ctx *engine.RequestContext, origin string, cfg *Config) {
	allowCreds := "false"
	if cfg.AllowCredentials {
		allowCreds = "true"
	}

	headers := map[string]string{
		"Access-Control-Allow-Origin":      origin,
		"Access-Control-Allow-Credentials": allowCreds,
	}

	if len(cfg.AllowMethods) > 0 {
		headers["Access-Control-Allow-Methods"] = strings.Join(cfg.AllowMethods, ", ")
	}

	if len(cfg.AllowHeaders) > 0 {
		headers["Access-Control-Allow-Headers"] = strings.Join(cfg.AllowHeaders, ", ")
	}

	if cfg.MaxAgeSeconds > 0 {
		headers["Access-Control-Max-Age"] = intToStr(cfg.MaxAgeSeconds)
	}

	ctx.CORSPreflightHeaders = headers
}

// Helper functions

func getHeader(headers map[string][]string, name string) string {
	key := strings.ToLower(name)
	for k, v := range headers {
		if strings.EqualFold(k, key) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func hasHeader(headers map[string][]string, name string) bool {
	return getHeader(headers, name) != ""
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsFold(slice []string, item string) bool {
	itemLower := strings.ToLower(item)
	for _, s := range slice {
		if strings.EqualFold(s, itemLower) {
			return true
		}
	}
	return false
}

func parseHeaderList(header string) []string {
	parts := strings.Split(header, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func intToStr(n int) string {
	// Simple int to string without strconv
	if n == 0 {
		return "0"
	}
	var neg bool
	if n < 0 {
		neg = true
		n = -n
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}

// UpdateConfig updates the layer configuration at runtime.
func (l *Layer) UpdateConfig(cfg Config) error {
	// Validate before mutating state: a rejected config must not half-apply.
	// Structural check (isAllOriginsWildcard) so every scheme spelling of the
	// all-hosts wildcard is rejected, matching NewLayer.
	for _, origin := range cfg.AllowOrigins {
		if cfg.AllowCredentials && isAllOriginsWildcard(normalizeOrigin(origin)) {
			return errors.New("cors: AllowCredentials with the all-origins wildcard grants credentialed access to every site; use an explicit origin allowlist")
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.config = cfg
	l.originRegex = make([]*regexp.Regexp, 0)
	l.exactOrigins = make(map[string]bool)

	for _, origin := range cfg.AllowOrigins {
		origin = normalizeOrigin(origin)
		if origin == "" {
			continue
		}
		if strings.Contains(origin, "*") {
			regex := compileWildcard(origin)
			if regex != nil {
				l.originRegex = append(l.originRegex, regex)
			}
		} else {
			l.exactOrigins[origin] = true
		}
	}

	return nil
}
