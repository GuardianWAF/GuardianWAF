// Package cors provides Cross-Origin Resource Sharing (CORS) security validation.
// It validates Origin headers against allowlists and enforces CORS policies.
package cors

import (
	"regexp"
	"strings"
	"sync"

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

// Process validates CORS requests and sets response headers.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	// Check if CORS is enabled (tenant config takes precedence)
	enabled := l.config.Enabled
	if ctx.TenantWAFConfig != nil && !ctx.TenantWAFConfig.CORS.Enabled {
		enabled = false
	}
	if !enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Get Origin header
	origin := getHeader(ctx.Headers, "Origin")
	if origin == "" {
		// Not a CORS request
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Reject "null" origin when credentials are enabled — prevents sandbox iframe abuse
	// (sandboxed iframes and data: URIs send Origin: null, which should not be reflected
	// with Access-Control-Allow-Credentials: true)
	if origin == "null" && l.config.AllowCredentials {
		return engine.LayerResult{Action: engine.ActionPass} // no CORS headers
	}

	// Validate origin against allowlist
	if !l.isOriginAllowed(origin) {
		if l.config.StrictMode {
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
				Score: 30,
			}
		}
		// Non-strict: pass but don't add CORS headers (browser will block)
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Preflight request (OPTIONS with Access-Control-Request-Method)
	if ctx.Method == "OPTIONS" && hasHeader(ctx.Headers, "Access-Control-Request-Method") {
		return l.handlePreflight(ctx, origin)
	}

	// Regular CORS request - set CORS headers via metadata
	l.setCORSHeaders(ctx, origin)
	return engine.LayerResult{Action: engine.ActionPass}
}

// isOriginAllowed checks if the origin matches any allowlist entry.
func (l *Layer) isOriginAllowed(origin string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()

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
func (l *Layer) handlePreflight(ctx *engine.RequestContext, origin string) engine.LayerResult {
	// Validate requested method
	reqMethod := getHeader(ctx.Headers, "Access-Control-Request-Method")
	if reqMethod != "" && len(l.config.AllowMethods) > 0 {
		if !contains(l.config.AllowMethods, reqMethod) {
			if l.config.StrictMode {
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
	if reqHeaders != "" && len(l.config.AllowHeaders) > 0 {
		headers := parseHeaderList(reqHeaders)
		for _, h := range headers {
			if !containsFold(l.config.AllowHeaders, h) {
				if l.config.StrictMode {
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
	l.setPreflightHeaders(ctx, origin)
	return engine.LayerResult{Action: engine.ActionPass}
}

// setCORSHeaders sets CORS headers for regular requests via response hook.
func (l *Layer) setCORSHeaders(ctx *engine.RequestContext, origin string) {
	allowCreds := "false"
	if l.config.AllowCredentials {
		allowCreds = "true"
	}

	// Store CORS headers in metadata for response layer
	ctx.Metadata["cors_headers"] = map[string]string{
		"Access-Control-Allow-Origin":      origin,
		"Access-Control-Allow-Credentials": allowCreds,
	}

	// Set expose headers
	if len(l.config.ExposeHeaders) > 0 {
		ctx.Metadata["cors_expose_headers"] = strings.Join(l.config.ExposeHeaders, ", ")
	}

	// Register response hook to add headers
	ctx.Metadata["cors_response_hook"] = true
}

// setPreflightHeaders sets CORS headers for preflight responses.
func (l *Layer) setPreflightHeaders(ctx *engine.RequestContext, origin string) {
	allowCreds := "false"
	if l.config.AllowCredentials {
		allowCreds = "true"
	}

	headers := map[string]string{
		"Access-Control-Allow-Origin":      origin,
		"Access-Control-Allow-Credentials": allowCreds,
	}

	if len(l.config.AllowMethods) > 0 {
		headers["Access-Control-Allow-Methods"] = strings.Join(l.config.AllowMethods, ", ")
	}

	if len(l.config.AllowHeaders) > 0 {
		headers["Access-Control-Allow-Headers"] = strings.Join(l.config.AllowHeaders, ", ")
	}

	if l.config.MaxAgeSeconds > 0 {
		headers["Access-Control-Max-Age"] = intToStr(l.config.MaxAgeSeconds)
	}

	ctx.Metadata["cors_preflight_headers"] = headers
	ctx.Metadata["cors_response_hook"] = true
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
	l.mu.Lock()
	defer l.mu.Unlock()

	l.config = cfg
	l.originRegex = make([]*regexp.Regexp, 0)
	l.exactOrigins = make(map[string]bool)

	for _, origin := range cfg.AllowOrigins {
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
