package apisecurity

import (
	"strings"
	"sync"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"time"
)

// Config holds the configuration for the API Security layer.
type Config struct {
	Enabled    bool          `yaml:"enabled"`
	JWT        JWTConfig     `yaml:"jwt"`
	APIKeys    APIKeysConfig `yaml:"api_keys"`
	SkipPaths  []string      `yaml:"skip_paths"`
	HeaderName string        `yaml:"header_name"` // API key header name
	QueryParam string        `yaml:"query_param"` // API key query parameter
}

// APIKeysConfig configures API key authentication.
type APIKeysConfig struct {
	Enabled    bool           `yaml:"enabled"`
	HeaderName string         `yaml:"header_name"`
	QueryParam string         `yaml:"query_param"`
	Keys       []APIKeyConfig `yaml:"keys"`
}

// Layer implements engine.Layer for API security.
type Layer struct {
	config          Config
	jwtValidator    *JWTValidator
	apiKeyValidator *APIKeyValidator
	skipPathMap     map[string]bool
	mu              sync.RWMutex
}

// NewLayer creates a new API Security layer.
func NewLayer(cfg *Config) (*Layer, error) {
	l := &Layer{
		config:      *cfg,
		skipPathMap: make(map[string]bool),
	}

	// Build skip path map
	for _, path := range cfg.SkipPaths {
		l.skipPathMap[path] = true
	}

	// Initialize JWT validator
	if cfg.JWT.Enabled {
		validator, err := NewJWTValidator(cfg.JWT)
		if err != nil {
			return nil, err
		}
		l.jwtValidator = validator
	}

	// Initialize API key validator
	if cfg.APIKeys.Enabled {
		l.apiKeyValidator, _ = NewAPIKeyValidator(cfg.APIKeys.Keys)
	}

	return l, nil
}

// Name returns the layer name.
func (l *Layer) Name() string { return "api_security" }

// Process validates API authentication.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	start := time.Now()
	// Check if API security is enabled (tenant config takes precedence)
	enabled := l.config.Enabled
	if ctx.TenantWAFConfig != nil && !ctx.TenantWAFConfig.APISecurity.Enabled {
		enabled = false
	}
	if !enabled {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}

	// Check if path should be skipped
	if l.shouldSkipPath(ctx.Path) {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}

	var findings []engine.Finding

	// Try JWT authentication first
	if l.jwtValidator != nil {
		token := l.extractBearerToken(ctx.Headers)
		if token != "" {
			claims, err := l.jwtValidator.Validate(token)
			if err != nil {
				return engine.LayerResult{
					Action: engine.ActionBlock,
					Findings: []engine.Finding{{
						DetectorName: "api_security",
						Category:     "authentication",
						Severity:     engine.SeverityHigh,
						Score:        60,
						Description:  "JWT validation failed: " + err.Error(),
						Location:     "header:Authorization",
					}},
					Score:    60,
		Duration: time.Since(start),
				}
			}

			// JWT is valid - store claims in metadata
			ctx.Metadata["jwt_claims"] = claims
			ctx.Metadata["auth_type"] = "jwt"
			ctx.Metadata["auth_subject"] = claims.Subject

			return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
		}
	}

	// Try API key authentication
	if l.apiKeyValidator != nil {
		apiKey := l.extractAPIKey(ctx.Headers, ctx.QueryParams)
		if apiKey != "" {
			keyConfig, err := l.apiKeyValidator.Validate(apiKey, ctx.Path)
			if err != nil {
				return engine.LayerResult{
					Action: engine.ActionBlock,
					Findings: []engine.Finding{{
						DetectorName: "api_security",
						Category:     "authentication",
						Severity:     engine.SeverityHigh,
						Score:        60,
						Description:  "API key validation failed: " + err.Error(),
						Location:     "api_key",
					}},
					Score:    60,
		Duration: time.Since(start),
				}
			}

			// API key is valid - store info in metadata
			ctx.Metadata["auth_type"] = "api_key"
			ctx.Metadata["api_key_name"] = keyConfig.Name
			ctx.Metadata["api_key_rate_limit"] = keyConfig.RateLimit

			return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
		}
	}

	// No valid authentication found
	// Only block if authentication is required
	if l.jwtValidator != nil || l.apiKeyValidator != nil {
		findings = append(findings, engine.Finding{
			DetectorName: "api_security",
			Category:     "authentication",
			Severity:     engine.SeverityMedium,
			Score:        40,
			Description:  "No valid API authentication provided",
			Location:     "request",
		})

		return engine.LayerResult{
			Action:   engine.ActionBlock,
			Findings: findings,
			Score:    40,
		Duration: time.Since(start),
		}
	}

	return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
}

func (l *Layer) shouldSkipPath(path string) bool {
	// Exact match
	if l.skipPathMap[path] {
		return true
	}

	// Prefix match for paths ending with *
	l.mu.RLock()
	defer l.mu.RUnlock()

	for skipPath := range l.skipPathMap {
		if strings.HasSuffix(skipPath, "*") {
			prefix := strings.TrimSuffix(skipPath, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
	}

	return false
}

func (l *Layer) extractBearerToken(headers map[string][]string) string {
	auth := getHeaderValue(headers, "Authorization")
	if auth == "" {
		return ""
	}

	// Check Bearer prefix
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	// Also support token without Bearer prefix
	return auth
}

func (l *Layer) extractAPIKey(headers, queryParams map[string][]string) string {
	// Try header first
	headerName := l.config.APIKeys.HeaderName
	if headerName == "" {
		headerName = "X-API-Key"
	}
	if key := getHeaderValue(headers, headerName); key != "" {
		return key
	}

	// Try query parameter
	paramName := l.config.APIKeys.QueryParam
	if paramName == "" {
		paramName = "api_key"
	}
	if vals, ok := queryParams[paramName]; ok && len(vals) > 0 {
		return vals[0]
	}

	return ""
}

func getHeaderValue(headers map[string][]string, name string) string {
	nameLower := strings.ToLower(name)
	for k, v := range headers {
		if strings.EqualFold(k, nameLower) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// AddSkipPath adds a path to skip during authentication.
func (l *Layer) AddSkipPath(path string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.skipPathMap[path] = true
}

// RemoveSkipPath removes a skip path.
func (l *Layer) RemoveSkipPath(path string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.skipPathMap, path)
}

// AddAPIKey adds an API key at runtime.
func (l *Layer) AddAPIKey(cfg APIKeyConfig) error {
	if l.apiKeyValidator == nil {
		return nil
	}
	return l.apiKeyValidator.AddKey(cfg)
}

// RemoveAPIKey removes an API key by name.
func (l *Layer) RemoveAPIKey(name string) bool {
	if l.apiKeyValidator == nil {
		return false
	}
	return l.apiKeyValidator.RemoveKey(name)
}

// RefreshJWKS refreshes the JWKS cache.
func (l *Layer) RefreshJWKS() {
	if l.jwtValidator != nil {
		l.jwtValidator.fetchJWKS()
	}
}

// Stats returns layer statistics.
func (l *Layer) Stats() map[string]any {
	stats := map[string]any{
		"enabled":       l.config.Enabled,
		"jwt_enabled":   l.jwtValidator != nil,
		"api_key_count": 0,
		"skip_paths":    len(l.skipPathMap),
	}

	if l.apiKeyValidator != nil {
		stats["api_key_count"] = len(l.apiKeyValidator.ListKeys())
	}

	return stats
}

// Start starts any background processes (JWKS refresh).
func (l *Layer) Start() {
	// JWKS refresh is started in NewJWTValidator
	_ = l
}

// Stop stops any background processes.
func (l *Layer) Stop() {
	// Nothing to stop currently
	_ = l
}
