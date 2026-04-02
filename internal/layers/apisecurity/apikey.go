package apisecurity

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// APIKeyConfig represents a single API key configuration.
type APIKeyConfig struct {
	Name         string   `yaml:"name"`
	KeyHash      string   `yaml:"key_hash"`      // sha256:hex or bcrypt:hash
	KeyPrefix    string   `yaml:"key_prefix"`    // Optional prefix for identification
	RateLimit    int      `yaml:"rate_limit"`    // Requests per minute
	AllowedPaths []string `yaml:"allowed_paths"` // Glob patterns
	Enabled      bool     `yaml:"enabled"`
}

// APIKeyValidator validates API keys.
type APIKeyValidator struct {
	keys      map[string]*APIKeyConfig // prefix -> config
	hashes    map[string]*APIKeyConfig // hash -> config
	mu        sync.RWMutex
	trackers  map[string]*keyTracker // key_id -> tracker
}

type keyTracker struct {
	requests []time.Time
	mu       sync.Mutex
}

// NewAPIKeyValidator creates a new API key validator.
func NewAPIKeyValidator(configs []APIKeyConfig) (*APIKeyValidator, error) {
	v := &APIKeyValidator{
		keys:     make(map[string]*APIKeyConfig),
		hashes:   make(map[string]*APIKeyConfig),
		trackers: make(map[string]*keyTracker),
	}

	for i := range configs {
		cfg := &configs[i]
		if !cfg.Enabled {
			continue
		}

		// Store by hash
		v.hashes[cfg.KeyHash] = cfg

		// Store by prefix if available
		if cfg.KeyPrefix != "" {
			v.keys[cfg.KeyPrefix] = cfg
		}

		// Initialize tracker
		v.trackers[cfg.Name] = &keyTracker{}
	}

	return v, nil
}

// Validate checks if an API key is valid and authorized for the given path.
func (v *APIKeyValidator) Validate(key, path string) (*APIKeyConfig, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	// Compute hash of provided key
	hash := sha256.Sum256([]byte(key))
	hashStr := "sha256:" + hex.EncodeToString(hash[:])

	// Look up by hash
	cfg, ok := v.hashes[hashStr]
	if !ok {
		// Try prefix lookup first
		for prefix, c := range v.keys {
			if strings.HasPrefix(key, prefix) {
				// Verify full hash
				if v.hashes["sha256:"+hashStr[7:]] == c {
					cfg = c
					ok = true
					break
				}
			}
		}
		if !ok {
			return nil, ErrInvalidAPIKey
		}
	}

	// Check if key is enabled
	if !cfg.Enabled {
		return nil, ErrAPIKeyDisabled
	}

	// Check path permission
	if len(cfg.AllowedPaths) > 0 {
		if !matchAnyPath(cfg.AllowedPaths, path) {
			return nil, ErrUnauthorizedPath
		}
	}

	// Check rate limit
	if cfg.RateLimit > 0 {
		tracker := v.trackers[cfg.Name]
		if tracker != nil && !v.checkRateLimit(tracker, cfg.RateLimit) {
			return nil, ErrRateLimitExceeded
		}
	}

	return cfg, nil
}

// ValidateConstantTime validates an API key in constant time.
func (v *APIKeyValidator) ValidateConstantTime(key, path string) (*APIKeyConfig, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	// Compute hash
	hash := sha256.Sum256([]byte(key))
	hashStr := "sha256:" + hex.EncodeToString(hash[:])

	// Check all keys in constant time
	var matched *APIKeyConfig
	for h, cfg := range v.hashes {
		// Constant-time comparison
		if subtle.ConstantTimeCompare([]byte(h), []byte(hashStr)) == 1 {
			matched = cfg
		}
	}

	if matched == nil {
		return nil, ErrInvalidAPIKey
	}

	// Check path (not constant-time, but after authentication)
	if len(matched.AllowedPaths) > 0 {
		if !matchAnyPath(matched.AllowedPaths, path) {
			return nil, ErrUnauthorizedPath
		}
	}

	return matched, nil
}

func (v *APIKeyValidator) checkRateLimit(tracker *keyTracker, limit int) bool {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-time.Minute)

	// Filter to requests in current window
	var valid []time.Time
	for _, t := range tracker.requests {
		if t.After(windowStart) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= limit {
		tracker.requests = valid
		return false
	}

	valid = append(valid, now)
	tracker.requests = valid
	return true
}

// AddKey adds a new API key at runtime.
func (v *APIKeyValidator) AddKey(cfg APIKeyConfig) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Hash the key if not already hashed
	if !strings.HasPrefix(cfg.KeyHash, "sha256:") && !strings.HasPrefix(cfg.KeyHash, "bcrypt:") {
		hash := sha256.Sum256([]byte(cfg.KeyHash))
		cfg.KeyHash = "sha256:" + hex.EncodeToString(hash[:])
	}

	v.hashes[cfg.KeyHash] = &cfg
	if cfg.KeyPrefix != "" {
		v.keys[cfg.KeyPrefix] = &cfg
	}
	v.trackers[cfg.Name] = &keyTracker{}

	return nil
}

// RemoveKey removes an API key by name.
func (v *APIKeyValidator) RemoveKey(name string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Find key by name
	var hashToRemove string
	for h, cfg := range v.hashes {
		if cfg.Name == name {
			hashToRemove = h
			delete(v.keys, cfg.KeyPrefix)
			break
		}
	}

	if hashToRemove == "" {
		return false
	}

	delete(v.hashes, hashToRemove)
	delete(v.trackers, name)
	return true
}

// ListKeys returns all API key names.
func (v *APIKeyValidator) ListKeys() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	names := make([]string, 0, len(v.hashes))
	for _, cfg := range v.hashes {
		names = append(names, cfg.Name)
	}
	return names
}

// matchAnyPath checks if path matches any of the patterns.
func matchAnyPath(patterns []string, path string) bool {
	for _, pattern := range patterns {
		if matchPath(pattern, path) {
			return true
		}
	}
	return false
}

// matchPath matches a path against a glob-like pattern.
func matchPath(pattern, path string) bool {
	// Exact match
	if pattern == path {
		return true
	}

	// Wildcard patterns
	if pattern == "*" || pattern == "/*" {
		return true
	}

	// Prefix match with trailing *
	if strings.HasSuffix(pattern, "*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(path, prefix)
	}

	// Single segment wildcard
	if strings.Contains(pattern, "/*/") {
		parts := strings.Split(pattern, "/*/")
		if len(parts) == 2 {
			return strings.HasPrefix(path, parts[0]+"/") && strings.HasSuffix(path, parts[1])
		}
	}

	return false
}

// Errors
var (
	ErrInvalidAPIKey     = &APIKeyError{Code: "invalid_key", Message: "invalid API key"}
	ErrAPIKeyDisabled    = &APIKeyError{Code: "key_disabled", Message: "API key is disabled"}
	ErrUnauthorizedPath  = &APIKeyError{Code: "unauthorized_path", Message: "path not allowed for this key"}
	ErrRateLimitExceeded = &APIKeyError{Code: "rate_limit", Message: "rate limit exceeded"}
)

// APIKeyError represents an API key validation error.
type APIKeyError struct {
	Code    string
	Message string
}

func (e *APIKeyError) Error() string {
	return e.Message
}
