package apisecurity

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// APIKeyConfig represents a single API key configuration.
type APIKeyConfig struct {
	Name         string   `yaml:"name"`
	KeyHash      string   `yaml:"key_hash"`      // sha256:hex, or a bare value that is hashed on load (bcrypt is not implemented)
	KeyPrefix    string   `yaml:"key_prefix"`    // Optional prefix for identification
	RateLimit    int      `yaml:"rate_limit"`    // Requests per minute
	AllowedPaths []string `yaml:"allowed_paths"` // Glob patterns
	Enabled      bool     `yaml:"enabled"`
}

// APIKeyValidator validates API keys.
type APIKeyValidator struct {
	keys     map[string]*APIKeyConfig // prefix -> config
	hashes   map[string]*APIKeyConfig // hash -> config
	mu       sync.RWMutex
	trackers map[string]*keyTracker // key_id -> tracker
}

type keyTracker struct {
	requests []time.Time
	mu       sync.Mutex
}

// normalizeKeyHash normalizes cfg.KeyHash in place. Bare values are treated
// as raw keys and hashed (the same contract as AddKey), "sha256:"-prefixed
// values are kept, and any other explicit scheme (e.g. "bcrypt:") is
// rejected: it was never implemented, and silently accepting it produced key
// configurations that could never authenticate.
func normalizeKeyHash(cfg *APIKeyConfig) error {
	switch {
	case strings.HasPrefix(cfg.KeyHash, "sha256:"):
		return nil
	case strings.HasPrefix(cfg.KeyHash, "bcrypt:"):
		return fmt.Errorf("api key %q: bcrypt key_hash is not supported (only sha256 is implemented)", cfg.Name)
	case cfg.KeyHash == "":
		return fmt.Errorf("api key %q: empty key_hash", cfg.Name)
	default:
		sum := sha256.Sum256([]byte(cfg.KeyHash))
		cfg.KeyHash = "sha256:" + hex.EncodeToString(sum[:])
		return nil
	}
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

		if err := normalizeKeyHash(cfg); err != nil {
			return nil, err
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
		return nil, ErrInvalidAPIKey
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

	// Check if key is enabled — parity with Validate: a disabled key must not
	// authenticate through the constant-time path either. AddKey registers
	// Enabled:false configs verbatim (only the constructor skips them), so
	// this is reachable for runtime-added keys.
	if !matched.Enabled {
		return nil, ErrAPIKeyDisabled
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

	if err := normalizeKeyHash(&cfg); err != nil {
		return err
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
