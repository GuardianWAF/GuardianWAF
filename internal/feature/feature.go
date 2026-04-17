// Package feature provides a lightweight, zero-dependency feature flag system.
// Flags can be set via YAML config, environment variables (GWAF_FEATURE_<NAME>=true),
// or programmatically. Per-tenant overrides are supported.
package feature

import (
	"os"
	"strings"
	"sync"
)

// Registry holds feature flag state with thread-safe access.
type Registry struct {
	mu     sync.RWMutex
	flags  map[string]bool
	tenant map[string]map[string]bool // tenantID -> flag -> enabled
}

// global is the default registry.
var global = &Registry{
	flags:  make(map[string]bool),
	tenant: make(map[string]map[string]bool),
}

// Set sets a feature flag globally.
func Set(name string, enabled bool) {
	global.mu.Lock()
	global.flags[strings.ToLower(name)] = enabled
	global.mu.Unlock()
}

// SetTenant sets a feature flag for a specific tenant.
func SetTenant(tenantID, name string, enabled bool) {
	global.mu.Lock()
	defer global.mu.Unlock()
	name = strings.ToLower(name)
	if global.tenant[tenantID] == nil {
		global.tenant[tenantID] = make(map[string]bool)
	}
	global.tenant[tenantID][name] = enabled
}

// IsEnabled checks if a feature flag is enabled.
// Tenant-specific flags take precedence over global flags.
// Unrecognized flags default to false.
func IsEnabled(name string) bool {
	return IsEnabledFor("", name)
}

// IsEnabledFor checks if a feature flag is enabled for a given tenant.
func IsEnabledFor(tenantID, name string) bool {
	global.mu.RLock()
	defer global.mu.RUnlock()
	name = strings.ToLower(name)
	if tenantID != "" {
		if t, ok := global.tenant[tenantID]; ok {
			if v, ok := t[name]; ok {
				return v
			}
		}
	}
	return global.flags[name]
}

// LoadFromMap loads flags from a string map (e.g., from YAML config).
func LoadFromMap(flags map[string]bool) {
	global.mu.Lock()
	defer global.mu.Unlock()
	for k, v := range flags {
		global.flags[strings.ToLower(k)] = v
	}
}

// LoadFromEnv loads flags from environment variables with the GWAF_FEATURE_ prefix.
// Example: GWAF_FEATURE_NEW_DETECTOR=true enables the "new_detector" flag.
func LoadFromEnv() {
	prefix := "GWAF_FEATURE_"
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, prefix) {
			continue
		}
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.ToLower(strings.TrimPrefix(parts[0], prefix))
		val := strings.ToLower(parts[1])
		global.flags[name] = val == "true" || val == "1" || val == "yes"
	}
}

// All returns a snapshot of all global flags.
func All() map[string]bool {
	global.mu.RLock()
	defer global.mu.RUnlock()
	out := make(map[string]bool, len(global.flags))
	for k, v := range global.flags {
		out[k] = v
	}
	return out
}

// Reset clears all flags (for testing).
func Reset() {
	global.mu.Lock()
	global.flags = make(map[string]bool)
	global.tenant = make(map[string]map[string]bool)
	global.mu.Unlock()
}
