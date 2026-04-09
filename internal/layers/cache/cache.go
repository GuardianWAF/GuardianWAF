// Package cache provides caching layer with Redis and in-memory backends.
package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Backend represents a cache backend interface.
type Backend interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
	Keys(ctx context.Context, pattern string) ([]string, error)
	Clear(ctx context.Context) error
	Close() error
}

// Config for cache layer.
type Config struct {
	Enabled    bool          `yaml:"enabled"`
	Backend    string        `yaml:"backend"` // "memory", "redis"
	TTL        time.Duration `yaml:"ttl"`
	MaxSize    int           `yaml:"max_size"` // For memory backend (MB)
	RedisAddr  string        `yaml:"redis_addr"`
	RedisPass  string        `yaml:"redis_password"`
	RedisDB    int           `yaml:"redis_db"`
	Prefix     string        `yaml:"prefix"`
}

// DefaultConfig returns default cache configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled: false,
		Backend: "memory",
		TTL:     5 * time.Minute,
		MaxSize: 100, // 100MB
		Prefix:  "gwaf",
	}
}

// Cache provides caching functionality.
type Cache struct {
	config  *Config
	backend Backend
}

// New creates a new cache with the specified backend.
func New(cfg *Config) (*Cache, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if !cfg.Enabled {
		return &Cache{config: cfg}, nil
	}

	var backend Backend
	var err error

	switch cfg.Backend {
	case "memory":
		backend = NewMemoryBackend(cfg.MaxSize)
	case "redis":
		backend, err = NewRedisBackend(cfg.RedisAddr, cfg.RedisPass, cfg.RedisDB)
		if err != nil {
			return nil, fmt.Errorf("failed to create redis backend: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown backend: %s", cfg.Backend)
	}

	return &Cache{
		config:  cfg,
		backend: backend,
	}, nil
}

// IsEnabled returns whether the cache is enabled.
func (c *Cache) IsEnabled() bool {
	return c.config.Enabled
}

// Get retrieves a value from cache.
func (c *Cache) Get(ctx context.Context, key string) ([]byte, error) {
	if !c.config.Enabled {
		return nil, fmt.Errorf("cache is disabled")
	}
	return c.backend.Get(ctx, c.prefixKey(key))
}

// GetString retrieves a string value from cache.
func (c *Cache) GetString(ctx context.Context, key string) (string, error) {
	data, err := c.Get(ctx, key)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GetJSON retrieves and unmarshals a JSON value from cache.
func (c *Cache) GetJSON(ctx context.Context, key string, v any) error {
	data, err := c.Get(ctx, key)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// Set stores a value in cache.
func (c *Cache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if !c.config.Enabled {
		return nil
	}
	if ttl == 0 {
		ttl = c.config.TTL
	}
	return c.backend.Set(ctx, c.prefixKey(key), value, ttl)
}

// SetString stores a string value in cache.
func (c *Cache) SetString(ctx context.Context, key string, value string, ttl time.Duration) error {
	return c.Set(ctx, key, []byte(value), ttl)
}

// SetJSON marshals and stores a value in cache.
func (c *Cache) SetJSON(ctx context.Context, key string, v any, ttl time.Duration) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.Set(ctx, key, data, ttl)
}

// Delete removes a value from cache.
func (c *Cache) Delete(ctx context.Context, key string) error {
	if !c.config.Enabled {
		return nil
	}
	return c.backend.Delete(ctx, c.prefixKey(key))
}

// Exists checks if a key exists in cache.
func (c *Cache) Exists(ctx context.Context, key string) (bool, error) {
	if !c.config.Enabled {
		return false, nil
	}
	return c.backend.Exists(ctx, c.prefixKey(key))
}

// Keys returns keys matching a pattern.
func (c *Cache) Keys(ctx context.Context, pattern string) ([]string, error) {
	if !c.config.Enabled {
		return nil, nil
	}
	keys, err := c.backend.Keys(ctx, c.prefixKey(pattern))
	if err != nil {
		return nil, err
	}

	// Remove prefix from keys
	for i, key := range keys {
		keys[i] = c.unprefixKey(key)
	}
	return keys, nil
}

// Clear removes all values from cache.
func (c *Cache) Clear(ctx context.Context) error {
	if !c.config.Enabled {
		return nil
	}
	return c.backend.Clear(ctx)
}

// Close closes the cache backend.
func (c *Cache) Close() error {
	if c.backend != nil {
		return c.backend.Close()
	}
	return nil
}

// prefixKey adds prefix to key.
func (c *Cache) prefixKey(key string) string {
	if c.config.Prefix == "" {
		return key
	}
	return fmt.Sprintf("%s:%s", c.config.Prefix, key)
}

// unprefixKey removes prefix from key.
func (c *Cache) unprefixKey(key string) string {
	if c.config.Prefix == "" {
		return key
	}
	prefix := c.config.Prefix + ":"
	if len(key) > len(prefix) && key[:len(prefix)] == prefix {
		return key[len(prefix):]
	}
	return key
}
