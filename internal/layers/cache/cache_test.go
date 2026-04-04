package cache

import (
	"context"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("expected cache to be disabled by default")
	}

	if cfg.Backend != "memory" {
		t.Errorf("backend = %s, want memory", cfg.Backend)
	}

	if cfg.TTL != 5*time.Minute {
		t.Errorf("ttl = %v, want 5m", cfg.TTL)
	}

	if cfg.MaxSize != 100 {
		t.Errorf("max_size = %d, want 100", cfg.MaxSize)
	}

	if cfg.Prefix != "gwaf" {
		t.Errorf("prefix = %s, want gwaf", cfg.Prefix)
	}
}

func TestNew_Disabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	cache, err := New(cfg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cache == nil {
		t.Fatal("expected cache, got nil")
	}

	if cache.IsEnabled() {
		t.Error("expected cache to be disabled")
	}
}

func TestNew_MemoryBackend(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Backend: "memory",
		MaxSize: 10,
	}

	cache, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	defer cache.Close()

	if !cache.IsEnabled() {
		t.Error("expected cache to be enabled")
	}

	if cache.backend == nil {
		t.Error("expected backend to be set")
	}
}

func TestNew_UnknownBackend(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Backend: "unknown",
	}

	_, err := New(cfg)
	if err == nil {
		t.Error("expected error for unknown backend")
	}
}

func TestCache_SetAndGet(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Backend: "memory",
		MaxSize: 10,
	}

	cache, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	defer cache.Close()

	ctx := context.Background()

	// Set value
	value := []byte("test-value")
	err = cache.Set(ctx, "test-key", value, 5*time.Minute)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Get value
	got, err := cache.Get(ctx, "test-key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(got) != string(value) {
		t.Errorf("Get = %s, want %s", string(got), string(value))
	}
}

func TestCache_Get_NotFound(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Backend: "memory",
		MaxSize: 10,
	}

	cache, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	defer cache.Close()

	ctx := context.Background()

	_, err = cache.Get(ctx, "nonexistent-key")
	if err == nil {
		t.Error("expected error for nonexistent key")
	}
}

func TestCache_Get_Disabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	cache, _ := New(cfg)

	ctx := context.Background()
	_, err := cache.Get(ctx, "any-key")
	if err == nil {
		t.Error("expected error when cache is disabled")
	}
}

func TestCache_Set_Disabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	cache, _ := New(cfg)

	ctx := context.Background()
	err := cache.Set(ctx, "key", []byte("value"), time.Minute)
	if err != nil {
		t.Errorf("Set should return nil when disabled, got: %v", err)
	}
}

func TestCache_GetString(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Backend: "memory",
		MaxSize: 10,
	}

	cache, _ := New(cfg)
	defer cache.Close()

	ctx := context.Background()

	cache.SetString(ctx, "str-key", "hello world", time.Minute)

	got, err := cache.GetString(ctx, "str-key")
	if err != nil {
		t.Fatalf("GetString failed: %v", err)
	}

	if got != "hello world" {
		t.Errorf("GetString = %s, want hello world", got)
	}
}

func TestCache_SetJSON_GetJSON(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Backend: "memory",
		MaxSize: 10,
	}

	cache, _ := New(cfg)
	defer cache.Close()

	ctx := context.Background()

	type TestStruct struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	original := TestStruct{Name: "test", Value: 42}
	err := cache.SetJSON(ctx, "json-key", original, time.Minute)
	if err != nil {
		t.Fatalf("SetJSON failed: %v", err)
	}

	var retrieved TestStruct
	err = cache.GetJSON(ctx, "json-key", &retrieved)
	if err != nil {
		t.Fatalf("GetJSON failed: %v", err)
	}

	if retrieved.Name != original.Name || retrieved.Value != original.Value {
		t.Errorf("GetJSON = %+v, want %+v", retrieved, original)
	}
}

func TestCache_Delete(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Backend: "memory",
		MaxSize: 10,
	}

	cache, _ := New(cfg)
	defer cache.Close()

	ctx := context.Background()

	cache.Set(ctx, "del-key", []byte("value"), time.Minute)

	err := cache.Delete(ctx, "del-key")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = cache.Get(ctx, "del-key")
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestCache_Delete_Disabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	cache, _ := New(cfg)

	ctx := context.Background()
	err := cache.Delete(ctx, "key")
	if err != nil {
		t.Errorf("Delete should return nil when disabled, got: %v", err)
	}
}

func TestCache_Exists(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Backend: "memory",
		MaxSize: 10,
	}

	cache, _ := New(cfg)
	defer cache.Close()

	ctx := context.Background()

	// Check nonexistent
	exists, _ := cache.Exists(ctx, "exist-key")
	if exists {
		t.Error("expected key to not exist")
	}

	// Set and check again
	cache.Set(ctx, "exist-key", []byte("value"), time.Minute)

	exists, _ = cache.Exists(ctx, "exist-key")
	if !exists {
		t.Error("expected key to exist")
	}
}

func TestCache_Exists_Disabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	cache, _ := New(cfg)

	ctx := context.Background()
	exists, _ := cache.Exists(ctx, "key")
	if exists {
		t.Error("Exists should return false when disabled")
	}
}

func TestCache_Keys(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Backend: "memory",
		MaxSize: 10,
		Prefix:  "test",
	}

	cache, _ := New(cfg)
	defer cache.Close()

	ctx := context.Background()

	cache.Set(ctx, "key1", []byte("v1"), time.Minute)
	cache.Set(ctx, "key2", []byte("v2"), time.Minute)
	cache.Set(ctx, "other", []byte("v3"), time.Minute)

	// Memory backend uses prefix matching
	keys, err := cache.Keys(ctx, "key")
	if err != nil {
		t.Fatalf("Keys failed: %v", err)
	}

	if len(keys) != 2 {
		t.Errorf("Keys returned %d keys, want 2", len(keys))
	}
}

func TestCache_Keys_Disabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	cache, _ := New(cfg)

	ctx := context.Background()
	keys, _ := cache.Keys(ctx, "*")
	if keys != nil {
		t.Error("Keys should return nil when disabled")
	}
}

func TestCache_Clear(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Backend: "memory",
		MaxSize: 10,
	}

	cache, _ := New(cfg)
	defer cache.Close()

	ctx := context.Background()

	cache.Set(ctx, "key1", []byte("v1"), time.Minute)
	cache.Set(ctx, "key2", []byte("v2"), time.Minute)

	err := cache.Clear(ctx)
	if err != nil {
		t.Fatalf("Clear failed: %v", err)
	}

	exists, _ := cache.Exists(ctx, "key1")
	if exists {
		t.Error("expected key1 to be cleared")
	}
}

func TestCache_Clear_Disabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	cache, _ := New(cfg)

	ctx := context.Background()
	err := cache.Clear(ctx)
	if err != nil {
		t.Errorf("Clear should return nil when disabled, got: %v", err)
	}
}

func TestCache_KeyPrefixing(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Backend: "memory",
		MaxSize: 10,
		Prefix:  "myprefix",
	}

	cache, _ := New(cfg)
	defer cache.Close()

	ctx := context.Background()

	cache.Set(ctx, "mykey", []byte("value"), time.Minute)

	// Should be able to get with unprefixed key
	got, err := cache.Get(ctx, "mykey")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(got) != "value" {
		t.Errorf("Get = %s, want value", string(got))
	}
}

func TestCache_TTL_Default(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Backend: "memory",
		MaxSize: 10,
		TTL:     time.Hour,
	}

	cache, _ := New(cfg)
	defer cache.Close()

	ctx := context.Background()

	// Set without explicit TTL - should use default
	err := cache.Set(ctx, "ttl-key", []byte("value"), 0)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Should still exist
	exists, _ := cache.Exists(ctx, "ttl-key")
	if !exists {
		t.Error("expected key to exist with default TTL")
	}
}

func TestCache_Expiration(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Backend: "memory",
		MaxSize: 10,
	}

	cache, _ := New(cfg)
	defer cache.Close()

	ctx := context.Background()

	// Set with very short TTL
	cache.Set(ctx, "expire-key", []byte("value"), 1*time.Millisecond)

	// Should exist immediately
	exists, _ := cache.Exists(ctx, "expire-key")
	if !exists {
		t.Error("expected key to exist immediately after set")
	}

	// Wait for expiration
	time.Sleep(50 * time.Millisecond)

	// Should be expired now
	exists, _ = cache.Exists(ctx, "expire-key")
	if exists {
		t.Error("expected key to be expired")
	}
}
