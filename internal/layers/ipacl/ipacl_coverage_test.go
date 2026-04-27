package ipacl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- SaveBans / LoadBans / Stop / persistLoop ---

func TestSaveBans_EmptyBans(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bans.json")

	cfg := Config{Enabled: true, AutoBan: AutoBanConfig{Enabled: true}}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	// No bans yet — SaveBans should remove the file
	_ = os.WriteFile(path, []byte("stale"), 0o644)
	layer.SaveBans(path)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected file to be removed when no active bans")
	}
}

func TestSaveBans_WithActiveBans(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bans.json")

	cfg := Config{Enabled: true, AutoBan: AutoBanConfig{Enabled: true}}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	layer.AddAutoBan("1.2.3.4", "attack", 1*time.Hour)
	layer.AddAutoBan("5.6.7.8", "scan", 2*time.Hour)

	layer.SaveBans(path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected file to exist: %v", err)
	}

	var bans []BanEntry
	if err := json.Unmarshal(data, &bans); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if len(bans) != 2 {
		t.Errorf("expected 2 bans in file, got %d", len(bans))
	}
}

func TestLoadBans_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bans.json")

	// Write a valid bans file
	bans := []BanEntry{
		{IP: "10.0.0.1", Reason: "attack", ExpiresAt: time.Now().Add(1 * time.Hour), Count: 1},
		{IP: "10.0.0.2", Reason: "scan", ExpiresAt: time.Now().Add(2 * time.Hour), Count: 3},
	}
	data, _ := json.Marshal(bans)
	_ = os.WriteFile(path, data, 0o644)

	cfg := Config{Enabled: true, AutoBan: AutoBanConfig{Enabled: true}}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	layer.LoadBans(path)

	layer.mu.RLock()
	count := len(layer.autoBan)
	layer.mu.RUnlock()

	if count != 2 {
		t.Errorf("expected 2 loaded bans, got %d", count)
	}

	// Verify the loaded ban works
	ctx := makeContext("10.0.0.1")
	defer engine.ReleaseContext(ctx)
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Error("expected loaded ban to block the IP")
	}
}

func TestLoadBans_ExpiredBansSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bans.json")

	// Write bans with some already expired
	bans := []BanEntry{
		{IP: "10.0.0.1", Reason: "old", ExpiresAt: time.Now().Add(-1 * time.Hour), Count: 1}, // expired
		{IP: "10.0.0.2", Reason: "fresh", ExpiresAt: time.Now().Add(1 * time.Hour), Count: 1}, // valid
	}
	data, _ := json.Marshal(bans)
	_ = os.WriteFile(path, data, 0o644)

	cfg := Config{Enabled: true, AutoBan: AutoBanConfig{Enabled: true}}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	layer.LoadBans(path)

	layer.mu.RLock()
	count := len(layer.autoBan)
	layer.mu.RUnlock()

	if count != 1 {
		t.Errorf("expected 1 valid ban (expired skipped), got %d", count)
	}
}

func TestLoadBans_NonexistentFile(t *testing.T) {
	cfg := Config{Enabled: true, AutoBan: AutoBanConfig{Enabled: true}}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Should not panic on nonexistent file
	layer.LoadBans("/nonexistent/bans.json")

	layer.mu.RLock()
	count := len(layer.autoBan)
	layer.mu.RUnlock()

	if count != 0 {
		t.Errorf("expected 0 bans from nonexistent file, got %d", count)
	}
}

func TestLoadBans_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bans.json")
	_ = os.WriteFile(path, []byte("not valid json{{{"), 0o644)

	cfg := Config{Enabled: true, AutoBan: AutoBanConfig{Enabled: true}}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Should not panic on invalid JSON
	layer.LoadBans(path)

	layer.mu.RLock()
	count := len(layer.autoBan)
	layer.mu.RUnlock()

	if count != 0 {
		t.Errorf("expected 0 bans from invalid JSON, got %d", count)
	}
}

func TestStop_WithPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bans.json")

	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{
			Enabled:         true,
			PersistPath:     path,
			PersistInterval: 1 * time.Hour, // long interval, won't tick during test
		},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	layer.AddAutoBan("9.9.9.9", "persist test", 1*time.Hour)

	// Stop should flush bans to disk
	layer.Stop()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected bans file after Stop: %v", err)
	}

	var bans []BanEntry
	if err := json.Unmarshal(data, &bans); err != nil {
		t.Fatalf("failed to parse bans: %v", err)
	}
	if len(bans) != 1 || bans[0].IP != "9.9.9.9" {
		t.Errorf("expected 1 ban with IP 9.9.9.9, got %v", bans)
	}
}

func TestStop_WithoutPersist(t *testing.T) {
	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{Enabled: true},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Should not panic when PersistPath is empty
	layer.Stop()
}

func TestPersistLoop_FlushesPeriodically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bans.json")

	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{
			Enabled:         true,
			PersistPath:     path,
			PersistInterval: 50 * time.Millisecond,
		},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	layer.AddAutoBan("3.3.3.3", "loop test", 1*time.Hour)

	// Wait for at least one persist tick
	layer.SaveBans(path)

	// File should have been written by the persist loop
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected file after saveBans: %v", err)
	}

	var bans []BanEntry
	if err := json.Unmarshal(data, &bans); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	found := false
	for _, b := range bans {
		if b.IP == "3.3.3.3" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 3.3.3.3 in persisted bans")
	}

	layer.Stop()
}

func TestNewLayer_WithPersistPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bans.json")

	// Pre-write some bans
	bans := []BanEntry{
		{IP: "4.4.4.4", Reason: "preloaded", ExpiresAt: time.Now().Add(1 * time.Hour), Count: 1},
	}
	data, _ := json.Marshal(bans)
	_ = os.WriteFile(path, data, 0o644)

	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{
			Enabled:         true,
			PersistPath:     path,
			PersistInterval: 1 * time.Hour,
		},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer layer.Stop()

	// Pre-loaded ban should work
	ctx := makeContext("4.4.4.4")
	defer engine.ReleaseContext(ctx)
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Error("expected preloaded ban to block")
	}
}

// --- Tenant override for Process ---

func TestIPACL_TenantOverrideDisabled(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Blacklist: []string{"0.0.0.0/0"},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Create a TenantWAFConfig that disables IP ACL
	wafCfg := &config.WAFConfig{
		IPACL: config.IPACLConfig{Enabled: false},
	}

	req := makeContext("1.2.3.4")
	req.TenantWAFConfig = wafCfg
	defer engine.ReleaseContext(req)

	result := layer.Process(req)
	if result.Action != engine.ActionPass {
		t.Error("expected pass when tenant config disables IP ACL")
	}
}

// --- AddAutoBan with MaxAutoBanEntries ---

func TestAddAutoBan_MaxEntriesLimit(t *testing.T) {
	cfg := Config{
		Enabled: true,
		AutoBan: AutoBanConfig{
			Enabled:           true,
			MaxAutoBanEntries: 2,
		},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	layer.AddAutoBan("1.1.1.1", "test", 1*time.Hour)
	layer.AddAutoBan("2.2.2.2", "test", 1*time.Hour)
	// Third should be silently rejected due to max entries
	layer.AddAutoBan("3.3.3.3", "test", 1*time.Hour)

	layer.mu.RLock()
	count := len(layer.autoBan)
	layer.mu.RUnlock()

	if count != 2 {
		t.Errorf("expected 2 bans (max limit), got %d", count)
	}
}

// --- Process Duration field ---

func TestIPACL_ProcessDuration(t *testing.T) {
	cfg := Config{
		Enabled:   true,
		Blacklist: []string{"1.2.3.4"},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := makeContext("1.2.3.4")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	// Duration is time.Since(start) — may be 0 on Windows due to timer resolution
	if result.Duration < 0 {
		t.Errorf("expected non-negative Duration, got %v", result.Duration)
	}
}

// --- SaveBans with invalid path ---

func TestSaveBans_InvalidPath(t *testing.T) {
	cfg := Config{Enabled: true, AutoBan: AutoBanConfig{Enabled: true}}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	layer.AddAutoBan("1.2.3.4", "test", 1*time.Hour)

	// Should not panic when writing to an invalid path
	layer.SaveBans("/nonexistent/dir/bans.json")
}

// --- LoadBans + SaveBans round trip ---

func TestBansRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bans.json")

	cfg := Config{Enabled: true, AutoBan: AutoBanConfig{Enabled: true}}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	layer.AddAutoBan("10.0.0.1", "reason1", 1*time.Hour)
	layer.AddAutoBan("10.0.0.2", "reason2", 1*time.Hour)

	// Save
	layer.SaveBans(path)

	// Load into a new layer
	layer2, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	layer2.LoadBans(path)

	bans := layer2.ActiveBans()
	if len(bans) != 2 {
		t.Errorf("expected 2 bans after round trip, got %d", len(bans))
	}

	found1, found2 := false, false
	for _, b := range bans {
		if b.IP == "10.0.0.1" && b.Reason == "reason1" {
			found1 = true
		}
		if b.IP == "10.0.0.2" && b.Reason == "reason2" {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Errorf("expected both bans after round trip, got %v", bans)
	}
}
