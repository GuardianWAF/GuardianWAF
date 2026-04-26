package ai

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- SetEncryptionKey with non-empty secret ---

func TestSetEncryptionKey_NonEmpty_Cov(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	cfg := ProviderConfig{
		ProviderID: "test",
		ModelID:    "model",
		APIKey:     "sk-plaintext-key",
		BaseURL:    "https://api.example.com",
	}
	if err := store.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	// Set encryption key
	store.SetEncryptionKey("my-encryption-secret")

	// Verify the API key is encrypted on disk
	configFile := filepath.Join(dir, "ai_config.json")
	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	configSection, ok := raw["config"].(map[string]any)
	if !ok {
		t.Fatal("config section missing")
	}

	apiKey, _ := configSection["api_key"].(string)
	if apiKey == "sk-plaintext-key" {
		t.Error("API key should be encrypted on disk after SetEncryptionKey")
	}
	if len(apiKey) < 10 {
		t.Errorf("API key looks too short, got %q", apiKey)
	}

	// The in-memory API key should still be plaintext (decrypted)
	gotCfg := store.GetConfig()
	if gotCfg.APIKey != "sk-plaintext-key" {
		t.Errorf("in-memory API key = %q, want sk-plaintext-key", gotCfg.APIKey)
	}
}

// --- SetEncryptionKey with empty secret disables encryption ---

func TestSetEncryptionKey_Empty_Cov(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	cfg := ProviderConfig{
		ProviderID: "test",
		ModelID:    "model",
		APIKey:     "sk-key",
		BaseURL:    "https://api.example.com",
	}
	_ = store.SetConfig(cfg)

	// First set a non-empty key
	store.SetEncryptionKey("some-secret")

	// Then disable encryption
	store.SetEncryptionKey("")

	// The encKey should be nil now
	store.mu.RLock()
	key := store.encKey
	store.mu.RUnlock()
	if key != nil {
		t.Error("expected nil encKey after setting empty secret")
	}
}

// --- SetEncryptionKey decrypts already-encrypted key ---

func TestSetEncryptionKey_DecryptExisting_Cov(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	// Set up initial config with encryption
	cfg := ProviderConfig{
		ProviderID: "test",
		ModelID:    "model",
		APIKey:     "sk-original-key",
		BaseURL:    "https://api.example.com",
	}
	_ = store.SetConfig(cfg)
	store.SetEncryptionKey("secret-1")

	// Now set a new encryption key - it should decrypt with old key first
	store.SetEncryptionKey("secret-2")

	gotCfg := store.GetConfig()
	if gotCfg.APIKey != "sk-original-key" {
		t.Errorf("API key = %q, want sk-original-key", gotCfg.APIKey)
	}
}

// --- deriveStoreKey ---

func TestDeriveStoreKey_Cov(t *testing.T) {
	password := []byte("test-password")
	salt := []byte("test-salt")
	iterations := 1000

	key := deriveStoreKey(password, salt, iterations)
	if len(key) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(key))
	}

	// Same input should produce same key
	key2 := deriveStoreKey(password, salt, iterations)
	if string(key) != string(key2) {
		t.Error("same input should produce same key")
	}

	// Different input should produce different key
	key3 := deriveStoreKey([]byte("other-password"), salt, iterations)
	if string(key) == string(key3) {
		t.Error("different passwords should produce different keys")
	}
}

// --- encryptValue and decryptValue roundtrip ---

func TestEncryptDecrypt_Roundtrip_Cov(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := "sk-test-api-key-12345"
	encrypted, err := encryptValue(plaintext, key)
	if err != nil {
		t.Fatalf("encryptValue: %v", err)
	}
	if encrypted == plaintext {
		t.Error("encrypted should differ from plaintext")
	}

	decrypted, err := decryptValue(encrypted, key)
	if err != nil {
		t.Fatalf("decryptValue: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

// --- decryptValue with wrong key ---

func TestDecryptValue_WrongKey_Cov(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1

	encrypted, err := encryptValue("secret-data", key1)
	if err != nil {
		t.Fatalf("encryptValue: %v", err)
	}

	_, err = decryptValue(encrypted, key2)
	if err == nil {
		t.Error("expected error decrypting with wrong key")
	}
}

// --- decryptValue with invalid base64 ---

func TestDecryptValue_InvalidBase64_Cov(t *testing.T) {
	key := make([]byte, 32)
	_, err := decryptValue("!!!invalid-base64!!!", key)
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

// --- decryptValue with too-short ciphertext ---

func TestDecryptValue_TooShort_Cov(t *testing.T) {
	key := make([]byte, 32)
	// Base64 encode a very short byte slice
	encoded := "AQ" // just 1 byte, too short for nonce
	_, err := decryptValue(encoded, key)
	if err == nil {
		t.Error("expected error for too-short ciphertext")
	}
}

// --- validateURLNotPrivate ---

func TestValidateURLNotPrivate_Cov(t *testing.T) {
	tests := []struct {
		url       string
		shouldErr bool
		desc      string
	}{
		{"https://api.openai.com/v1", false, "public URL"},
		{"http://localhost:8080/api", true, "localhost"},
		{"http://127.0.0.1:8080/api", true, "loopback IP"},
		{"http://10.0.0.1:8080/api", true, "private IP"},
		{"http://192.168.1.1:8080/api", true, "private IP 192.168"},
		{"http://172.16.0.1:8080/api", true, "private IP 172.16"},
		{"http://169.254.1.1:8080/api", true, "link-local"},
		{"http://0.0.0.0:8080/api", true, "unspecified"},
		{"http://host.internal:8080/api", true, ".internal suffix"},
		{"http://host.local:8080/api", true, ".local suffix"},
		{"http://example.com/api", false, "public domain"},
		{"not-a-url", false, "no scheme (URL parses as path)"},
	}

	for _, tt := range tests {
		err := validateURLNotPrivate(tt.url)
		if tt.shouldErr && err == nil {
			t.Errorf("%s: expected error for %q", tt.desc, tt.url)
		}
		if !tt.shouldErr && err != nil {
			t.Errorf("%s: unexpected error for %q: %v", tt.desc, tt.url, err)
		}
	}
}

// --- aiSSRFDialContext ---

func TestAiSSRFDialContext_Cov(t *testing.T) {
	// Create a test server to get a real address
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dialFn := aiSSRFDialContext()

	// Test with a valid host that resolves to 127.0.0.1 (httptest server)
	// This should fail because httptest servers bind to 127.0.0.1 which is loopback
	_, err := dialFn(t.Context(), "tcp", "127.0.0.1:0")
	if err == nil {
		t.Error("expected SSRF dial to reject loopback address")
	}
}

// --- NewClient with TLS server name ---

func TestNewClient_TLSServerName_Cov(t *testing.T) {
	client := NewClient(ClientConfig{
		BaseURL:              "https://api.example.com/v1",
		APIKey:               "test",
		Model:                "test",
		TLSServerName:        "custom-server-name",
		AllowPrivateEndpoint: true,
	})
	if client == nil {
		t.Fatal("expected client")
	}
}

// --- NewClient with timeout ---

func TestNewClient_WithTimeout_Cov(t *testing.T) {
	client := NewClient(ClientConfig{
		BaseURL:              "https://api.example.com/v1",
		APIKey:               "test",
		Model:                "test",
		Timeout:              30 * time.Second,
		AllowPrivateEndpoint: true,
	})
	if client == nil {
		t.Fatal("expected client")
	}
	if client.httpClient.Timeout != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", client.httpClient.Timeout)
	}
}

// --- loadOrCreateEncKey loads existing key ---

func TestLoadOrCreateEncKey_ExistingKey_Cov(t *testing.T) {
	dir := t.TempDir()
	// Pre-create an existing key file
	existingKey := make([]byte, 32)
	for i := range existingKey {
		existingKey[i] = byte(i + 1)
	}
	keyPath := filepath.Join(dir, encKeyFile)
	if err := os.WriteFile(keyPath, existingKey, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	store := NewStore(dir)
	store.mu.RLock()
	key := store.encKey
	store.mu.RUnlock()

	if key == nil {
		t.Fatal("expected encryption key to be loaded")
	}
	if string(key) != string(existingKey) {
		t.Error("loaded key should match the pre-created key")
	}
}

// --- loadOrCreateEncKey with wrong-size key file ---

func TestLoadOrCreateEncKey_WrongSizeKey_Cov(t *testing.T) {
	dir := t.TempDir()
	// Write a key file with wrong size
	keyPath := filepath.Join(dir, encKeyFile)
	if err := os.WriteFile(keyPath, []byte("short"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	store := NewStore(dir)
	store.mu.RLock()
	key := store.encKey
	store.mu.RUnlock()

	// Should generate a new key since existing one is wrong size
	if key == nil {
		t.Fatal("expected a new encryption key to be generated")
	}
	if len(key) != 32 {
		t.Errorf("expected 32-byte key, got %d", len(key))
	}
}

// --- Analyzer Stop when already stopped ---

func TestAnalyzer_Stop_AlreadyStopped_Cov(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	a := NewAnalyzer(AnalyzerConfig{Enabled: true}, store, "")

	// Stop without starting should close stopCh
	a.Stop()
	// Second stop should be a no-op
	a.Stop()
}

// --- Analyzer collectEvent with tenant ID ---

func TestAnalyzer_CollectEvent_WithTenantID_Cov(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	_ = store.SetConfig(ProviderConfig{
		ProviderID: "test",
		ModelID:    "test-model",
		APIKey:     "test-key",
		BaseURL:    "https://fake.url",
	})

	a := NewAnalyzer(AnalyzerConfig{
		Enabled:       true,
		BatchSize:     100,
		BatchInterval: time.Hour,
		MinScoreForAI: 10,
	}, store, "")

	// Manually collect an event with tenant ID
	ev := engine.Event{
		ClientIP:   "1.2.3.4",
		Method:     "POST",
		Path:       "/api/data",
		Query:      "q=test",
		UserAgent:  "Mozilla/5.0",
		Score:      60,
		Action:     engine.ActionBlock,
		Timestamp:  time.Now(),
		TenantID:   "tenant-abc",
		Findings:   []engine.Finding{{DetectorName: "xss", Description: "XSS attempt", Score: 60}},
	}
	a.collectEvent(ev)

	a.mu.RLock()
	pending := a.pending
	a.mu.RUnlock()

	if len(pending) != 1 {
		t.Fatalf("expected 1 pending event, got %d", len(pending))
	}
	if pending[0].TenantID != "tenant-abc" {
		t.Errorf("tenant_id = %q, want tenant-abc", pending[0].TenantID)
	}
	if pending[0].Method != "POST" {
		t.Errorf("method = %q, want POST", pending[0].Method)
	}
	if pending[0].Query != "q=test" {
		t.Errorf("query = %q, want q=test", pending[0].Query)
	}
}

// --- Analyzer loop: event below MinScoreForAI is skipped ---

func TestAnalyzer_LowScoreEventSkipped_Cov(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return error so the batch analysis fails fast
		w.WriteHeader(500)
	}))
	defer srv.Close()

	dir := t.TempDir()
	store := NewStore(dir)
	_ = store.SetConfig(ProviderConfig{
		ProviderID: "test",
		ModelID:    "test-model",
		APIKey:     "test-key",
		BaseURL:    srv.URL,
	})

	a := NewAnalyzer(AnalyzerConfig{
		Enabled:       true,
		BatchSize:     1,
		BatchInterval: time.Hour,
		MinScoreForAI: 50,
	}, store, "")
	a.SetLogger(func(_, _ string) {})

	eventCh := make(chan engine.Event, 10)
	a.Start(eventCh)

	// Send a low-score event that should be skipped
	eventCh <- engine.Event{
		ClientIP:  "1.2.3.4",
		Score:     10, // Below MinScoreForAI
		Action:    engine.ActionPass,
		Timestamp: time.Now(),
	}

	// Send a high-score event to trigger batch flush
	eventCh <- engine.Event{
		ClientIP:  "5.6.7.8",
		Score:     80,
		Action:    engine.ActionBlock,
		Timestamp: time.Now(),
		Findings:  []engine.Finding{{DetectorName: "sqli", Description: "test", Score: 80}},
	}

	time.Sleep(200 * time.Millisecond)
	a.Stop()

	// Only 1 result should exist (the high-score event triggered the batch)
	history := store.GetHistory(10)
	if len(history) != 1 {
		t.Errorf("expected 1 result (low-score skipped), got %d", len(history))
	}
	if len(history) > 0 && history[0].Error == "" {
		t.Error("expected error in result (API returned 500)")
	}
}

// --- Analyzer ManualAnalyze with API error ---

func TestAnalyzer_ManualAnalyze_APIError_Cov(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	store := NewStore(dir)
	_ = store.SetConfig(ProviderConfig{
		ProviderID: "test",
		ModelID:    "test-model",
		APIKey:     "test-key",
		BaseURL:    srv.URL,
	})

	a := NewAnalyzer(AnalyzerConfig{
		Enabled:         true,
		MaxTokensHour:   50000,
		MaxTokensDay:    500000,
		MaxRequestsHour: 30,
	}, store, "")

	result, err := a.ManualAnalyze([]engine.Event{
		{ClientIP: "1.2.3.4", Method: "GET", Path: "/", Timestamp: time.Now()},
	})
	if err == nil {
		t.Error("expected error from API")
	}
	if result == nil {
		t.Fatal("expected result even on error")
	}
	if result.Error == "" {
		t.Error("expected error message in result")
	}
}

// --- Analyzer flushBatch with empty batch (no-op) ---

func TestAnalyzer_FlushBatch_Empty_Cov(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	a := NewAnalyzer(AnalyzerConfig{Enabled: true}, store, "")
	a.SetLogger(func(_, _ string) {})

	// flushBatch with empty pending should be no-op
	a.flushBatch()

	history := store.GetHistory(10)
	if len(history) != 0 {
		t.Error("expected no results for empty batch flush")
	}
}

// --- Analyzer applyVerdicts with no blocker ---

func TestAnalyzer_ApplyVerdicts_NoBlocker_Cov(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	a := NewAnalyzer(AnalyzerConfig{
		Enabled:          true,
		AutoBlockEnabled: true,
	}, store, "")

	// No blocker set - should be no-op
	a.applyVerdicts([]Verdict{{IP: "1.2.3.4", Action: "block", Confidence: 0.95}})
	// Should not panic
}

// --- Analyzer applyVerdicts with blocker but auto-block disabled ---

func TestAnalyzer_ApplyVerdicts_AutoBlockDisabled_Cov(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	a := NewAnalyzer(AnalyzerConfig{
		Enabled:          true,
		AutoBlockEnabled: false,
	}, store, "")

	var mb mockBlocker
	a.SetBlocker(&mb)

	a.applyVerdicts([]Verdict{{IP: "1.2.3.4", Action: "block", Confidence: 0.95}})
	if len(mb.calls) != 0 {
		t.Error("should not block when auto-block disabled")
	}
}

// --- Store: save with encryption roundtrip ---

func TestStore_EncryptionRoundtrip_Cov(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	// Set encryption key before saving
	store.SetEncryptionKey("test-secret")

	cfg := ProviderConfig{
		ProviderID: "openai",
		ModelID:    "gpt-4o",
		APIKey:     "sk-super-secret-key",
		BaseURL:    "https://api.openai.com/v1",
	}
	if err := store.SetConfig(cfg); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}

	// Read the file and verify API key is encrypted
	configFile := filepath.Join(dir, "ai_config.json")
	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if bytes.Contains(data, []byte("sk-super-secret-key")) {
		t.Error("API key should NOT appear in plaintext on disk")
	}

	// Reload store with same encryption key - should decrypt correctly
	store2 := NewStore(dir)
	store2.SetEncryptionKey("test-secret")
	cfg2 := store2.GetConfig()
	if cfg2.APIKey != "sk-super-secret-key" {
		t.Errorf("API key after reload = %q, want sk-super-secret-key", cfg2.APIKey)
	}
}

// --- Store: HasConfig with base URL but no API key ---

func TestStore_HasConfig_NoAPIKey_Cov(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	cfg := ProviderConfig{
		ProviderID: "test",
		BaseURL:    "https://api.example.com",
		// No API key
	}
	_ = store.SetConfig(cfg)

	if store.HasConfig() {
		t.Error("expected false when no API key")
	}
}

// --- Store: HasConfig with API key but no base URL ---

func TestStore_HasConfig_NoBaseURL_Cov(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	cfg := ProviderConfig{
		ProviderID: "test",
		APIKey:     "sk-key",
		// No base URL
	}
	_ = store.SetConfig(cfg)

	if store.HasConfig() {
		t.Error("expected false when no base URL")
	}
}

// --- Store: save with already-encrypted API key ---

func TestStore_Save_AlreadyEncrypted_Cov(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	store.SetEncryptionKey("secret")

	cfg := ProviderConfig{
		ProviderID: "test",
		APIKey:     "sk-my-key",
		BaseURL:    "https://api.example.com",
	}
	_ = store.SetConfig(cfg)

	// The key should be encrypted on disk. Get the encrypted form.
	configFile := filepath.Join(dir, "ai_config.json")
	data, _ := os.ReadFile(configFile)
	var raw map[string]any
	json.Unmarshal(data, &raw)
	configSection := raw["config"].(map[string]any)
	encryptedKey := configSection["api_key"].(string)

	// Now manually set the API key to the encrypted form to test the skip path
	store.mu.Lock()
	store.data.Config.APIKey = encryptedKey // already has enc: prefix
	err := store.save()
	store.mu.Unlock()

	if err != nil {
		t.Fatalf("save with already-encrypted key: %v", err)
	}
}

// --- extractJSON edge cases ---

func TestExtractJSON_EdgeCases_Cov(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"no braces at all", "no braces at all"},
		{"{only open", "{only open"},
		{"only close}", "only close}"},
		{"{}", "{}"},
		{"text {\"a\":1} more", "{\"a\":1}"},
		{"```json\n{\"x\": true}\n```", "{\"x\": true}"},
		{"multiple {first} and {second}", "{first} and {second}"},
	}
	for _, tt := range tests {
		got := extractJSON(tt.input)
		if got != tt.want {
			t.Errorf("extractJSON(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// --- truncate edge cases ---

func TestTruncate_EdgeCases_Cov(t *testing.T) {
	if truncate("", 10) != "" {
		t.Error("empty string should stay empty")
	}
	if truncate("abc", 3) != "abc" {
		t.Error("string at exact length should not be truncated")
	}
	if truncate("abcd", 3) != "abc..." {
		t.Error("string over length should be truncated with ...")
	}
	if truncate("a", 0) != "..." {
		t.Error("maxLen 0 should return ...")
	}
}

// --- CatalogCache with empty URL defaults ---

func TestNewCatalogCache_EmptyURL_Cov(t *testing.T) {
	cc := NewCatalogCache("")
	if cc.url != defaultCatalogURL {
		t.Errorf("expected default URL, got %s", cc.url)
	}
}

// --- FetchCatalog with large response (>5MB) ---

func TestFetchCatalog_LargeResponse_Cov(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Send > 5MB response
		w.WriteHeader(http.StatusOK)
		large := make([]byte, 6*1024*1024)
		for i := range large {
			large[i] = 'a'
		}
		w.Write(large)
	}))
	defer srv.Close()

	_, err := FetchCatalog(srv.URL)
	if err == nil {
		t.Error("expected error for oversized response")
	}
}

// --- Analyzer with initial provider from store ---

func TestNewAnalyzer_WithInitialProvider_Cov(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	_ = store.SetConfig(ProviderConfig{
		ProviderID: "test",
		ModelID:    "test-model",
		APIKey:     "test-key",
		BaseURL:    "https://api.example.com/v1",
	})

	a := NewAnalyzer(AnalyzerConfig{Enabled: true}, store, "")
	if a.client == nil {
		t.Error("expected client to be initialized from store config")
	}
}

// --- Analyzer defaults ---

func TestNewAnalyzer_Defaults_Cov(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	a := NewAnalyzer(AnalyzerConfig{Enabled: true}, store, "")

	if a.config.BatchSize != 20 {
		t.Errorf("default BatchSize = %d, want 20", a.config.BatchSize)
	}
	if a.config.BatchInterval != 60*time.Second {
		t.Errorf("default BatchInterval = %v, want 60s", a.config.BatchInterval)
	}
	if a.config.MinScoreForAI != 25 {
		t.Errorf("default MinScoreForAI = %d, want 25", a.config.MinScoreForAI)
	}
	if a.config.AutoBlockTTL != time.Hour {
		t.Errorf("default AutoBlockTTL = %v, want 1h", a.config.AutoBlockTTL)
	}
	if a.config.MaxTokensHour != 50000 {
		t.Errorf("default MaxTokensHour = %d, want 50000", a.config.MaxTokensHour)
	}
	if a.config.MaxTokensDay != 500000 {
		t.Errorf("default MaxTokensDay = %d, want 500000", a.config.MaxTokensDay)
	}
	if a.config.MaxRequestsHour != 30 {
		t.Errorf("default MaxRequestsHour = %d, want 30", a.config.MaxRequestsHour)
	}
}
