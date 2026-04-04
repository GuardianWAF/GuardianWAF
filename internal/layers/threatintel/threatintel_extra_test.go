package threatintel

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- Cache Tests ---

func TestCache_Clear(t *testing.T) {
	cache := NewCache(100, 10*time.Minute)
	cache.Set("a", &ThreatInfo{Score: 1})
	cache.Set("b", &ThreatInfo{Score: 2})
	if cache.Len() != 2 {
		t.Fatalf("expected 2, got %d", cache.Len())
	}
	cache.Clear()
	if cache.Len() != 0 {
		t.Errorf("expected 0 after clear, got %d", cache.Len())
	}
}

func TestCache_Cleanup(t *testing.T) {
	cache := NewCache(100, 50*time.Millisecond)
	cache.Set("a", &ThreatInfo{Score: 1})
	cache.Set("b", &ThreatInfo{Score: 2})

	time.Sleep(100 * time.Millisecond)

	removed := cache.Cleanup()
	if removed != 2 {
		t.Errorf("expected 2 removed, got %d", removed)
	}
	if cache.Len() != 0 {
		t.Errorf("expected 0 after cleanup, got %d", cache.Len())
	}
}

func TestCache_Cleanup_Partial(t *testing.T) {
	cache := NewCache(100, 200*time.Millisecond)
	cache.Set("a", &ThreatInfo{Score: 1})
	time.Sleep(80 * time.Millisecond)
	cache.Set("b", &ThreatInfo{Score: 2})
	time.Sleep(130 * time.Millisecond)

	removed := cache.Cleanup()
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
	if cache.Len() != 1 {
		t.Errorf("expected 1 remaining, got %d", cache.Len())
	}
}

func TestCache_Keys(t *testing.T) {
	cache := NewCache(100, 10*time.Minute)
	cache.Set("key1", &ThreatInfo{Score: 1})
	cache.Set("key2", &ThreatInfo{Score: 2})

	keys := cache.Keys()
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	if !m["key1"] || !m["key2"] {
		t.Errorf("expected keys key1 and key2, got %v", keys)
	}
}

func TestCache_UpdateExisting(t *testing.T) {
	cache := NewCache(100, 10*time.Minute)
	cache.Set("a", &ThreatInfo{Score: 10})
	cache.Set("a", &ThreatInfo{Score: 20})

	info, ok := cache.Get("a")
	if !ok {
		t.Fatal("expected key 'a'")
	}
	if info.Score != 20 {
		t.Errorf("expected score 20, got %d", info.Score)
	}
}

func TestCache_ZeroCapacity(t *testing.T) {
	cache := NewCache(0, 10*time.Minute)
	cache.Set("a", &ThreatInfo{Score: 1})
	if cache.Len() != 1 {
		t.Errorf("expected 1, got %d", cache.Len())
	}
}

func TestCache_GetExpired(t *testing.T) {
	cache := NewCache(100, 50*time.Millisecond)
	cache.Set("test", &ThreatInfo{Score: 50})
	time.Sleep(100 * time.Millisecond)

	_, ok := cache.Get("test")
	if ok {
		t.Error("expected expired item to not be found")
	}
}

// --- Feed Manager Tests ---

func TestFeedManager_SetUpdateCallback(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Format: "jsonl"})
	called := false
	fm.SetUpdateCallback(func(entries []ThreatEntry) { called = true })
	fm.onUpdate([]ThreatEntry{})
	if !called {
		t.Error("callback should have been called")
	}
}

func TestFeedManager_LoadOnce_UnknownType(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Type: "unknown"})
	_, err := fm.LoadOnce(context.Background())
	if err == nil {
		t.Error("expected error for unknown type")
	}
}

func TestFeedManager_ParseJSON(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Format: "json"})

	data := []map[string]any{
		{"ip": "1.2.3.4", "score": float64(90), "type": "malware_c2", "source": "test"},
		{"domain": "evil.com", "score": float64(80), "type": "phishing", "source": "test"},
	}
	jsonBytes, _ := json.Marshal(data)

	entries, err := fm.parseJSON(strings.NewReader(string(jsonBytes)))
	if err != nil {
		t.Fatalf("parseJSON failed: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].IP != "1.2.3.4" {
		t.Errorf("expected IP 1.2.3.4, got %s", entries[0].IP)
	}
	if entries[1].Domain != "evil.com" {
		t.Errorf("expected domain evil.com, got %s", entries[1].Domain)
	}
}

func TestFeedManager_ParseJSON_DefaultScore(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Format: "json"})
	data := []map[string]any{
		{"ip": "1.2.3.4"}, // no score → default 50
	}
	jsonBytes, _ := json.Marshal(data)

	entries, _ := fm.parseJSON(strings.NewReader(string(jsonBytes)))
	if len(entries) != 1 {
		t.Fatalf("expected 1, got %d", len(entries))
	}
	if entries[0].Info.Score != 50 {
		t.Errorf("expected default score 50, got %d", entries[0].Info.Score)
	}
}

func TestFeedManager_ParseJSON_SkipEmpty(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Format: "json"})
	data := []map[string]any{
		{"score": float64(90)}, // no ip/cidr/domain → skip
	}
	jsonBytes, _ := json.Marshal(data)

	entries, _ := fm.parseJSON(strings.NewReader(string(jsonBytes)))
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty entry, got %d", len(entries))
	}
}

func TestFeedManager_ParseReader_UnknownFormat(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Format: "xml"})
	_, err := fm.parseReader(strings.NewReader(""))
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestFeedManager_LoadFile_NotFound(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Type: "file", Path: "/nonexistent/file.txt", Format: "csv"})
	_, err := fm.LoadOnce(context.Background())
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestFeedManager_LoadFile_CSV(t *testing.T) {
	f, err := os.CreateTemp("", "threat-*.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	f.WriteString("192.0.2.1,90,malware_c2,test\n")
	f.WriteString("10.0.0.0/8,80,internal,local\n")
	f.Close()

	fm := NewFeedManager(FeedConfig{Type: "file", Path: f.Name(), Format: "csv"})
	entries, err := fm.LoadOnce(context.Background())
	if err != nil {
		t.Fatalf("LoadOnce failed: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestFeedManager_LoadURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := []map[string]any{
			{"ip": "1.2.3.4", "score": float64(90), "type": "malware_c2", "source": "url-test"},
		}
		json.NewEncoder(w).Encode(data)
	}))
	defer srv.Close()

	fm := NewFeedManager(FeedConfig{Type: "url", URL: srv.URL, Format: "json"})
	entries, err := fm.LoadOnce(context.Background())
	if err != nil {
		t.Fatalf("LoadOnce URL failed: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].IP != "1.2.3.4" {
		t.Errorf("expected IP 1.2.3.4, got %s", entries[0].IP)
	}
}

func TestFeedManager_LoadURL_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	fm := NewFeedManager(FeedConfig{Type: "url", URL: srv.URL, Format: "json"})
	_, err := fm.LoadOnce(context.Background())
	if err == nil {
		t.Error("expected error for 500 status")
	}
}

func TestFeedManager_Stop(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Format: "jsonl", Refresh: 1 * time.Hour})
	fm.Stop()
}

// --- Layer updateEntries ---

func TestLayer_UpdateEntries(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, _ := NewLayer(cfg)

	entries := []ThreatEntry{
		{IP: "10.0.0.1", Info: &ThreatInfo{Score: 90, Type: "malware"}},
		{CIDR: "192.0.2.0/24", Info: &ThreatInfo{Score: 80, Type: "spam"}},
		{Domain: "evil.com", Info: &ThreatInfo{Score: 70, Type: "phishing"}},
		{Info: nil}, // should be skipped
	}
	layer.updateEntries(entries)

	stats := layer.Stats()
	if stats["ip_cache_size"] != 1 {
		t.Errorf("expected 1 IP, got %d", stats["ip_cache_size"])
	}
	if stats["cidr_entries"] != 1 {
		t.Errorf("expected 1 CIDR, got %d", stats["cidr_entries"])
	}
	if stats["domain_cache_size"] != 1 {
		t.Errorf("expected 1 domain, got %d", stats["domain_cache_size"])
	}
}

// --- Layer Process: domain with port ---

func TestProcess_DomainWithPort(t *testing.T) {
	cfg := Config{
		Enabled: true,
		DomainRep: DomainRepConfig{
			Enabled:        true,
			BlockMalicious: false,
		},
	}
	layer, _ := NewLayer(cfg)
	layer.AddDomain("example.com", &ThreatInfo{Score: 95, Type: "phishing", Source: "test"})

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("10.0.0.1"),
		Headers:  map[string][]string{"Host": {"example.com:8080"}},
	}

	result := layer.Process(ctx)
	if len(result.Findings) == 0 {
		t.Error("expected findings for domain with port")
	}
}

// --- Layer Process: no client IP ---

func TestProcess_NoClientIP(t *testing.T) {
	cfg := Config{
		Enabled: true,
		IPReputation: IPRepConfig{
			Enabled:        true,
			BlockMalicious: true,
			ScoreThreshold: 50,
		},
	}
	layer, _ := NewLayer(cfg)

	ctx := &engine.RequestContext{
		ClientIP: nil,
		Headers:  map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass with nil IP, got %v", result.Action)
	}
}

// --- Layer Process: IP with block_malicious=false ---

func TestProcess_IPNotBlocking(t *testing.T) {
	cfg := Config{
		Enabled: true,
		IPReputation: IPRepConfig{
			Enabled:        true,
			BlockMalicious: false,
			ScoreThreshold: 50,
		},
	}
	layer, _ := NewLayer(cfg)
	layer.AddIP("192.0.2.1", &ThreatInfo{Score: 90, Type: "malware_c2", Source: "test"})

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("192.0.2.1"),
		Headers:  map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass when not blocking, got %v", result.Action)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings for flagged IP")
	}
}

// --- Layer Process: IP below threshold ---

func TestProcess_IPBelowThreshold_NoFindings(t *testing.T) {
	cfg := Config{
		Enabled: true,
		IPReputation: IPRepConfig{
			Enabled:        true,
			BlockMalicious: true,
			ScoreThreshold: 90,
		},
	}
	layer, _ := NewLayer(cfg)
	layer.AddIP("192.0.2.1", &ThreatInfo{Score: 50, Type: "suspicious", Source: "test"})

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("192.0.2.1"),
		Headers:  map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for IP below threshold, got %v", result.Action)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected no findings for IP below threshold, got %d", len(result.Findings))
	}
}

// --- parseInt edge cases ---

func TestParseInt_Negative(t *testing.T) {
	n, err := parseInt("-42")
	if err != nil {
		t.Fatalf("parseInt(-42) failed: %v", err)
	}
	if n != -42 {
		t.Errorf("expected -42, got %d", n)
	}
}

func TestParseInt_Invalid(t *testing.T) {
	_, err := parseInt("abc")
	if err == nil {
		t.Error("expected error for non-numeric")
	}
}

func TestParseInt_Empty(t *testing.T) {
	n, err := parseInt("")
	if err != nil {
		t.Fatalf("parseInt('') failed: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0, got %d", n)
	}
}

// --- parseJSONL edge cases ---

func TestParseJSONL_EmptyLine(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Format: "jsonl"})
	input := "\n\n# comment\n"
	entries, err := fm.parseJSONL(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseJSONL failed: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty/comment input, got %d", len(entries))
	}
}

func TestParseJSONL_MalformedJSON(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Format: "jsonl"})
	input := "not-json\n{\"ip\": \"1.2.3.4\"}\n"
	entries, err := fm.parseJSONL(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseJSONL failed: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

func TestParseJSONL_NoIdentifier(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Format: "jsonl"})
	input := `{"score": 90, "type": "test"}`
	entries, _ := fm.parseJSONL(strings.NewReader(input))
	if len(entries) != 0 {
		t.Errorf("expected 0 for no identifier, got %d", len(entries))
	}
}

// --- parseCSV edge cases ---

func TestParseCSV_EmptyIP(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Format: "csv"})
	input := ",90,test,src\n"
	entries, _ := fm.parseCSV(strings.NewReader(input))
	if len(entries) != 0 {
		t.Errorf("expected 0 for empty IP, got %d", len(entries))
	}
}

func TestParseCSV_DefaultFormat(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Format: "jsonl"})
	input := `{"ip": "1.2.3.4", "score": 70, "type": "scanner"}`
	entries, err := fm.parseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseReader failed: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1, got %d", len(entries))
	}
}

// --- getHost edge case ---

func TestGetHost_NoHost(t *testing.T) {
	headers := map[string][]string{"Content-Type": {"text/html"}}
	if got := getHost(headers); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestGetHost_EmptySlice(t *testing.T) {
	headers := map[string][]string{"Host": {}}
	if got := getHost(headers); got != "" {
		t.Errorf("expected empty for empty slice, got %q", got)
	}
}

// --- parseJSONL with default score ---

func TestParseJSONL_DefaultScore(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Format: "jsonl"})
	input := `{"ip": "1.2.3.4", "type": "test"}`
	entries, _ := fm.parseJSONL(strings.NewReader(input))
	if len(entries) != 1 {
		t.Fatalf("expected 1, got %d", len(entries))
	}
	if entries[0].Info.Score != 50 {
		t.Errorf("expected default score 50, got %d", entries[0].Info.Score)
	}
}

// --- Layer Start (no feeds to avoid deadlock) ---

func TestLayer_StartStop_NoFeeds(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, _ := NewLayer(cfg)
	layer.Start()
	layer.Start() // idempotent (no feeds → no deadlock)
	layer.Stop()
}

// --- Layer Process: clean request ---

func TestProcess_CleanRequest(t *testing.T) {
	cfg := Config{
		Enabled: true,
		IPReputation: IPRepConfig{
			Enabled:        true,
			BlockMalicious: true,
			ScoreThreshold: 50,
		},
		DomainRep: DomainRepConfig{
			Enabled:        true,
			BlockMalicious: true,
		},
	}
	layer, _ := NewLayer(cfg)

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("10.0.0.1"),
		Headers:  map[string][]string{"Host": {"clean.example.com"}},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for clean request, got %v", result.Action)
	}
	if result.Score != 0 {
		t.Errorf("expected score 0 for clean request, got %d", result.Score)
	}
}

// --- Layer Process: domain blocked with high score ---

func TestProcess_DomainBlocked_HighScore(t *testing.T) {
	cfg := Config{
		Enabled: true,
		DomainRep: DomainRepConfig{
			Enabled:        true,
			BlockMalicious: true,
		},
	}
	layer, _ := NewLayer(cfg)
	layer.AddDomain("evil.com", &ThreatInfo{Score: 90, Type: "phishing", Source: "test"})

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("10.0.0.1"),
		Headers:  map[string][]string{"Host": {"evil.com"}},
	}

	result := layer.Process(ctx)
	if result.Score == 0 {
		t.Error("expected non-zero score for blocked domain")
	}
}

// --- FeedManager Start/Stop/refreshLoop ---

func TestFeedManager_StartStop_Immediate(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Type: "url", URL: "http://127.0.0.1:1/feed", Refresh: 0})
	fm.Start()
	// Should not panic even with refresh=0
	time.Sleep(50 * time.Millisecond)
	fm.Stop()
}

func TestFeedManager_StartStop_WithRefresh(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ip":"1.2.3.4","score":50,"type":"test"}` + "\n"))
	}))
	defer srv.Close()

	var updatedEntries []ThreatEntry
	fm := NewFeedManager(FeedConfig{
		Type:    "url",
		URL:     srv.URL + "/feed",
		Refresh: 100 * time.Millisecond,
	})
	fm.SetUpdateCallback(func(entries []ThreatEntry) {
		updatedEntries = entries
	})

	fm.Start()
	defer fm.Stop()

	// Wait for initial load + at least one refresh
	time.Sleep(250 * time.Millisecond)

	if callCount < 2 {
		t.Errorf("expected at least 2 calls (initial+refresh), got %d", callCount)
	}
	if len(updatedEntries) == 0 {
		t.Error("expected entries via update callback")
	}
}

func TestFeedManager_loadURL_InvalidStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	fm := NewFeedManager(FeedConfig{Type: "url", URL: srv.URL + "/feed"})
	_, err := fm.LoadOnce(context.Background())
	if err == nil {
		t.Error("expected error for non-200 status")
	}
}

func TestFeedManager_loadURL_Unreachable(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Type: "url", URL: "http://127.0.0.1:1/feed"})
	_, err := fm.LoadOnce(context.Background())
	if err == nil {
		t.Error("expected error for unreachable URL")
	}
}

func TestFeedManager_loadFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/feeds.jsonl"
	content := `{"ip":"1.2.3.4","score":90,"type":"malware"}` + "\n" + `{"ip":"5.6.7.8","score":80,"type":"scanner"}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	fm := NewFeedManager(FeedConfig{Type: "file", Path: path})
	entries, err := fm.LoadOnce(context.Background())
	if err != nil {
		t.Fatalf("LoadOnce file: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestFeedManager_loadFile_Missing(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Type: "file", Path: "/nonexistent/feed.jsonl"})
	_, err := fm.LoadOnce(context.Background())
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestFeedManager_loadOnce_UnknownType(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Type: "ftp"})
	_, err := fm.LoadOnce(context.Background())
	if err == nil {
		t.Error("expected error for unknown feed type")
	}
}

// --- parseReader format detection ---

func TestParseReader_DefaultJsonl(t *testing.T) {
	fm := NewFeedManager(FeedConfig{}) // no format specified
	input := `{"ip":"1.2.3.4","score":60,"type":"test"}` + "\n"
	entries, err := fm.parseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseReader: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

func TestParseReader_JSONFormat(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Format: "json"})
	input := `[{"ip":"1.2.3.4","score":90,"type":"malware"},{"ip":"5.6.7.8","score":80,"type":"scanner"}]`
	entries, err := fm.parseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseReader JSON: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestParseReader_CSVFormat(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Format: "csv"})
	input := "1.2.3.4,90,malware\n5.6.7.8,80,scanner\n"
	entries, err := fm.parseReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseReader CSV: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

// --- loadURL via HTTP with JSONL format ---

func TestFeedManager_loadURL_Jsonl(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ip":"1.2.3.4","score":90,"type":"malware"}` + "\n" + `{"cidr":"10.0.0.0/8","score":70,"type":"internal"}` + "\n"))
	}))
	defer srv.Close()

	fm := NewFeedManager(FeedConfig{Type: "url", URL: srv.URL + "/feed"})
	entries, err := fm.LoadOnce(context.Background())
	if err != nil {
		t.Fatalf("LoadOnce URL: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

// Cover loadURL NewRequest error branch.
func TestFeedManager_loadURL_InvalidURL(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Type: "url", URL: "://bad-url"})
	_, err := fm.LoadOnce(context.Background())
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

// Cover parseJSON decode error branch.
func TestFeedManager_ParseJSON_Invalid(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Format: "json"})
	_, err := fm.parseJSON(strings.NewReader("not valid json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// Cover NewLayer with feeds loading initial data.
func TestLayer_WithFeed(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/feed.jsonl"
	content := `{"ip":"1.2.3.4","score":90,"type":"malware"}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Enabled: true,
		Feeds:   []FeedConfig{{Type: "file", Path: path, Format: "jsonl"}},
	}
	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Verify feed data was loaded during NewLayer
	if layer.ipCache.Len() != 1 {
		t.Errorf("expected 1 entry from feed, got %d", layer.ipCache.Len())
	}
}

// Cover checkIP with invalid CIDR in cache.
func TestCheckIP_InvalidCIDR(t *testing.T) {
	layer, _ := NewLayer(Config{Enabled: true})
	layer.cidrCache["not-a-valid-cidr"] = &ThreatInfo{Score: 50, Type: "test"}

	info, ok := layer.checkIP(net.ParseIP("1.2.3.4"))
	if ok {
		t.Errorf("expected no match for invalid CIDR, got %+v", info)
	}
}

// TestLayer_StartStop_WithFeeds covers Start/Stop loop bodies when feeds exist.
func TestLayer_StartStop_WithFeeds(t *testing.T) {
	cfg := Config{
		Enabled: true,
		Feeds: []FeedConfig{
			{Type: "file", Path: "test.csv", Format: "csv", Refresh: time.Hour},
		},
	}
	layer, err := NewLayer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	layer.Start()
	layer.Stop()
}
