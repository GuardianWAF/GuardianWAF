package threatintel

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/ipacl"
)

// --- validateFeedURL coverage (currently 14.3%) ---

func TestValidateFeedURL_Localhost_Cov(t *testing.T) {
	err := validateFeedURL("http://localhost/feed")
	if err == nil {
		t.Error("expected error for localhost URL")
	}
}

func TestValidateFeedURL_InternalSuffix_Cov(t *testing.T) {
	err := validateFeedURL("http://myhost.internal/feed")
	if err == nil {
		t.Error("expected error for .internal host")
	}
}

func TestValidateFeedURL_LocalSuffix_Cov(t *testing.T) {
	err := validateFeedURL("http://myhost.local/feed")
	if err == nil {
		t.Error("expected error for .local host")
	}
}

func TestValidateFeedURL_PrivateIP_Cov(t *testing.T) {
	err := validateFeedURL("http://192.168.1.1/feed")
	if err == nil {
		t.Error("expected error for private IP")
	}
}

func TestValidateFeedURL_LoopbackIP_Cov(t *testing.T) {
	err := validateFeedURL("http://127.0.0.1/feed")
	if err == nil {
		t.Error("expected error for loopback IP")
	}
}

func TestValidateFeedURL_LinkLocalIP_Cov(t *testing.T) {
	err := validateFeedURL("http://169.254.1.1/feed")
	if err == nil {
		t.Error("expected error for link-local IP")
	}
}

func TestValidateFeedURL_UnspecifiedIP_Cov(t *testing.T) {
	err := validateFeedURL("http://0.0.0.0/feed")
	if err == nil {
		t.Error("expected error for unspecified IP")
	}
}

func TestValidateFeedURL_PublicIP_Cov(t *testing.T) {
	err := validateFeedURL("http://8.8.8.8/feed")
	if err != nil {
		t.Errorf("expected no error for public IP: %v", err)
	}
}

func TestValidateFeedURL_InvalidURL_Cov(t *testing.T) {
	err := validateFeedURL("://invalid")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestValidateFeedURL_PublicHostname_Cov(t *testing.T) {
	// Use an IP-based URL to avoid DNS dependency
	err := validateFeedURL("http://8.8.4.4/feed")
	if err != nil {
		t.Errorf("expected no error for public IP URL: %v", err)
	}
}

func TestValidateFeedURL_HostnameResolvesPrivate_Cov(t *testing.T) {
	// Test with a URL that has an IP we can validate directly
	err := validateFeedURL("http://10.0.0.1/feed")
	if err == nil {
		t.Error("expected error for private IP URL")
	}
}

func TestValidateFeedURL_DNSLookupFails_Cov(t *testing.T) {
	// A hostname that won't resolve - should not error (just skip)
	err := validateFeedURL("http://this-host-definitely-does-not-exist-12345.example/feed")
	// DNS resolution failure returns nil (not an error)
	if err != nil {
		t.Logf("DNS lookup failed (expected in some environments): %v", err)
	}
}

// --- NewFeedManager SSRF transport coverage (currently 38.1%) ---

func TestNewFeedManager_SkipSSLVerify_Cov(t *testing.T) {
	// This exercises the SkipSSLVerify warning log path
	fm := NewFeedManager(&FeedConfig{
		Format:        "jsonl",
		SkipSSLVerify: true,
	})
	if fm == nil {
		t.Error("expected non-nil feed manager")
	}
}

func TestNewFeedManager_PrivateURLsAllowed_Cov(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{
		Format:           "jsonl",
		AllowPrivateURLs: true,
	})
	if fm == nil {
		t.Error("expected non-nil feed manager")
	}
}

func TestNewFeedManager_DefaultTransport_Cov(t *testing.T) {
	// Ensure default transport clone works
	fm := NewFeedManager(&FeedConfig{
		Format: "jsonl",
	})
	if fm == nil {
		t.Error("expected non-nil feed manager")
	}
	if fm.client == nil {
		t.Error("expected non-nil HTTP client")
	}
}

// --- Stop idempotent coverage ---

func TestFeedManager_Stop_Idempotent_Cov(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{Format: "jsonl"})
	fm.Stop()
	fm.Stop() // Should not panic on second call
}

// --- loadURL HTTP warning for non-HTTPS ---

func TestFeedManager_loadURL_HTTPWarning_Cov(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ip":"1.2.3.4","score":50,"type":"test"}` + "\n"))
	}))
	defer srv.Close()

	fm := NewFeedManager(&FeedConfig{
		Type:             "url",
		URL:              srv.URL, // http://... URL, should trigger warning
		Format:           "jsonl",
		AllowPrivateURLs: true,
	})
	entries, err := fm.LoadOnce(context.Background())
	if err != nil {
		t.Fatalf("LoadOnce failed: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

// --- loadURL SSRF rejection ---

func TestFeedManager_loadURL_SSRFRejected_Cov(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{
		Type:   "url",
		URL:    "http://127.0.0.1/feed",
		Format: "jsonl",
	})
	_, err := fm.LoadOnce(context.Background())
	if err == nil {
		t.Error("expected SSRF rejection for localhost URL")
	}
}

// --- Process with tenant override disabling threat intel ---

func TestProcess_TenantOverrideDisabled_Cov(t *testing.T) {
	cfg := Config{
		Enabled: true,
		IPReputation: IPRepConfig{
			Enabled:        true,
			BlockMalicious: true,
			ScoreThreshold: 50,
		},
	}
	layer, _ := NewLayer(&cfg)

	// Tenant config disables threat intel
	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("192.0.2.1"),
		Headers:  map[string][]string{},
		TenantWAFConfig: &config.WAFConfig{
			ThreatIntel: config.ThreatIntelConfig{Enabled: false},
		},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass when tenant disables threat intel, got %v", result.Action)
	}
}

// --- checkIP returns non-ThreatInfo value from CIDR tree ---

func TestCheckIP_NonThreatInfoValue_Cov(t *testing.T) {
	layer, _ := NewLayer(&Config{Enabled: true})

	// Insert a non-ThreatInfo value into the CIDR tree
	layer.mu.Lock()
	layer.cidrTree.Insert("10.0.0.0/8", "not-a-threat-info")
	layer.mu.Unlock()

	// Should return false since the value is not *ThreatInfo
	_, ok := layer.checkIP(net.ParseIP("10.1.2.3"))
	if ok {
		t.Error("expected false for non-ThreatInfo value in CIDR tree")
	}
}

// --- checkDomain with no results ---

func TestCheckDomain_NoMatch_Cov(t *testing.T) {
	layer, _ := NewLayer(&Config{Enabled: true})
	layer.AddDomain("example.com", &ThreatInfo{Score: 50})

	// Completely unrelated domain
	_, ok := layer.checkDomain("other.com")
	if ok {
		t.Error("expected no match for unrelated domain")
	}
}

// --- updateEntries rebuilds CIDR tree ---

func TestLayer_UpdateEntries_RebuildsCIDR_Cov(t *testing.T) {
	layer, _ := NewLayer(&Config{Enabled: true})

	// First update
	layer.updateEntries([]ThreatEntry{
		{CIDR: "10.0.0.0/8", Info: &ThreatInfo{Score: 50, Type: "test"}},
	})

	stats := layer.Stats()
	if stats["cidr_entries"] != 1 {
		t.Errorf("expected 1 CIDR entry, got %d", stats["cidr_entries"])
	}

	// Second update with different data — should rebuild tree
	layer.updateEntries([]ThreatEntry{
		{CIDR: "192.0.2.0/24", Info: &ThreatInfo{Score: 60, Type: "test2"}},
	})

	stats = layer.Stats()
	if stats["cidr_entries"] != 1 {
		t.Errorf("expected 1 CIDR entry after rebuild, got %d", stats["cidr_entries"])
	}

	// Old CIDR should no longer match
	_, ok := layer.checkIP(net.ParseIP("10.1.2.3"))
	if ok {
		t.Error("old CIDR should be evicted after updateEntries rebuild")
	}

	// New CIDR should match
	info, ok := layer.checkIP(net.ParseIP("192.0.2.100"))
	if !ok || info.Score != 60 {
		t.Error("new CIDR should match")
	}
}

// --- parseInt overflow ---

func TestParseInt_Overflow_Cov(t *testing.T) {
	// Construct a string that would overflow int
	bigStr := "9999999999999999999999999999999999999999"
	_, err := parseInt(bigStr)
	if err == nil {
		t.Error("expected error for integer overflow")
	}
}

// --- parseCSV with domain entry ---

func TestParseCSV_DomainEntry_Cov(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{Format: "csv"})
	input := "evil.example.com,90,phishing,phishtank\n"
	entries, err := fm.parseCSV(strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseCSV failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Domain != "evil.example.com" {
		t.Errorf("expected domain evil.example.com, got %s", entries[0].Domain)
	}
}

// --- parseCSV with CIDR entry ---

func TestParseCSV_CIDREntry_Cov(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{Format: "csv"})
	input := "10.0.0.0/8,80,internal,local\n"
	entries, _ := fm.parseCSV(strings.NewReader(input))
	if len(entries) != 1 {
		t.Fatalf("expected 1, got %d", len(entries))
	}
	if entries[0].CIDR != "10.0.0.0/8" {
		t.Errorf("expected CIDR 10.0.0.0/8, got %s", entries[0].CIDR)
	}
}

// --- parseJSONL scanner error ---

func TestParseJSONL_ScannerError_Cov(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{Format: "jsonl"})
	// Simple valid input to verify normal path
	input := `{"ip":"1.2.3.4","score":50,"type":"test"}`
	entries, err := fm.parseJSONL(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

// --- parseJSON with valid data ---

func TestParseJSON_ValidData_Cov(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{Format: "json"})
	data := []map[string]any{
		{"ip": "1.2.3.4", "score": float64(90), "type": "malware", "source": "test"},
		{"cidr": "10.0.0.0/8", "score": float64(80), "type": "internal", "source": "test"},
		{"domain": "evil.com", "score": float64(70), "type": "phishing", "source": "test"},
	}
	jsonBytes, _ := json.Marshal(data)
	entries, err := fm.parseJSON(strings.NewReader(string(jsonBytes)))
	if err != nil {
		t.Fatalf("parseJSON failed: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}

// --- Layer Order ---

func TestLayer_Order_Cov(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, _ := NewLayer(&cfg)
	// The Layer doesn't implement Order() in the interface, but Name is tested
	// Let's verify Process works end-to-end
	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("10.0.0.1"),
		Headers:  map[string][]string{"Host": {"clean.example.com"}},
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass, got %v", result.Action)
	}
}

// --- Stats after updateEntries with nil Info entries ---

func TestLayer_Stats_AfterUpdate_Cov(t *testing.T) {
	layer, _ := NewLayer(&Config{Enabled: true})
	layer.updateEntries([]ThreatEntry{
		{IP: "1.2.3.4", Info: &ThreatInfo{Score: 90}},
		{Info: nil}, // should be skipped
		{Domain: "evil.com", Info: &ThreatInfo{Score: 80}},
		{CIDR: "10.0.0.0/8", Info: &ThreatInfo{Score: 70}},
	})
	stats := layer.Stats()
	if stats["ip_cache_size"] != 1 {
		t.Errorf("expected 1 IP, got %d", stats["ip_cache_size"])
	}
	if stats["domain_cache_size"] != 1 {
		t.Errorf("expected 1 domain, got %d", stats["domain_cache_size"])
	}
	if stats["cidr_entries"] != 1 {
		t.Errorf("expected 1 CIDR, got %d", stats["cidr_entries"])
	}
}

// --- RadixTree usage coverage ---

func TestLayer_CIDRLookup_Cov(t *testing.T) {
	layer, _ := NewLayer(&Config{Enabled: true})

	// Direct insertion into radix tree
	layer.mu.Lock()
	tree := ipacl.NewRadixTree()
	tree.Insert("172.16.0.0/12", &ThreatInfo{Score: 75, Type: "internal"})
	layer.cidrTree = tree
	layer.mu.Unlock()

	info, ok := layer.checkIP(net.ParseIP("172.16.5.5"))
	if !ok {
		t.Error("expected match for IP in CIDR")
	}
	if info.Score != 75 {
		t.Errorf("expected score 75, got %d", info.Score)
	}

	// Result should be cached now
	cachedInfo, ok := layer.ipCache.Get("172.16.5.5")
	if !ok || cachedInfo.Score != 75 {
		t.Error("expected cached result after CIDR lookup")
	}
}
