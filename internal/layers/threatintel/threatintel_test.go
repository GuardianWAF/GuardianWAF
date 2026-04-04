package threatintel

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestNewLayer(t *testing.T) {
	cfg := Config{
		Enabled: true,
		IPReputation: IPRepConfig{
			Enabled:        true,
			BlockMalicious: true,
			ScoreThreshold: 70,
		},
		CacheSize: 1000,
		CacheTTL:  30 * time.Minute,
	}

	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}

	if layer.Name() != "threat_intel" {
		t.Errorf("Expected name 'threat_intel', got '%s'", layer.Name())
	}
}

func TestProcess_Disabled(t *testing.T) {
	cfg := Config{Enabled: false}
	layer, _ := NewLayer(&cfg)

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("192.0.2.1"),
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Expected pass when disabled, got %v", result.Action)
	}
}

func TestProcess_IPBlocked(t *testing.T) {
	cfg := Config{
		Enabled: true,
		IPReputation: IPRepConfig{
			Enabled:        true,
			BlockMalicious: true,
			ScoreThreshold: 70,
		},
	}
	layer, _ := NewLayer(&cfg)

	// Add malicious IP
	layer.AddIP("192.0.2.1", &ThreatInfo{
		Score:  90,
		Type:   "malware_c2",
		Source: "test",
	})

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("192.0.2.1"),
		Headers:  map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("Expected block for malicious IP, got %v", result.Action)
	}
	if result.Score != 90 {
		t.Errorf("Expected score 90, got %d", result.Score)
	}
}

func TestProcess_IPBelowThreshold(t *testing.T) {
	cfg := Config{
		Enabled: true,
		IPReputation: IPRepConfig{
			Enabled:        true,
			BlockMalicious: true,
			ScoreThreshold: 70,
		},
	}
	layer, _ := NewLayer(&cfg)

	// Add IP with low score
	layer.AddIP("192.0.2.1", &ThreatInfo{
		Score:  50,
		Type:   "suspicious",
		Source: "test",
	})

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("192.0.2.1"),
		Headers:  map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Expected pass for IP below threshold, got %v", result.Action)
	}
}

func TestProcess_DomainFlagged(t *testing.T) {
	cfg := Config{
		Enabled: true,
		IPReputation: IPRepConfig{
			Enabled: true,
		},
		DomainRep: DomainRepConfig{
			Enabled:        true,
			BlockMalicious: false, // Log only
		},
	}
	layer, _ := NewLayer(&cfg)

	layer.AddDomain("malicious.example.com", &ThreatInfo{
		Score:  95,
		Type:   "phishing",
		Source: "test",
	})

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("10.0.0.1"),
		Headers:  map[string][]string{"Host": {"malicious.example.com"}},
	}

	result := layer.Process(ctx)
	// Should pass (block_malicious=false) but include findings
	if result.Action != engine.ActionPass {
		t.Errorf("Expected pass for domain (block disabled), got %v", result.Action)
	}
	if len(result.Findings) == 0 {
		t.Error("Expected findings for malicious domain")
	}
}

func TestProcess_DomainBlocked(t *testing.T) {
	cfg := Config{
		Enabled: true,
		IPReputation: IPRepConfig{
			Enabled: true,
		},
		DomainRep: DomainRepConfig{
			Enabled:        true,
			BlockMalicious: true,
		},
	}
	layer, _ := NewLayer(&cfg)

	layer.AddDomain("malicious.example.com", &ThreatInfo{
		Score:  80,
		Type:   "phishing",
		Source: "test",
	})

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("10.0.0.1"),
		Headers:  map[string][]string{"Host": {"malicious.example.com"}},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Error("Domain blocking adds findings but doesn't block")
	}
}

func TestCheckIP_CIDR(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, _ := NewLayer(&cfg)

	// Add CIDR range
	layer.mu.Lock()
	layer.cidrCache["192.0.2.0/24"] = &ThreatInfo{
		Score:  85,
		Type:   "spam",
		Source: "test",
	}
	layer.mu.Unlock()

	// IP in CIDR should match
	info, ok := layer.checkIP(net.ParseIP("192.0.2.100"))
	if !ok {
		t.Error("Expected IP in CIDR to match")
	}
	if info.Score != 85 {
		t.Errorf("Expected score 85, got %d", info.Score)
	}

	// IP outside CIDR should not match
	_, ok = layer.checkIP(net.ParseIP("10.0.0.1"))
	if ok {
		t.Error("Expected IP outside CIDR to not match")
	}
}

func TestCheckDomain_Subdomain(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, _ := NewLayer(&cfg)

	// Add parent domain
	layer.AddDomain("example.com", &ThreatInfo{
		Score:  75,
		Type:   "malware",
		Source: "test",
	})

	// Subdomain should match
	info, ok := layer.checkDomain("sub.example.com")
	if !ok {
		t.Error("Expected subdomain to match parent domain")
	}
	if info.Score != 75 {
		t.Errorf("Expected score 75, got %d", info.Score)
	}

	// Unrelated domain should not match
	_, ok = layer.checkDomain("other.com")
	if ok {
		t.Error("Expected unrelated domain to not match")
	}
}

func TestAddRemoveIP(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, _ := NewLayer(&cfg)

	layer.AddIP("10.0.0.1", &ThreatInfo{Score: 50, Type: "test"})

	info, ok := layer.ipCache.Get("10.0.0.1")
	if !ok {
		t.Error("Expected IP to be in cache")
	}
	if info.Score != 50 {
		t.Errorf("Expected score 50, got %d", info.Score)
	}

	layer.RemoveIP("10.0.0.1")
	_, ok = layer.ipCache.Get("10.0.0.1")
	if ok {
		t.Error("Expected IP to be removed from cache")
	}
}

func TestStats(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, _ := NewLayer(&cfg)

	layer.AddIP("10.0.0.1", &ThreatInfo{Score: 50})
	layer.AddIP("10.0.0.2", &ThreatInfo{Score: 50})
	layer.AddDomain("test.com", &ThreatInfo{Score: 50})
	layer.mu.Lock()
	layer.cidrCache["192.0.2.0/24"] = &ThreatInfo{Score: 50}
	layer.mu.Unlock()

	stats := layer.Stats()
	if stats["ip_cache_size"] != 2 {
		t.Errorf("Expected ip_cache_size 2, got %d", stats["ip_cache_size"])
	}
	if stats["domain_cache_size"] != 1 {
		t.Errorf("Expected domain_cache_size 1, got %d", stats["domain_cache_size"])
	}
	if stats["cidr_entries"] != 1 {
		t.Errorf("Expected cidr_entries 1, got %d", stats["cidr_entries"])
	}
}

func TestCacheLRU(t *testing.T) {
	cache := NewCache(3, 10*time.Minute)

	// Add 3 items
	cache.Set("a", &ThreatInfo{Score: 1})
	cache.Set("b", &ThreatInfo{Score: 2})
	cache.Set("c", &ThreatInfo{Score: 3})

	// Add 4th item - should evict oldest
	cache.Set("d", &ThreatInfo{Score: 4})

	// 'a' should be evicted
	_, ok := cache.Get("a")
	if ok {
		t.Error("Expected 'a' to be evicted")
	}

	// 'b', 'c', 'd' should exist
	if _, ok := cache.Get("b"); !ok {
		t.Error("Expected 'b' to exist")
	}
	if _, ok := cache.Get("c"); !ok {
		t.Error("Expected 'c' to exist")
	}
	if _, ok := cache.Get("d"); !ok {
		t.Error("Expected 'd' to exist")
	}
}

func TestCacheTTL(t *testing.T) {
	cache := NewCache(100, 50*time.Millisecond)

	cache.Set("test", &ThreatInfo{Score: 50})

	// Should exist immediately
	_, ok := cache.Get("test")
	if !ok {
		t.Error("Expected item to exist")
	}

	// Wait for TTL
	time.Sleep(100 * time.Millisecond)

	// Should be expired
	_, ok = cache.Get("test")
	if ok {
		t.Error("Expected item to be expired")
	}
}

func TestParseJSONL(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Format: "jsonl"})

	jsonl := `{"ip": "192.0.2.1", "score": 90, "type": "malware_c2", "source": "test"}
{"cidr": "10.0.0.0/8", "score": 80, "type": "internal", "source": "internal"}
{"domain": "evil.com", "score": 95, "type": "phishing", "source": "phishtank"}
# comment
`

	entries, err := fm.parseJSONL(strings.NewReader(jsonl))
	if err != nil {
		t.Fatalf("parseJSONL failed: %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("Expected 3 valid entries, got %d", len(entries))
	}

	// Check first entry
	if entries[0].IP != "192.0.2.1" {
		t.Errorf("Expected IP 192.0.2.1, got %s", entries[0].IP)
	}
	if entries[0].Info.Score != 90 {
		t.Errorf("Expected score 90, got %d", entries[0].Info.Score)
	}
}

func TestParseCSV(t *testing.T) {
	fm := NewFeedManager(FeedConfig{Format: "csv"})

	csv := `# comment
192.0.2.1,90,malware_c2,test
10.0.0.0/8,80,internal,local
evil.com,95,phishing,phishtank
`

	entries, err := fm.parseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parseCSV failed: %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("Expected 3 entries, got %d", len(entries))
	}

	// Check CIDR entry
	if entries[1].CIDR != "10.0.0.0/8" {
		t.Errorf("Expected CIDR 10.0.0.0/8, got %s", entries[1].CIDR)
	}
}

func TestLayer_StartStop(t *testing.T) {
	cfg := Config{Enabled: true}
	layer, _ := NewLayer(&cfg)
	layer.Start()
	layer.Start() // idempotent
	layer.Stop()
	// Should not panic
}

// Benchmark
func BenchmarkProcess(b *testing.B) {
	cfg := Config{
		Enabled: true,
		IPReputation: IPRepConfig{
			Enabled:        true,
			BlockMalicious: true,
			ScoreThreshold: 70,
		},
	}
	layer, _ := NewLayer(&cfg)

	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		layer.AddIP(net.IP{192, 0, 2, byte(i)}.String(), &ThreatInfo{Score: 50})
	}

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("10.0.0.1"),
		Headers:  map[string][]string{"Host": {"example.com"}},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		layer.Process(ctx)
	}
}
