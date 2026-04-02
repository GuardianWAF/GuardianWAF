package integration

import (
	"fmt"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection/sqli"
	"github.com/guardianwaf/guardianwaf/internal/layers/ipacl"
	"github.com/guardianwaf/guardianwaf/internal/layers/ratelimit"
	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
)

func BenchmarkEngine_BenignRequest(b *testing.B) {
	eng, _ := setupIntegrationEngine(b)
	defer eng.Close()

	req := httptest.NewRequest("GET", "/hello?name=world", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		eng.Check(req)
	}
}

func BenchmarkEngine_AttackRequest(b *testing.B) {
	eng, _ := setupIntegrationEngine(b)
	defer eng.Close()

	req := httptest.NewRequest("GET", "/search?q='+OR+1%3D1+--", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		eng.Check(req)
	}
}

func BenchmarkEngine_XSSRequest(b *testing.B) {
	eng, _ := setupIntegrationEngine(b)
	defer eng.Close()

	req := httptest.NewRequest("GET", "/page?q=%3Cscript%3Ealert(1)%3C/script%3E", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0")

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		eng.Check(req)
	}
}

func BenchmarkSQLiTokenizer(b *testing.B) {
	inputs := []struct {
		name  string
		input string
	}{
		{"benign", "SELECT a product FROM our catalog WHERE price < 50"},
		{"simple_sqli", "' OR 1=1 --"},
		{"union_sqli", "' UNION SELECT username, password FROM users --"},
		{"complex_sqli", "1' AND (SELECT COUNT(*) FROM (SELECT CONCAT(0x7e,(SELECT @@version),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --"},
	}

	for _, tc := range inputs {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				sqli.Tokenize(tc.input)
			}
		})
	}
}

func BenchmarkSQLiDetect(b *testing.B) {
	inputs := []struct {
		name  string
		input string
	}{
		{"benign", "hello world normal query"},
		{"sqli_tautology", "' OR 1=1 --"},
		{"sqli_union", "' UNION SELECT 1,2,3 --"},
	}

	for _, tc := range inputs {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				sqli.Detect(tc.input, "query")
			}
		})
	}
}

func BenchmarkRadixTree_Lookup(b *testing.B) {
	tree := ipacl.NewRadixTree()

	// Insert 10K entries: /24 CIDRs
	for i := 0; i < 256; i++ {
		for j := 0; j < 40; j++ {
			cidr := fmt.Sprintf("%d.%d.0.0/24", i, j)
			if err := tree.Insert(cidr, true); err != nil {
				b.Fatalf("Insert %s: %v", cidr, err)
			}
		}
	}

	lookupIP := net.ParseIP("128.20.0.42")

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		tree.Lookup(lookupIP)
	}
}

func BenchmarkRadixTree_Insert(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		tree := ipacl.NewRadixTree()
		for i := 0; i < 100; i++ {
			cidr := fmt.Sprintf("10.%d.%d.0/24", i/10, i%10)
			_ = tree.Insert(cidr, true)
		}
	}
}

func BenchmarkTokenBucket(b *testing.B) {
	bucket := ratelimit.NewTokenBucket(100, 100)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		bucket.Allow()
	}
}

func BenchmarkNormalizeAll(b *testing.B) {
	inputs := []struct {
		name  string
		input string
	}{
		{"plain", "/hello/world?name=test"},
		{"url_encoded", "%27%20OR%201%3D1%20--%20"},
		{"double_encoded", "%252527%2520OR%25201%253D1"},
		{"unicode", "\uff27\uff35\uff21\uff32\uff24\uff29\uff21\uff2e"},
		{"html_entities", "&lt;script&gt;alert(1)&lt;/script&gt;"},
		{"path_traversal", "/foo/../../../etc/passwd"},
	}

	for _, tc := range inputs {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				sanitizer.NormalizeAll(tc.input)
			}
		})
	}
}

func BenchmarkDetectionLayer_Process(b *testing.B) {
	cfg := config.DefaultConfig()
	cfg.Events.Storage = "memory"

	store := events.NewMemoryStore(1000)
	bus := events.NewEventBus()
	eng, err := engine.NewEngine(cfg, store, bus)
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	san := newSanitizer()
	eng.AddLayer(engine.OrderedLayer{Layer: san, Order: engine.OrderSanitizer})

	detLayer := detection.NewLayer(detection.Config{
		Enabled: true,
		Detectors: map[string]detection.DetectorConfig{
			"sqli": {Enabled: true, Multiplier: 1.0},
			"xss":  {Enabled: true, Multiplier: 1.0},
			"lfi":  {Enabled: true, Multiplier: 1.0},
			"cmdi": {Enabled: true, Multiplier: 1.0},
			"xxe":  {Enabled: true, Multiplier: 1.0},
			"ssrf": {Enabled: true, Multiplier: 1.0},
		},
	})
	eng.AddLayer(engine.OrderedLayer{Layer: detLayer, Order: engine.OrderDetection})

	req := httptest.NewRequest("GET", "/hello?name=world&page=1&sort=asc", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0")

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		eng.Check(req)
	}
}

func BenchmarkEventStore(b *testing.B) {
	store := events.NewMemoryStore(10000)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		ev := engine.Event{
			ID:         "bench-event",
			Timestamp:  time.Now(),
			RequestID:  "req-1",
			ClientIP:   "1.2.3.4",
			Method:     "GET",
			Path:       "/hello",
			Action:     engine.ActionPass,
			Score:      0,
			StatusCode: 200,
		}
		_ = store.Store(ev)
	}
}

func BenchmarkEngine_FullPipeline_MultiParam(b *testing.B) {
	eng, _ := setupIntegrationEngine(b)
	defer eng.Close()

	req := httptest.NewRequest("GET", "/api/search?q=hello&page=1&sort=name&filter=active&limit=20", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		eng.Check(req)
	}
}

func BenchmarkEngine_Parallel(b *testing.B) {
	eng, _ := setupIntegrationEngine(b)
	defer eng.Close()

	req := httptest.NewRequest("GET", "/hello?name=world", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header.Set("User-Agent", "Mozilla/5.0")

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			eng.Check(req)
		}
	})
}
