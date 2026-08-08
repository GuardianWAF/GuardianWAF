package integration

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

func BenchmarkEngine_LargeHeaders(b *testing.B) {
	eng, _ := setupIntegrationEngine(b)
	defer eng.Close()

	headerValue := strings.Repeat("a", 512)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		req := httptest.NewRequest("GET", "/api/data", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		for i := 0; i < 100; i++ {
			req.Header.Set(fmt.Sprintf("X-Bench-%03d", i), headerValue)
		}
		eng.Check(req)
	}
}

func BenchmarkEngine_LargeBody(b *testing.B) {
	eng, _ := setupIntegrationEngine(b)
	defer eng.Close()

	body := []byte(strings.Repeat(`{"message":"hello world","value":42}`+"\n", 4096))

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for range b.N {
		req := httptest.NewRequest("POST", "/api/upload", bytes.NewReader(body))
		req.RemoteAddr = "1.2.3.4:12345"
		req.Header.Set("Content-Type", "application/json")
		eng.Check(req)
	}
}

func BenchmarkEngine_GzipBody(b *testing.B) {
	benchmarkCompressedBody(b, "gzip")
}

func BenchmarkEngine_DeflateBody(b *testing.B) {
	benchmarkCompressedBody(b, "deflate")
}

func benchmarkCompressedBody(b *testing.B, encoding string) {
	b.Helper()
	eng, _ := setupIntegrationEngine(b)
	defer eng.Close()

	raw := []byte(strings.Repeat(`{"query":"normal search","page":1}`+"\n", 4096))
	compressed := compressBenchmarkPayload(b, encoding, raw)

	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for range b.N {
		req := httptest.NewRequest("POST", "/api/search", bytes.NewReader(compressed))
		req.RemoteAddr = "1.2.3.4:12345"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", encoding)
		eng.Check(req)
	}
}

func compressBenchmarkPayload(b testing.TB, encoding string, raw []byte) []byte {
	b.Helper()
	var buf bytes.Buffer
	var w io.WriteCloser
	switch encoding {
	case "gzip":
		w = gzip.NewWriter(&buf)
	case "deflate":
		fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
		if err != nil {
			b.Fatalf("flate.NewWriter() error = %v", err)
		}
		w = fw
	default:
		b.Fatalf("unsupported encoding %q", encoding)
	}
	if _, err := w.Write(raw); err != nil {
		b.Fatalf("compress write error = %v", err)
	}
	if err := w.Close(); err != nil {
		b.Fatalf("compress close error = %v", err)
	}
	return buf.Bytes()
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

	detLayer := detection.NewLayer(&detection.Config{
		Enabled: true,
		Detectors: map[string]detection.DetectorConfig{
			"sqli":         {Enabled: true, Multiplier: 1.0},
			"xss":          {Enabled: true, Multiplier: 1.0},
			"lfi":          {Enabled: true, Multiplier: 1.0},
			"cmdi":         {Enabled: true, Multiplier: 1.0},
			"xxe":          {Enabled: true, Multiplier: 1.0},
			"ssrf":         {Enabled: true, Multiplier: 1.0},
			"ssti":         {Enabled: true, Multiplier: 1.0},
			"nosqli":       {Enabled: true, Multiplier: 1.0},
			"smuggling":    {Enabled: true, Multiplier: 1.0},
			"openredirect": {Enabled: true, Multiplier: 1.0},
			"graphql":      {Enabled: true, Multiplier: 1.0},
		},
		GraphQLMaxDepth:           10,
		GraphQLMaxComplexity:      1000,
		GraphQLBlockIntrospection: true,
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

func BenchmarkEventStore_HighEventRate(b *testing.B) {
	store := events.NewMemoryStore(100000)
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

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = store.Store(ev)
		}
	})
}

func BenchmarkRouteLookup_ManyRoutes(b *testing.B) {
	vhosts := make([]config.VirtualHostConfig, 100)
	for i := range vhosts {
		routes := make([]config.RouteConfig, 100)
		for j := range routes {
			routes[j] = config.RouteConfig{
				Path:     fmt.Sprintf("/tenant-%03d/service-%03d", i, j),
				Upstream: fmt.Sprintf("backend-%03d-%03d", i, j),
			}
		}
		vhosts[i] = config.VirtualHostConfig{
			Domains: []string{fmt.Sprintf("tenant-%03d.example.com", i)},
			Routes:  routes,
		}
	}
	req := httptest.NewRequest("GET", "https://tenant-099.example.com/tenant-099/service-099/orders", nil)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		vh := config.FindVirtualHost(vhosts, req.Host)
		if vh == nil {
			b.Fatal("virtual host not found")
		}
		if route := findBenchmarkRoute(vh.Routes, req); route == nil {
			b.Fatal("route not found")
		}
	}
}

func findBenchmarkRoute(routes []config.RouteConfig, req *http.Request) *config.RouteConfig {
	var best *config.RouteConfig
	for i := range routes {
		route := &routes[i]
		if strings.HasPrefix(req.URL.Path, route.Path) && (best == nil || len(route.Path) > len(best.Path)) {
			best = route
		}
	}
	return best
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

	// Clone request inside the parallel loop to avoid body-sharing race.
	// AcquireContext reads r.Body and replaces it with a replayReadCloser,
	// so sharing a single *httptest.Request across goroutines causes
	// MultiReader to panic on the already-consumed second read.
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		req := httptest.NewRequest("GET", "/hello?name=world", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		req.Header.Set("User-Agent", "Mozilla/5.0")
		for pb.Next() {
			eng.Check(req)
		}
	})
}
