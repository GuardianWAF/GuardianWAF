// Package quality measures detection quality through the full standalone
// pipeline (every layer the default config enables), the way a production
// request sees it. It complements the per-detector corpus test in
// internal/layers/detection, which exercises the detection layer alone.
package quality

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/events"
	"github.com/guardianwaf/guardianwaf/internal/runtime/layerregistry"
)

// Corpus files declare where their samples are placed in a request with a
// header line such as "# placement: query,form". Supported placements:
//
//	query  GET  /search?q=<sample>
//	form   POST /comments with comment=<sample> (urlencoded)
//	multipart POST /profile: multipart/form-data with comment=<sample> beside
//	         a text field and a PNG upload
//	json   POST /api/items with the sample as the JSON body
//	cookie GET /account with Cookie: pref=<URL-encoded sample>
//	cookie_raw GET /account with the sample line (name=value) as a cookie
//	header GET /api/items with X-Search-Term: <sample>
//	header_raw GET /api/items with the sample line (Name: value) as a header
//	path   GET  /<sample>
//	xml      POST /api/import with the sample as an XML body
//	redirect GET  /login?next=<sample>
//	file     GET  /download?file=<sample>
//	fetch    GET  /preview?url=<sample>
//	graphql  POST /graphql with {"query": <sample>} (lines already in that form are sent as-is)
var placements = map[string]func(sample string) *http.Request{
	"query": func(s string) *http.Request {
		return httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape(s), nil)
	},
	"form": func(s string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/comments", strings.NewReader("comment="+url.QueryEscape(s)))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	},
	"multipart": func(s string) *http.Request {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		_ = w.WriteField("title", "hello")
		_ = w.WriteField("comment", s)
		fw, _ := w.CreateFormFile("avatar", "me.png")
		_, _ = fw.Write([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"))
		_ = w.Close()
		r := httptest.NewRequest(http.MethodPost, "/profile", &buf)
		r.Header.Set("Content-Type", w.FormDataContentType())
		return r
	},
	"cookie": func(s string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/account", nil)
		r.Header.Set("Cookie", "theme=dark; pref="+url.QueryEscape(s))
		return r
	},
	"cookie_raw": func(s string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/account", nil)
		r.Header.Set("Cookie", "theme=dark; "+s)
		return r
	},
	"header": func(s string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/items", nil)
		r.Header.Set("X-Search-Term", s)
		return r
	},
	"header_raw": func(s string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/items", nil)
		name, value, _ := strings.Cut(s, ":")
		r.Header.Add(strings.TrimSpace(name), strings.TrimSpace(value))
		return r
	},
	"json": func(s string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/items", strings.NewReader(s))
		r.Header.Set("Content-Type", "application/json")
		return r
	},
	"path": func(s string) *http.Request {
		return httptest.NewRequest(http.MethodGet, "/"+strings.TrimPrefix(s, "/"), nil)
	},
	"redirect": func(s string) *http.Request {
		return httptest.NewRequest(http.MethodGet, "/login?next="+url.QueryEscape(s), nil)
	},
	"file": func(s string) *http.Request {
		return httptest.NewRequest(http.MethodGet, "/download?file="+url.QueryEscape(s), nil)
	},
	"fetch": func(s string) *http.Request {
		return httptest.NewRequest(http.MethodGet, "/preview?url="+url.QueryEscape(s), nil)
	},
	"graphql": func(s string) *http.Request {
		// Some corpus lines are already full request bodies; wrapping them
		// again would hide the query inside a string.
		body := []byte(s)
		if !strings.HasPrefix(strings.TrimSpace(s), `{"query"`) {
			body, _ = json.Marshal(map[string]string{"query": s})
		}
		r := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		return r
	},
	"jsonfield": func(s string) *http.Request {
		body, _ := json.Marshal(map[string]string{"username": s, "comment": "hello"})
		r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		return r
	},
	"xml": func(s string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/import", strings.NewReader(s))
		r.Header.Set("Content-Type", "application/xml")
		return r
	},
}

// attackPlacements places the shared attack corpora (testdata/attacks, which
// predate placement headers) where each attack class is delivered.
var attackPlacements = map[string][]string{
	"xxe":          {"xml"},
	"graphql":      {"graphql"},
	"openredirect": {"redirect"},
	"lfi":          {"file", "query"},
	"ssrf":         {"fetch", "query"},
}

// browserHeaders makes requests look like a real browser so bot detection
// does not add score that a production user would never see.
func browserHeaders(r *http.Request, n int) {
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	r.Header.Set("Accept-Language", "en-US,en;q=0.9,tr;q=0.8")
	r.Header.Set("Accept-Encoding", "gzip, deflate, br")
	r.Header.Set("Referer", "https://shop.example.com/")
	// A distinct client per sample keeps rate limiting out of the measurement.
	r.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:40000", n>>16&255, n>>8&255, n&255)
}

func newPipeline(t testing.TB) *engine.Engine {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Events.Storage = "memory"
	// Threat-intel feeds need the network; the corpus measures content
	// detection only.
	cfg.WAF.ThreatIntel.Enabled = false
	store := events.NewMemoryStore(1000)
	eng, err := engine.NewEngine(cfg, store, events.NewEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { eng.Close() })
	for _, d := range layerregistry.DefaultRegistry() {
		layer, ok, err := layerregistry.BuildLayer(d.Name, cfg)
		if err != nil {
			t.Fatalf("build %s: %v", d.Name, err)
		}
		if ok {
			eng.AddLayer(layer)
		}
	}
	return eng
}
