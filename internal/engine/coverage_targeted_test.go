package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEngine_Check_EmptyLayersRecordsPassEventAndStats(t *testing.T) {
	e, store, bus := testEngine(t)
	defer e.Close()

	req := testRequest(http.MethodGet, "/empty-layers")
	event := e.Check(req)
	if event == nil {
		t.Fatal("expected non-nil event")
	}
	if event.Action != ActionPass {
		t.Fatalf("expected ActionPass, got %v", event.Action)
	}
	if event.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", event.StatusCode)
	}
	if event.Score != 0 {
		t.Fatalf("expected score 0, got %d", event.Score)
	}
	if store.len() != 1 {
		t.Fatalf("expected 1 stored event, got %d", store.len())
	}
	if bus.publishCount() != 1 {
		t.Fatalf("expected 1 published event, got %d", bus.publishCount())
	}

	stats := e.Stats()
	if stats.TotalRequests != 1 || stats.PassedRequests != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestEngine_PipelineLayers_SkipsNilLayer(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	e.AddLayer(OrderedLayer{Layer: nil, Order: 50})
	e.AddLayer(OrderedLayer{Layer: &passLayer{name: "kept"}, Order: 100})

	layers := e.PipelineLayers()
	if len(layers) != 1 {
		t.Fatalf("expected 1 exported layer, got %#v", layers)
	}
	if layers[0].Name != "kept" || layers[0].Order != 100 {
		t.Fatalf("unexpected layer info: %#v", layers[0])
	}
}

func TestEngine_RecordStatsAndLayerTimings_EdgeCases(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	e.recordStats(ActionChallenge, -1*time.Microsecond)
	e.recordLayerTimings(map[string]time.Duration{
		"":         time.Millisecond,
		"edge":     -1 * time.Microsecond,
		"positive": 1500 * time.Microsecond,
	})

	stats := e.Stats()
	if stats.TotalRequests != 1 {
		t.Fatalf("expected 1 total request, got %d", stats.TotalRequests)
	}
	if stats.ChallengedRequests != 1 {
		t.Fatalf("expected 1 challenged request, got %d", stats.ChallengedRequests)
	}
	if stats.AvgLatencyUs != 0 || stats.LatencySumUs != 0 {
		t.Fatalf("expected zeroed latency for negative duration, got avg=%d sum=%d", stats.AvgLatencyUs, stats.LatencySumUs)
	}
	if len(stats.LayerTiming) != 2 {
		t.Fatalf("expected 2 named layer stats, got %#v", stats.LayerTiming)
	}
	if stats.LayerTiming[0].Layer != "edge" || stats.LayerTiming[0].Count != 1 || stats.LayerTiming[0].DurationSumUs != 0 {
		t.Fatalf("unexpected edge timing stats: %#v", stats.LayerTiming[0])
	}
	if stats.LayerTiming[1].Layer != "positive" || stats.LayerTiming[1].Count != 1 || stats.LayerTiming[1].DurationSumUs != 1500 {
		t.Fatalf("unexpected positive timing stats: %#v", stats.LayerTiming[1])
	}
}

func TestEngine_ExtractClientIP_MethodWrapper(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:4567"

	ip := e.ExtractClientIP(req)
	if ip == nil || ip.String() != "203.0.113.10" {
		t.Fatalf("expected wrapper to return remote IP, got %v", ip)
	}
}

func TestEngine_SetGeoIPStatus_ExposedInStats(t *testing.T) {
	e, _, _ := testEngine(t)
	defer e.Close()

	e.SetGeoIPStatus(true, 1234)
	stats := e.Stats()
	if !stats.GeoIPReady || stats.GeoIPRanges != 1234 {
		t.Fatalf("unexpected geoip stats: %+v", stats)
	}
}

func TestSetGeoIPLookup_NewEventPopulatesCountry(t *testing.T) {
	SetGeoIPLookup(func(ip string) (string, string) {
		if ip != "198.51.100.8" {
			t.Fatalf("unexpected lookup IP %q", ip)
		}
		return "US", "United States"
	})
	defer SetGeoIPLookup(nil)

	req := httptest.NewRequest(http.MethodGet, "/geo", nil)
	req.RemoteAddr = "198.51.100.8:443"
	ctx := AcquireContext(req, 2, 1024)
	defer ReleaseContext(ctx)

	event := NewEvent(ctx, http.StatusOK)
	if event.CountryCode != "US" || event.CountryName != "United States" {
		t.Fatalf("unexpected geo fields: %+v", event)
	}
}

func TestEventHelpers_RedactionAndPaddingEdges(t *testing.T) {
	if got := redactSensitiveQueryParams("plain"); got != "plain" {
		t.Fatalf("expected plain query unchanged, got %q", got)
	}
	if got := redactSensitiveQueryParams("%%%invalid"); got != "%%%invalid" {
		t.Fatalf("expected malformed query unchanged, got %q", got)
	}
	if got := redactSensitiveURL("://bad url"); got != "://bad url" {
		t.Fatalf("expected invalid URL to fall back unchanged, got %q", got)
	}
	if got := padInt2(-5); got != "00" {
		t.Fatalf("expected negative padding to clamp to 00, got %q", got)
	}
}
