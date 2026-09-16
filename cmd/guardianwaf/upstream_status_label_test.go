package main

import (
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/proxy"
)

// Regression (round 2026-09-16): UpstreamConfig.Name is mandatory
// (internal/config/validate.go rejects an empty name) and is the identity
// operators route by, but the route builder dropped it, so
// Router.AllUpstreamStatus surfaced the route path prefix as the upstream
// identity: guardianwaf_upstream_* metrics were labeled with the prefix
// (e.g. upstream="/api") regardless of the configured name, and two virtual
// hosts sharing a prefix behind two different upstreams emitted duplicate
// Prometheus series label sets, which a scrape rejects or overwrites.

func upstreamLabelTestConfig() *config.Config {
	yes := true
	cfg := config.DefaultConfig()
	cfg.AllowPrivateUpstreams = &yes
	cfg.Upstreams = []config.UpstreamConfig{
		{
			Name:         "payments-api",
			Targets:      []config.TargetConfig{{URL: "http://127.0.0.1:1", Weight: 1}},
			LoadBalancer: "round_robin",
		},
		{
			Name:         "search-api",
			Targets:      []config.TargetConfig{{URL: "http://127.0.0.1:2", Weight: 1}},
			LoadBalancer: "round_robin",
		},
	}
	// Same path prefix under two virtual hosts, dispatched to two different
	// upstreams: the identities must stay distinct end to end.
	cfg.VirtualHosts = []config.VirtualHostConfig{
		{Domains: []string{"pay.example.com"}, Routes: []config.RouteConfig{{Path: "/api", Upstream: "payments-api"}}},
		{Domains: []string{"search.example.com"}, Routes: []config.RouteConfig{{Path: "/api", Upstream: "search-api"}}},
	}
	return cfg
}

func upstreamStatusNames(statuses []proxy.UpstreamStatus) []string {
	out := make([]string, 0, len(statuses))
	for _, s := range statuses {
		out = append(out, s.Name)
	}
	sort.Strings(out)
	return out
}

func TestBuildReverseProxy_UpstreamStatusLabelCarriesConfiguredName(t *testing.T) {
	handler, checkers, err := buildReverseProxyStrict(upstreamLabelTestConfig())
	if err != nil {
		t.Fatalf("buildReverseProxyStrict: %v", err)
	}
	defer stopHealthCheckers(checkers)
	router, ok := handler.(*proxy.Router)
	if !ok {
		t.Fatalf("handler is %T, want *proxy.Router", handler)
	}
	defer router.Close()

	statuses := router.AllUpstreamStatus()
	if len(statuses) != 2 {
		t.Fatalf("AllUpstreamStatus returned %d statuses %v, want 2 unique upstreams", len(statuses), upstreamStatusNames(statuses))
	}
	byName := make(map[string]proxy.UpstreamStatus, len(statuses))
	for _, s := range statuses {
		byName[s.Name] = s
	}
	for _, want := range []string{"payments-api", "search-api"} {
		s, found := byName[want]
		if !found {
			t.Fatalf("statuses named %v, missing configured upstream %q", upstreamStatusNames(statuses), want)
		}
		if s.TotalCount != 1 {
			t.Errorf("upstream %q TotalCount = %d, want 1", want, s.TotalCount)
		}
	}

	rr := httptest.NewRecorder()
	writeUpstreamMetrics(rr, statuses)
	exposition := rr.Body.String()
	if !strings.Contains(exposition, "guardianwaf_upstream_") {
		t.Fatalf("exposition contains no guardianwaf_upstream_* series:\n%s", exposition)
	}
	for _, wantLine := range []string{
		"guardianwaf_upstream_targets_total{upstream=\"payments-api\"} 1\n",
		"guardianwaf_upstream_targets_total{upstream=\"search-api\"} 1\n",
	} {
		if !strings.Contains(exposition, wantLine) {
			t.Errorf("exposition missing %q:\n%s", wantLine, exposition)
		}
	}

	// Distinct upstreams must never share a series label set: a Prometheus
	// scrape rejects an exposition with duplicate series.
	seen := make(map[string]int)
	for _, line := range strings.Split(exposition, "\n") {
		if strings.HasPrefix(line, "guardianwaf_upstream_targets_total{") {
			seen[line]++
		}
	}
	for line, n := range seen {
		if n > 1 {
			t.Errorf("duplicate Prometheus series %q emitted %d times", line, n)
		}
	}
}

func TestBuildReverseProxy_UpstreamStatusLabelUniquePrefix(t *testing.T) {
	cfg := upstreamLabelTestConfig()
	cfg.VirtualHosts = nil
	cfg.Routes = []config.RouteConfig{{Path: "/legacy", Upstream: "payments-api"}}

	handler, checkers, err := buildReverseProxyStrict(cfg)
	if err != nil {
		t.Fatalf("buildReverseProxyStrict: %v", err)
	}
	defer stopHealthCheckers(checkers)
	router, ok := handler.(*proxy.Router)
	if !ok {
		t.Fatalf("handler is %T, want *proxy.Router", handler)
	}
	defer router.Close()

	statuses := router.AllUpstreamStatus()
	if len(statuses) != 1 {
		t.Fatalf("AllUpstreamStatus returned %d statuses %v, want 1", len(statuses), upstreamStatusNames(statuses))
	}
	if statuses[0].Name != "payments-api" {
		t.Fatalf("upstream Name = %q, want configured upstream name \"payments-api\"", statuses[0].Name)
	}
}
