package docker

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// Regression (hunt catalog-closure round): BuildConfig documented "Deep copy
// static config" but implemented `merged := *staticCfg` — a shallow copy.
// addVHostRoute's existing-vhost branch assigns cfg.VirtualHosts[i].Routes
// directly, writing the new slice header through the SHARED backing array
// into the operator's static config. cmd/guardianwaf/docker_runtime.go
// re-passes the SAME base cfg on every watcher sync (the SetOnChange closure
// captures it once), so each sync accumulated another duplicate of the
// discovered route in the operator's base config, and the spare capacity of
// staticCfg.Upstreams held the merged upstream where a later static append
// would clobber it.

func staticConfigWithVHost() *config.Config {
	// Build the upstreams slice with spare capacity (cap > len) so the
	// append-aliasing corruption mode is observable deterministically.
	ups := make([]config.UpstreamConfig, 0, 4)
	ups = append(ups, config.UpstreamConfig{
		Name:         "static-api",
		LoadBalancer: "round_robin",
		Targets:      []config.TargetConfig{{URL: "http://10.0.0.10:8080", Weight: 1}},
	})
	return &config.Config{
		Upstreams: ups,
		VirtualHosts: []config.VirtualHostConfig{
			{Domains: []string{"app.example.com"}, Routes: []config.RouteConfig{{Path: "/", Upstream: "static-api"}}},
		},
	}
}

func discoveredAppService() []DiscoveredService {
	return []DiscoveredService{{
		ContainerID:   "abc123def456",
		ContainerName: "app",
		Host:          "app.example.com",
		Path:          "/",
		Port:          8081,
		IPAddress:     "172.17.0.5",
		Weight:        1,
		LBStrategy:    "round_robin",
		UpstreamName:  "docker-app",
		Status:        "running",
	}}
}

// The static config must be untouched by a BuildConfig call: same route
// count on the operator's vhost, and a later append to the operator's
// upstreams must not clobber the merged upstream sitting in shared spare
// capacity.
func TestBuildConfigDoesNotMutateStaticConfig(t *testing.T) {
	staticCfg := staticConfigWithVHost()
	beforeRoutes := len(staticCfg.VirtualHosts[0].Routes)
	beforeUpstreams := len(staticCfg.Upstreams)

	merged := BuildConfig(discoveredAppService(), staticCfg)

	if got := len(staticCfg.VirtualHosts[0].Routes); got != beforeRoutes {
		t.Fatalf("FAIL: BuildConfig mutated the static config's vhost routes (%d -> %d) — the shallow copy aliases the operator's config", beforeRoutes, got)
	}
	if got := len(staticCfg.Upstreams); got != beforeUpstreams {
		t.Fatalf("FAIL: BuildConfig mutated the static config's upstreams (%d -> %d)", beforeUpstreams, got)
	}

	// The spare-capacity corruption mode: a later append by the config owner
	// writes into the shared backing array. The merged upstream that
	// BuildConfig placed at index beforeUpstreams must survive it.
	staticCfg.Upstreams = append(staticCfg.Upstreams, config.UpstreamConfig{Name: "added-later"})
	if got := merged.Upstreams[beforeUpstreams].Name; got == "added-later" {
		t.Fatalf("FAIL: a later append to the static config clobbered the merged upstream at index %d — BuildConfig aliases the static backing array", beforeUpstreams)
	}

	// The merged view still contains both the static and the discovered
	// upstreams.
	if len(merged.Upstreams) != beforeUpstreams+1 {
		t.Fatalf("FAIL: merged upstreams = %d, want %d (static + discovered)", len(merged.Upstreams), beforeUpstreams+1)
	}
}

// Repeated watcher syncs against the same base config must produce identical
// merged output — the discovered route must not accumulate in the operator's
// static config between syncs.
func TestBuildConfigRepeatedSyncsDoNotAccumulateRoutes(t *testing.T) {
	staticCfg := staticConfigWithVHost()
	services := discoveredAppService()

	first := BuildConfig(services, staticCfg)
	routesFirst := len(first.VirtualHosts[0].Routes)

	second := BuildConfig(services, staticCfg)
	routesSecond := len(second.VirtualHosts[0].Routes)

	if routesFirst != routesSecond {
		t.Fatalf("FAIL: repeated syncs accumulate routes in the merged config (%d then %d) — the static config is being mutated across syncs", routesFirst, routesSecond)
	}
}
