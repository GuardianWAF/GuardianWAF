package docker

// Regression tests for the network-fallback selection contract (round
// round69-docker-network-flap). Container.NetworkSettings.Networks is a Go
// map, so DiscoverFromContainers' "fallback to any network" branch ranged the
// map directly and took the first entry with a non-empty IPAddress — map
// iteration order is randomized per call, so a container whose configured
// network is missing (or has no IP) got a different IPAddress (and therefore
// TargetURL and the proxy route the watcher rebuilds each sync) on every
// call. The fallback now sorts network names and takes the first with an IP,
// mirroring autoDetectPort's deterministic-selection contract: same
// container, same network set ⇒ same IPAddress on every sync.

import (
	"testing"
)

func networkFallbackFixture(networks map[string]NetworkInfo) []Container {
	c := Container{
		ID:     "abc123def456",
		Names:  []string{"/web"},
		State:  "running",
		Labels: map[string]string{"gwaf.enable": "true", "gwaf.host": "app.example.com"},
	}
	c.NetworkSettings.Networks = networks
	return []Container{c}
}

func TestNetworkFallbackIsDeterministic(t *testing.T) {
	// Neither network is the configured "bridge", so the fallback fires. The
	// alphabetically-first network with an IP ("backend") must win on every
	// call — pre-fix this flipped between 10.0.0.5 and 10.1.0.5.
	networks := map[string]NetworkInfo{
		"frontend": {IPAddress: "10.1.0.5"},
		"backend":  {IPAddress: "10.0.0.5"},
	}

	wantURL := ""
	for range 100 {
		svcs := DiscoverFromContainers(networkFallbackFixture(networks), "gwaf", "bridge")
		if len(svcs) != 1 {
			t.Fatalf("expected 1 discovered service per call, got %d", len(svcs))
		}
		if svcs[0].IPAddress != "10.0.0.5" {
			t.Fatalf("network fallback selected %q; want the sorted-first network with an IP (backend → 10.0.0.5)", svcs[0].IPAddress)
		}
		if wantURL == "" {
			wantURL = svcs[0].TargetURL()
		} else if svcs[0].TargetURL() != wantURL {
			t.Fatalf("TargetURL is nondeterministic across calls: %q vs %q", wantURL, svcs[0].TargetURL())
		}
	}
	if wantURL != "http://10.0.0.5:80" {
		t.Fatalf("unexpected TargetURL %q; want http://10.0.0.5:80", wantURL)
	}
}

func TestRequestedNetworkPreferredOverSortedFallback(t *testing.T) {
	// The configured-network lookup must keep priority over the sorted
	// fallback: "alpha" sorts first, but "bridge" is the requested network.
	networks := map[string]NetworkInfo{
		"alpha":  {IPAddress: "10.0.0.5"},
		"bridge": {IPAddress: "172.17.0.9"},
	}

	svcs := DiscoverFromContainers(networkFallbackFixture(networks), "gwaf", "bridge")
	if len(svcs) != 1 {
		t.Fatalf("expected 1 discovered service, got %d", len(svcs))
	}
	if svcs[0].IPAddress != "172.17.0.9" {
		t.Fatalf("configured network not preferred: selected %q, want bridge IP 172.17.0.9", svcs[0].IPAddress)
	}
}

func TestNetworkFallbackSkipsEmptyIPs(t *testing.T) {
	// A listed network with no assigned IP must be skipped in sorted order.
	networks := map[string]NetworkInfo{
		"aaa": {IPAddress: ""},
		"zzz": {IPAddress: "10.2.0.7"},
	}

	svcs := DiscoverFromContainers(networkFallbackFixture(networks), "gwaf", "bridge")
	if len(svcs) != 1 {
		t.Fatalf("expected 1 discovered service, got %d", len(svcs))
	}
	if svcs[0].IPAddress != "10.2.0.7" {
		t.Fatalf("empty-IP network not skipped: selected %q, want zzz IP 10.2.0.7", svcs[0].IPAddress)
	}
}

func TestNoNetworkWithIPDropsService(t *testing.T) {
	// Existing inclusion gate: no network with an IP ⇒ no IPAddress ⇒ the
	// container yields no service.
	networks := map[string]NetworkInfo{
		"aaa": {IPAddress: ""},
		"zzz": {IPAddress: ""},
	}

	svcs := DiscoverFromContainers(networkFallbackFixture(networks), "gwaf", "bridge")
	if len(svcs) != 0 {
		t.Fatalf("expected 0 discovered services when no network has an IP, got %d (%+v)", len(svcs), svcs)
	}
}
