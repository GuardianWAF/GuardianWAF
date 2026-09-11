package docker

// Regression tests for the auto-detect port selection contract (round
// round5-docker-port-order). ListContainers converts Docker's ExposedPorts
// MAP in map-iteration order (randomized per run), so any consumer that
// depends on the slice order is nondeterministic. autoDetectPort must select
// the lowest exposed TCP port (falling back to the lowest exposed port of any
// type, then 80) so an unlabeled multi-port container gets a stable
// TargetURL on every sync instead of flapping between ports.

import (
	"testing"
)

func portOrderFixture(ports []ContainerPort) []Container {
	c := Container{
		ID:     "abc123",
		Names:  []string{"/web"},
		State:  "running",
		Labels: map[string]string{"gwaf.enable": "true"},
		Ports:  ports,
	}
	c.NetworkSettings.Networks = map[string]NetworkInfo{
		"bridge": {IPAddress: "172.17.0.5"},
	}
	return []Container{c}
}

func TestAutoDetectPortIsOrderIndependent(t *testing.T) {
	a := autoDetectPort(Container{Ports: []ContainerPort{{PrivatePort: 80, Type: "tcp"}, {PrivatePort: 8080, Type: "tcp"}}})
	b := autoDetectPort(Container{Ports: []ContainerPort{{PrivatePort: 8080, Type: "tcp"}, {PrivatePort: 80, Type: "tcp"}}})
	if a != b {
		t.Fatalf("port selection is order-dependent: %d vs %d", a, b)
	}
	if a != 80 {
		t.Fatalf("expected the lowest TCP port 80, got %d", a)
	}
}

func TestDiscoveredServicePortStableAcrossOrderings(t *testing.T) {
	svcA := DiscoverFromContainers(portOrderFixture([]ContainerPort{
		{PrivatePort: 80, Type: "tcp"},
		{PrivatePort: 8080, Type: "tcp"},
	}), "gwaf", "bridge")
	svcB := DiscoverFromContainers(portOrderFixture([]ContainerPort{
		{PrivatePort: 8080, Type: "tcp"},
		{PrivatePort: 80, Type: "tcp"},
	}), "gwaf", "bridge")

	if len(svcA) != 1 || len(svcB) != 1 {
		t.Fatalf("expected 1 discovered service per ordering, got %d and %d", len(svcA), len(svcB))
	}
	if svcA[0].TargetURL() != svcB[0].TargetURL() {
		t.Fatalf("TargetURL depends on wire order: %q vs %q", svcA[0].TargetURL(), svcB[0].TargetURL())
	}
}

func TestAutoDetectPortPrefersTCPOverUDP(t *testing.T) {
	got := autoDetectPort(Container{Ports: []ContainerPort{{PrivatePort: 53, Type: "udp"}, {PrivatePort: 8080, Type: "tcp"}}})
	if got != 8080 {
		t.Fatalf("expected TCP port 8080 to win over UDP 53, got %d", got)
	}
}

func TestAutoDetectPortFallsBackToLowestAny(t *testing.T) {
	got := autoDetectPort(Container{Ports: []ContainerPort{{PrivatePort: 8053, Type: "udp"}, {PrivatePort: 9053, Type: "udp"}}})
	if got != 8053 {
		t.Fatalf("expected the lowest exposed port 8053, got %d", got)
	}
}

func TestAutoDetectPortDefaultsTo80(t *testing.T) {
	if got := autoDetectPort(Container{}); got != 80 {
		t.Fatalf("expected default port 80 for a container with no exposed ports, got %d", got)
	}
}
