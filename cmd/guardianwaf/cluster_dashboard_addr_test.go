package main

import (
	"net"
	"strings"
	"testing"
)

// Regression (new-series round 1): setupClusterRuntime advertised the node's
// dashboard address to the cluster as "http://" + cfg.Dashboard.Listen. The
// dashboard listen address is a BIND address and defaults to 0.0.0.0:9443, so
// every follower's 307 leader-redirect pointed clients at the unspecified
// address: a client dialing 0.0.0.0 reaches its OWN machine (the follower
// again), producing a redirect loop until the client's redirect cap —
// cluster-wide ban/unban failed from every follower. The advertised host must
// be reachable from other nodes: a wildcard listen must fall back to the Raft
// bind address's host (operators configure a real IP there).

func TestClusterDashboardAdvertisementReachable(t *testing.T) {
	cases := []struct {
		name            string
		dashListen      string
		raftBind        string
		want            string
		expectReachable bool
	}{
		{
			name:            "wizard default: wildcard listen falls back to raft host",
			dashListen:      "0.0.0.0:9443",
			raftBind:        "10.0.0.2:7000",
			want:            "http://10.0.0.2:9443",
			expectReachable: true,
		},
		{
			name:            "IPv6 wildcard listen falls back to raft host",
			dashListen:      "[::]:9443",
			raftBind:        "10.0.0.2:7000",
			want:            "http://10.0.0.2:9443",
			expectReachable: true,
		},
		{
			name:            "explicit listen host is kept",
			dashListen:      "10.0.0.3:9443",
			raftBind:        "10.0.0.2:7000",
			want:            "http://10.0.0.3:9443",
			expectReachable: true,
		},
		{
			name:            "loopback listen is kept (local dashboard)",
			dashListen:      "127.0.0.1:9443",
			raftBind:        "10.0.0.2:7000",
			want:            "http://127.0.0.1:9443",
			expectReachable: true,
		},
		{
			name:       "both wildcard: no reachable host derivable, listen kept as-is",
			dashListen: "0.0.0.0:9443",
			raftBind:   "0.0.0.0:7000",
			want:       "http://0.0.0.0:9443",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := "http://" + clusterDashboardAdvertiseAddr(tc.dashListen, tc.raftBind)
			if got != tc.want {
				t.Fatalf("FAIL: dashboard advertisement %q is not reachable from other cluster nodes (want %q) — followers 307-redirect ban clients to this address and the client dials its own machine, looping until the redirect cap", got, tc.want)
			}
			if !tc.expectReachable {
				return
			}
			host, _, err := net.SplitHostPort(strings.TrimPrefix(got, "http://"))
			if err != nil {
				t.Fatalf("FAIL: advertisement %q is not host:port: %v", got, err)
			}
			if host == "0.0.0.0" || host == "::" {
				t.Fatalf("FAIL: advertisement %q uses the unspecified address as a destination", got)
			}
		})
	}
}
