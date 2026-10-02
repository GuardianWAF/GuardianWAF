package clustersync

// Regression: a replicated ban must be keyed by the canonical net.IP.String().
//
// ReplicatedStore was written with the raw string the operator supplied and
// read with ip.String() by the WAF pipeline
// (internal/layers/ipacl/ipacl.go — l.clusterStore.IsBanned(ip.String())).
// The two disagree whenever the operator's spelling is not already canonical:
//
//	"2001:0db8:0000:0000:0000:0000:0000:0001"  read as "2001:db8::1"
//	"::ffff:10.0.0.1"                          read as "10.0.0.1"
//	"2001:DB8::1"                              read as "2001:db8::1"
//
// An unparseable spelling ("010.0.0.1", "10.0.0.1 ") was worse: the read side
// derives its key from a parsed net.IP, so that key could never be produced.
//
// In every case the ban was accepted with HTTP 200, replicated to every node
// over Raft, and reported active by BannedIPs()/the dashboard — while never
// matching a single request. A cluster-wide security control silently did
// nothing. NewBanCommand and applyBanIP now normalize with net.ParseIP and
// reject unparseable addresses; applyBanIP also guards the raft-replay seam,
// mirroring the negative-duration check above it.

import (
	"net"
	"testing"
	"time"
)

// banViaApply applies a ban exactly as the Raft state machine does.
func banViaApply(t *testing.T, s *ReplicatedStore, ip string, d time.Duration) error {
	t.Helper()
	cmd, err := NewBanCommand(ip, d)
	if err != nil {
		return err
	}
	return s.Apply(cmd)
}

func TestBanCommandCanonicalizesNonCanonicalSpellings(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"::ffff:10.0.0.1", "10.0.0.1"},
		{"2001:DB8::1", "2001:db8::1"},
		{"203.0.113.9", "203.0.113.9"},
	} {
		cmd, err := NewBanCommand(tc.input, 0)
		if err != nil {
			t.Fatalf("NewBanCommand(%q) rejected a valid address: %v", tc.input, err)
		}
		var p BanIPPayload
		if err := cmd.DecodePayload(&p); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if p.IP != tc.want {
			t.Errorf("NewBanCommand(%q) stored IP %q, want canonical %q", tc.input, p.IP, tc.want)
		}
	}
}

func TestBanCommandRejectsUnparseableIP(t *testing.T) {
	for _, bad := range []string{"010.0.0.1", "10.0.0.1 ", "not-an-ip", "", "1.2.3"} {
		if _, err := NewBanCommand(bad, 0); err == nil {
			t.Errorf("NewBanCommand(%q) accepted an address net.ParseIP rejects — it would "+
				"become a ban that can never match", bad)
		}
	}
}

// DEFECT: a non-canonical spelling must block the address it names.
func TestClusterBanMatchesNonCanonicalIPv6(t *testing.T) {
	s := NewReplicatedStore()
	const expanded = "2001:0db8:0000:0000:0000:0000:0000:0001"

	if err := banViaApply(t, s, expanded, 0); err != nil {
		t.Fatalf("apply: %v", err)
	}
	readKey := net.ParseIP(expanded).String()
	if !s.IsBanned(readKey) {
		t.Fatalf("banned %q but IsBanned(%q) is false — the replicated ban must be keyed "+
			"by the canonical form the WAF pipeline looks up", expanded, readKey)
	}
}

func TestClusterBanMatchesIPV4MappedIPv6(t *testing.T) {
	s := NewReplicatedStore()
	const mapped = "::ffff:10.0.0.1"

	if err := banViaApply(t, s, mapped, 0); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !s.IsBanned(net.ParseIP(mapped).String()) {
		t.Fatalf("banned %q but the pipeline's key %q does not match", mapped,
			net.ParseIP(mapped).String())
	}
}

// CONTROL: a canonical IPv4 ban matches, and a neighbour does not.
func TestCanonicalIPv4BanMatchesExactly(t *testing.T) {
	s := NewReplicatedStore()
	if err := banViaApply(t, s, "203.0.113.9", 0); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !s.IsBanned(net.ParseIP("203.0.113.9").String()) {
		t.Fatal("a canonical IPv4 ban must match")
	}
	if s.IsBanned(net.ParseIP("203.0.113.10").String()) {
		t.Fatal("an unbanned address was reported as banned")
	}
}

// CONTROL: BannedIPs must only ever report keys IsBanned can match — the
// dashboard reads it, so a non-canonical key there would advertise an
// enforcement that never happens.
func TestBannedIPsKeysAreAlwaysMatchable(t *testing.T) {
	s := NewReplicatedStore()
	for _, raw := range []string{
		"2001:0db8:0000:0000:0000:0000:0000:0001",
		"::ffff:10.0.0.1",
		"192.0.2.44",
	} {
		if err := banViaApply(t, s, raw, 0); err != nil {
			t.Fatalf("apply %q: %v", raw, err)
		}
	}
	for _, b := range s.BannedIPs() {
		if b.IP != net.ParseIP(b.IP).String() {
			t.Errorf("BannedIPs() reported non-canonical key %q; IsBanned(%q) would be false",
				b.IP, net.ParseIP(b.IP).String())
		}
		if !s.IsBanned(b.IP) {
			t.Errorf("BannedIPs() reported %q but IsBanned(%q) is false", b.IP, b.IP)
		}
	}
}

// CONTROL: normalization must not disturb expiry semantics.
func TestCanonicalBanStillExpires(t *testing.T) {
	s := NewReplicatedStore()
	if err := banViaApply(t, s, "198.51.100.7", 50*time.Millisecond); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !s.IsBanned("198.51.100.7") {
		t.Fatal("ban not active immediately after apply")
	}
	time.Sleep(80 * time.Millisecond)
	if s.IsBanned("198.51.100.7") {
		t.Fatal("expired ban still reported as banned")
	}
}
