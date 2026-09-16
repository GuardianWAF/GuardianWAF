package gossip

import (
	"testing"
	"time"
)

// Regression (round 2026-09-16): applyPiggyback's self-refutation branch and
// Leave() constructed self Member literals without RaftAddr/DashboardAddr.
// MemberList.Add full-replaces the entry when the incarnation is higher
// (shouldReplace), so a refuted suspicion — ordinary packet loss — permanently
// stripped the node's raft/dashboard addresses from its own record locally and
// propagated the degraded record cluster-wide: peers holding the richer
// alive@N view replaced it with the degraded alive@N+1, blanking the
// dashboard's leader-redirect URLs and any RaftAddr consumer. The refutation
// must carry the node's full advertised identity, exactly as NewWithTransport
// registers self.

func refutationTestConfig(id string) Config {
	cfg := DefaultConfig(id, "127.0.0.1:0")
	cfg.Secret = testSecret
	return cfg
}

func findMemberByID(g *Gossip, id string) (Member, bool) {
	for _, m := range g.Members() {
		if m.ID == id {
			return m, true
		}
	}
	return Member{}, false
}

func TestApplyPiggybackRefutationPreservesSelfIdentity(t *testing.T) {
	cfg := refutationTestConfig("node-a")
	cfg.RaftAddr = "10.0.0.1:7947"
	cfg.DashboardAddr = "10.0.0.1:8080"
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer a.Stop()

	if got := a.LocalMember(); got.RaftAddr != "10.0.0.1:7947" || got.DashboardAddr != "10.0.0.1:8080" {
		t.Fatalf("self registration lost identity: raft=%q dash=%q", got.RaftAddr, got.DashboardAddr)
	}

	// A peer announces us suspect at the incarnation they learned from our
	// alive@1 broadcast — the ordinary packet-loss scenario.
	suspect := EncodeMembers([]Member{{ID: "node-a", Addr: a.LocalMember().Addr, Incarnation: 1, State: StateSuspect}})
	a.applyPiggyback(suspect)

	self := a.LocalMember()
	if self.State != StateAlive || self.Incarnation != 2 {
		t.Fatalf("refutation machinery did not refute (state=%v inc=%d)", self.State, self.Incarnation)
	}
	if self.RaftAddr != "10.0.0.1:7947" {
		t.Fatalf("refuted self entry lost RaftAddr: got %q, want %q", self.RaftAddr, "10.0.0.1:7947")
	}
	if self.DashboardAddr != "10.0.0.1:8080" {
		t.Fatalf("refuted self entry lost DashboardAddr: got %q, want %q", self.DashboardAddr, "10.0.0.1:8080")
	}
}

func TestRefutationPropagationPreservesIdentity(t *testing.T) {
	cfgA := refutationTestConfig("node-a")
	cfgA.RaftAddr = "10.0.0.1:7947"
	cfgA.DashboardAddr = "10.0.0.1:8080"
	a, err := New(cfgA)
	if err != nil {
		t.Fatalf("New a: %v", err)
	}
	defer a.Stop()
	b, err := New(refutationTestConfig("node-b"))
	if err != nil {
		t.Fatalf("New b: %v", err)
	}
	defer b.Stop()
	if err := a.Start(); err != nil {
		t.Fatalf("Start a: %v", err)
	}
	if err := b.Start(); err != nil {
		t.Fatalf("Start b: %v", err)
	}

	// B learns A with full identity via the real push-pull join.
	if n := b.Join([]string{a.transport.LocalAddr()}); n == 0 {
		t.Fatalf("B could not join via A over UDP loopback")
	}
	if m, ok := findMemberByID(b, "node-a"); !ok || m.Incarnation != 1 || m.RaftAddr != "10.0.0.1:7947" || m.DashboardAddr != "10.0.0.1:8080" {
		t.Fatalf("B's initial view of A wrong: %+v", m)
	}

	// A refutes a suspect announcement (real production piggyback handler),
	// then disseminates the refutation over the real UDP+HMAC path.
	a.applyPiggyback(EncodeMembers([]Member{{ID: "node-a", Incarnation: 1, State: StateSuspect}}))
	a.disseminate()

	deadline := time.Now().Add(2 * time.Second)
	for {
		m, ok := findMemberByID(b, "node-a")
		if ok && m.Incarnation >= 2 {
			if m.RaftAddr != "10.0.0.1:7947" || m.DashboardAddr != "10.0.0.1:8080" {
				t.Fatalf("B replaced its richer view of A with a degraded refutation: raft=%q dash=%q", m.RaftAddr, m.DashboardAddr)
			}
			return
		}
		if time.Now().After(deadline) {
			if ok {
				t.Fatalf("refutation never propagated (B still holds inc=%d raft=%q dash=%q)", m.Incarnation, m.RaftAddr, m.DashboardAddr)
			}
			t.Fatalf("refutation never propagated (B has no view of A)")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Control: a foreign member's update carries its identity through the same
// encode/decode/apply machinery untouched by the self-refutation literal.
func TestForeignMemberUpdateKeepsIdentity(t *testing.T) {
	b, err := New(refutationTestConfig("node-b"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer b.Stop()

	c := Member{ID: "node-c", Addr: "10.0.0.3:7946", RaftAddr: "10.0.0.3:7947", DashboardAddr: "10.0.0.3:8080", Incarnation: 1, State: StateAlive}
	b.applyPiggyback(EncodeMembers([]Member{c}))

	m, ok := b.members.Get("node-c")
	if !ok {
		t.Fatalf("foreign member not applied")
	}
	if m.RaftAddr != "10.0.0.3:7947" || m.DashboardAddr != "10.0.0.3:8080" {
		t.Fatalf("foreign member lost identity: raft=%q dash=%q", m.RaftAddr, m.DashboardAddr)
	}
}
