package gossip

import (
	"testing"
)

// MemberList.PurgeDead's documented contract is "called periodically by the
// prober" (member.go) — probeCycle is that periodic point. A dead member must
// leave the membership view within one probe cycle: otherwise dead entries
// accumulate in AllMembers and in every push-pull payload until process
// restart.
func TestProbeCycle_PurgesDeadMembers(t *testing.T) {
	g, _, _ := newCallbackTestGossip(t, "node-a")

	g.applyPiggyback(EncodeMembers([]Member{{ID: "node-b", Addr: "10.0.0.2:7946", Incarnation: 1, State: StateAlive}}))
	g.applyPiggyback(EncodeMembers([]Member{{ID: "node-b", Addr: "10.0.0.2:7946", Incarnation: 1, State: StateDead}}))

	if got := g.Members(); len(got) != 2 {
		t.Fatalf("pre-state: expected node-a + dead node-b in view, got %d members", len(got))
	}

	// One probe cycle — the documented periodic purge point.
	g.probeCycle()

	if got := g.Members(); len(got) != 1 {
		t.Fatalf("FAIL: dead member survived a probe cycle (PurgeDead never wired into the prober): members=%d", len(got))
	}
	if _, ok := g.members.Get("node-b"); ok {
		t.Fatalf("FAIL: dead node-b still present after probe cycle")
	}
	// Self must remain.
	if _, ok := g.members.Get("node-a"); !ok {
		t.Fatalf("probe cycle purged the local node")
	}
}
