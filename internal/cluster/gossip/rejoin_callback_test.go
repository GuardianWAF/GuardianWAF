package gossip

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// stubTransport satisfies Transport without any network activity. The
// callback-contract tests drive applyPiggyback directly, so only LocalAddr is
// ever called (by NewWithTransport).
type stubTransport struct{ local string }

func (t *stubTransport) Send(addr string, data []byte) error { return nil }
func (t *stubTransport) Receive(ctx context.Context) ([]byte, string, error) {
	<-ctx.Done()
	return nil, "", ctx.Err()
}
func (t *stubTransport) LocalAddr() string { return t.local }
func (t *stubTransport) Close() error      { return nil }

// newCallbackTestGossip builds a stopped (never-Started) gossip node with
// join/leave capture. applyPiggyback is driven directly, so no receive loop
// and no clock are involved — the assertions are deterministic.
func newCallbackTestGossip(t *testing.T, nodeID string) (*Gossip, *[]string, *[]string) {
	t.Helper()
	tr := &stubTransport{local: "127.0.0.1:7946"}
	g, err := NewWithTransport(Config{
		NodeID:           nodeID,
		Addr:             "127.0.0.1:7946",
		Secret:           bytes.Repeat([]byte("k"), MinSecretLen),
		ProbeInterval:    time.Second,
		ProbeTimeout:     500 * time.Millisecond,
		SuspicionTimeout: 5 * time.Second,
		GossipInterval:   200 * time.Millisecond,
	}, tr)
	if err != nil {
		t.Fatalf("NewWithTransport: %v", err)
	}
	joins := &[]string{}
	leaves := &[]string{}
	g.SetCallbacks(
		func(id, addr string) { *joins = append(*joins, id) },
		func(id string) { *leaves = append(*leaves, id) },
	)
	return g, joins, leaves
}

// The join/leave callbacks are the Raft peer-sync bridge's only view of
// membership changes: onJoin re-adds a node to the Raft peer set, onLeave
// removes it. They must therefore fire on membership-view TRANSITIONS, not on
// every message receipt:
//
//   - a member that died and rejoins under the same ID (higher incarnation,
//     StateAlive) must re-fire onJoin even though its dead entry still exists
//     in the local view (wasNew=false) — otherwise the node is gossip-alive
//     but is never re-added to the Raft peer set;
//   - a duplicate dead announcement (same incarnation, same state) must not
//     re-fire onLeave;
//   - a dead-first announcement for an unknown member is not a transition and
//     must not fire onLeave.
func TestApplyPiggyback_CallbacksFireOnTransitions(t *testing.T) {
	g, joins, leaves := newCallbackTestGossip(t, "node-a")

	b := func(inc uint64, state MemberState) []Member {
		return []Member{{ID: "node-b", Addr: "10.0.0.2:7946", Incarnation: inc, State: state}}
	}

	// B joins alive.
	g.applyPiggyback(EncodeMembers(b(1, StateAlive)))
	if len(*joins) != 1 || len(*leaves) != 0 {
		t.Fatalf("initial join: joins=%v leaves=%v", *joins, *leaves)
	}

	// B dies.
	g.applyPiggyback(EncodeMembers(b(1, StateDead)))
	if len(*leaves) != 1 {
		t.Fatalf("death: leaves=%v, want exactly one", *leaves)
	}

	// Duplicate dead announcement — not a new transition.
	g.applyPiggyback(EncodeMembers(b(1, StateDead)))
	if len(*leaves) != 1 {
		t.Fatalf("FAIL: duplicate dead announcement re-fired onLeave: leaves=%v", *leaves)
	}

	// Dead-first sight of an unknown member — not a transition.
	g.applyPiggyback(EncodeMembers([]Member{{ID: "ghost", Addr: "10.0.0.9:7946", Incarnation: 1, State: StateDead}}))
	if len(*leaves) != 1 {
		t.Fatalf("FAIL: unknown-member dead announcement fired onLeave: leaves=%v", *leaves)
	}

	// B rejoins alive with a higher incarnation — onJoin must fire again so
	// the Raft peer-sync bridge re-adds it to the peer set.
	g.applyPiggyback(EncodeMembers(b(2, StateAlive)))
	if len(*joins) != 2 {
		t.Fatalf("FAIL: rejoin of a dead member did not re-fire onJoin — the node is gossip-alive but never re-added to the Raft peer set: joins=%v leaves=%v", *joins, *leaves)
	}
	if (*joins)[1] != "node-b" {
		t.Fatalf("rejoin recorded wrong join: %v", *joins)
	}
}

// The same transition contract applies to the exported external-source entry
// point (Raft state replication wiring).
func TestUpdateMember_CallbacksFireOnTransitions(t *testing.T) {
	g, joins, leaves := newCallbackTestGossip(t, "node-a")

	g.UpdateMember(Member{ID: "node-b", Addr: "10.0.0.2:7946", Incarnation: 1, State: StateAlive})
	if len(*joins) != 1 {
		t.Fatalf("initial join: joins=%v", *joins)
	}

	g.UpdateMember(Member{ID: "node-b", Addr: "10.0.0.2:7946", Incarnation: 1, State: StateDead})
	if len(*leaves) != 1 {
		t.Fatalf("death: leaves=%v, want exactly one", *leaves)
	}

	// Duplicate dead announcement — not a new transition.
	g.UpdateMember(Member{ID: "node-b", Addr: "10.0.0.2:7946", Incarnation: 1, State: StateDead})
	if len(*leaves) != 1 {
		t.Fatalf("FAIL: duplicate dead announcement re-fired onLeave: leaves=%v", *leaves)
	}

	// Rejoin must re-fire onJoin.
	g.UpdateMember(Member{ID: "node-b", Addr: "10.0.0.2:7946", Incarnation: 2, State: StateAlive})
	if len(*joins) != 2 {
		t.Fatalf("FAIL: rejoin of a dead member did not re-fire onJoin: joins=%v leaves=%v", *joins, *leaves)
	}
}
