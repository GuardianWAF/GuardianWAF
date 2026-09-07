package gossip

import (
	"testing"
	"time"
)

// Regression: UpdateMember is an external-source entry point (e.g. Raft state
// replication) that fires onJoin/onLeave. Stop() documents that the callbacks
// (the Raft peer-sync bridge) can never fire after shutdown, and markSuspect
// plus the suspect->dead timer enforce that via g.stopped — but UpdateMember
// had no guard, so a post-Stop update (late Raft replication) drove the
// bridge into raft.UpdatePeers on a stopped Raft node.
func TestUpdateMemberRespectsShutdownInvariant(t *testing.T) {
	tr, err := NewUDPTransport("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewUDPTransport: %v", err)
	}
	defer tr.Close()

	g, err := NewWithTransport(Config{
		NodeID:         "shutdown-invariant",
		Secret:         testSecret,
		Addr:           tr.LocalAddr(),
		ProbeInterval:  200 * time.Millisecond,
		ProbeTimeout:   50 * time.Millisecond,
		GossipInterval: 200 * time.Millisecond,
	}, tr)
	if err != nil {
		t.Fatalf("NewWithTransport: %v", err)
	}

	var fired []string
	g.OnJoin(func(id, addr string) { fired = append(fired, "join:"+id) })
	g.OnLeave(func(id string) { fired = append(fired, "leave:"+id) })

	// Positive control: while running, callbacks still fire.
	if err := g.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	g.UpdateMember(Member{ID: "live-node", Addr: "127.0.0.1:6502", Incarnation: 1, State: StateAlive})

	deadline := time.Now().Add(2 * time.Second)
	for len(fired) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(fired) == 0 {
		t.Fatalf("positive control failed: no callback fired while running — guard is over-blocking")
	}

	g.Stop() // shutdown complete — the invariant begins here
	fired = nil

	// Post-shutdown external updates must not fire any callback.
	g.UpdateMember(Member{ID: "late-dead", Addr: "127.0.0.1:6501", Incarnation: 1, State: StateDead})
	g.UpdateMember(Member{ID: "late-alive", Addr: "127.0.0.1:6502", Incarnation: 1, State: StateAlive})
	time.Sleep(100 * time.Millisecond)

	if len(fired) > 0 {
		t.Fatalf("join/leave callbacks fired after Stop(): %v — UpdateMember violates the post-shutdown invariant", fired)
	}
}
