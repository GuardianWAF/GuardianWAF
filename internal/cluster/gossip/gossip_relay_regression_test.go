package gossip

// Regression tests for the piggyback relay contract (round
// round4-gossip-relay). applyPiggyback must re-enqueue every APPLIED state
// transition — not just inserts — so suspect/dead/refutation updates spread
// beyond the originator's direct fanout. MemberList.Add reports true only
// for inserts, so gating the relay on Add's return silently dropped every
// replacement: state changes died after one hop, nodes outside the fanout
// kept stale membership views forever, and a node purged as dead during a
// partition was never re-learned when the partition healed (a healthy node
// emits no transition of its own). Re-enqueueing is self-terminating: an
// update relays only while it advances the local view, and shouldReplace is
// monotonic, so it dies out exactly when the cluster has converged.

import (
	"context"
	"testing"
)

type regGossipTransport struct{}

func (regGossipTransport) Send(addr string, data []byte) error                 { return nil }
func (regGossipTransport) Receive(ctx context.Context) ([]byte, string, error) { <-ctx.Done(); return nil, "", ctx.Err() }
func (regGossipTransport) LocalAddr() string                                   { return "127.0.0.1:7998" }
func (regGossipTransport) Close() error                                        { return nil }

func newRegGossip(t *testing.T) *Gossip {
	t.Helper()
	cfg := DefaultConfig("node-c", "127.0.0.1:7998")
	cfg.Secret = make([]byte, 32) // auth requires a >=32-byte secret
	g, err := NewWithTransport(cfg, regGossipTransport{})
	if err != nil {
		t.Fatalf("NewWithTransport: %v", err)
	}
	t.Cleanup(g.Stop)
	return g
}

func TestAppliedPiggybackTransitionsAreRelayed(t *testing.T) {
	g := newRegGossip(t)

	// Seed: node-b is Alive, incarnation 1.
	g.members.Add(Member{ID: "node-b", Addr: "10.0.0.2:7946", RaftAddr: "10.0.0.2:7947", Incarnation: 1, State: StateAlive})

	// An applied REPLACEMENT (alive → suspect at equal incarnation) must be
	// relayed.
	suspect := EncodeMembers([]Member{{ID: "node-b", Addr: "10.0.0.2:7946", RaftAddr: "10.0.0.2:7947", Incarnation: 1, State: StateSuspect}})
	g.applyPiggyback(suspect)

	if b, ok := g.members.Get("node-b"); !ok || b.State != StateSuspect {
		t.Fatalf("setup: Suspect(node-b) not applied, state=%v ok=%v", b.State, ok)
	}
	relayed := g.takePiggyback()
	if len(relayed) == 0 {
		t.Fatalf("applied Suspect(node-b) transition was not re-enqueued for dissemination")
	}
	members, err := DecodeMembers(relayed)
	if err != nil {
		t.Fatalf("relayed payload undecodable: %v", err)
	}
	found := false
	for _, m := range members {
		if m.ID == "node-b" && m.State == StateSuspect {
			found = true
		}
	}
	if !found {
		t.Fatalf("relayed payload does not carry Suspect(node-b): %+v", members)
	}

	// Control: a stale update (lower incarnation) is neither applied nor relayed.
	g.applyPiggyback(EncodeMembers([]Member{{ID: "node-b", Incarnation: 0, State: StateDead}}))
	if b, _ := g.members.Get("node-b"); b.State != StateSuspect {
		t.Fatalf("stale update was applied: state=%v", b.State)
	}
	if relayed := g.takePiggyback(); len(relayed) != 0 {
		t.Fatalf("stale update was relayed: % x", relayed)
	}

	// Control: inserts are relayed (the previously working path).
	g.applyPiggyback(EncodeMembers([]Member{{ID: "node-e", Addr: "10.0.0.5:7946", RaftAddr: "10.0.0.5:7947", Incarnation: 1, State: StateAlive}}))
	if relayed := g.takePiggyback(); len(relayed) == 0 {
		t.Fatalf("insert update was not relayed")
	}
}

// TestRelayIsSelfTerminating pins the termination property: re-relaying an
// update that no longer advances the local view must not re-enqueue it, so
// the epidemic dies out at convergence instead of looping forever.
func TestRelayIsSelfTerminating(t *testing.T) {
	g := newRegGossip(t)

	suspect := EncodeMembers([]Member{{ID: "node-b", Addr: "10.0.0.2:7946", RaftAddr: "10.0.0.2:7947", Incarnation: 1, State: StateSuspect}})
	g.applyPiggyback(suspect)          // first application: applied + relayed
	g.takePiggyback()                  // drain
	g.applyPiggyback(suspect)          // duplicate: no advance → must NOT relay
	if relayed := g.takePiggyback(); len(relayed) != 0 {
		t.Fatalf("duplicate Suspect(node-b) was re-relayed: % x", relayed)
	}
}
