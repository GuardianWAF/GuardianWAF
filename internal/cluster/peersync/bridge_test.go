package peersync

import (
	"github.com/guardianwaf/guardianwaf/internal/cluster/gossip"
	"github.com/guardianwaf/guardianwaf/internal/cluster/raft"
	"reflect"
	"testing"
)

type fakeMemberList struct{ members []gossip.Member }

func (f *fakeMemberList) Members() []gossip.Member { return f.members }

type noopStateMachine struct{}

func (noopStateMachine) Apply(raft.LogEntry) {}

func TestBridgePreservesConfiguredVoters(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		members []gossip.Member
	}{
		{"all alive", []gossip.Member{{ID: "self", State: gossip.StateAlive}, {ID: "n2", RaftAddr: "127.0.0.1:9002", State: gossip.StateAlive}, {ID: "n3", RaftAddr: "127.0.0.1:9003", State: gossip.StateAlive}}},
		{"partition", []gossip.Member{{ID: "self", State: gossip.StateAlive}, {ID: "n2", State: gossip.StateDead}, {ID: "n3", State: gossip.StateSuspect}}},
		{"empty membership", nil},
		{"unconfigured member", []gossip.Member{{ID: "new", RaftAddr: "127.0.0.1:9004", State: gossip.StateAlive}}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			cfg := testRaftConfig("self", "127.0.0.1:0")
			cfg.Peers = []raft.Peer{{ID: "n2", Addr: "127.0.0.1:9002"}, {ID: "n3", Addr: "127.0.0.1:9003"}}
			r, err := raft.New(cfg, noopStateMachine{})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Stop()
			bridge := NewBridge(&fakeMemberList{members: scenario.members}, r, nil)
			join, leave := bridge.Callbacks()
			for range 3 {
				bridge.Sync()
				join("new", "127.0.0.1:4")
				leave("n2")
				if got := r.Peers(); !reflect.DeepEqual(got, cfg.Peers) {
					t.Fatalf("gossip changed voting membership: got %+v want %+v", got, cfg.Peers)
				}
				if majority := (len(r.Peers())+1)/2 + 1; majority != 2 {
					t.Fatalf("majority=%d want2", majority)
				}
			}
		})
	}
}
func TestBridgeDoesNotBootstrapVotersFromGossip(t *testing.T) {
	r, err := raft.New(testRaftConfig("self", "127.0.0.1:0"), noopStateMachine{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	NewBridge(&fakeMemberList{members: []gossip.Member{{ID: "other", RaftAddr: "127.0.0.1:2", State: gossip.StateAlive}}}, r, nil).Sync()
	if len(r.Peers()) != 0 {
		t.Fatal("unconfigured gossip member became a voter")
	}
}
func TestBridgeRealGossip(t *testing.T) {
	gc := gossip.DefaultConfig("self", "127.0.0.1:0")
	gc.Secret = testClusterSecret
	g, err := gossip.New(gc)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Stop()
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	cfg := testRaftConfig("self", "127.0.0.1:0")
	cfg.Peers = []raft.Peer{{ID: "remote", Addr: "127.0.0.1:9001"}}
	r, err := raft.New(cfg, noopStateMachine{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	b := NewBridge(g, r, nil)
	join, leave := b.Callbacks()
	g.SetCallbacks(join, leave)
	b.Sync()
	if !reflect.DeepEqual(r.Peers(), cfg.Peers) {
		t.Fatal("initial self-only gossip view changed configured voters")
	}
}
