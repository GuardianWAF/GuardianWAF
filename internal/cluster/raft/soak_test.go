package raft

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestSoakBoundedWALAndRestart is the long-uptime check from the production
// roadmap: a three-node cluster takes a sustained write stream with the
// default snapshot threshold, and the WAL and snapshot must stay bounded while
// a restarted node must come back in bounded time. It is opt-in because it
// runs for minutes:
//
//	GWAF_RAFT_SOAK=1 GWAF_RAFT_SOAK_ENTRIES=200000 go test -run TestSoak -v ./internal/cluster/raft/
func TestSoakBoundedWALAndRestart(t *testing.T) {
	if os.Getenv("GWAF_RAFT_SOAK") == "" {
		t.Skip("set GWAF_RAFT_SOAK=1 to run the Raft soak")
	}
	entries := 100000
	if v, err := strconv.Atoi(os.Getenv("GWAF_RAFT_SOAK_ENTRIES")); err == nil && v > 0 {
		entries = v
	}
	const (
		threshold = 10000 // the cluster.snapshot_threshold default
		keySpace  = 5000  // bans churn over a bounded set of keys
		batch     = 1000
	)

	ids := []string{"soak-a", "soak-b", "soak-c"}
	dirs := map[string]string{}
	nodes := map[string]*Raft{}
	cfgFor := func(id string) Config {
		return Config{
			NodeID: id, Secret: testSecret, BindAddr: "127.0.0.1:0", DataDir: dirs[id],
			ElectionTimeoutMin: 300 * time.Millisecond, ElectionTimeoutMax: 600 * time.Millisecond,
			HeartbeatInterval: 30 * time.Millisecond, SnapshotThreshold: threshold,
		}
	}
	for _, id := range ids {
		dirs[id] = t.TempDir()
		r, err := New(cfgFor(id), newKVSM())
		if err != nil {
			t.Fatal(err)
		}
		nodes[id] = r
	}
	wire := func() {
		for _, id := range ids {
			var peers []Peer
			for _, other := range ids {
				if other != id {
					peers = append(peers, Peer{ID: other, Addr: nodes[other].Transport().LocalAddr()})
				}
			}
			nodes[id].UpdatePeers(peers)
		}
	}
	wire()
	for _, id := range ids {
		if err := nodes[id].Start(); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for _, r := range nodes {
			r.Stop()
		}
	}()

	leader := func() *Raft {
		var l *Raft
		waitFor(t, 15*time.Second, "a leader", func() bool {
			for _, r := range nodes {
				if r.Role() == RoleLeader {
					l = r
					return true
				}
			}
			return false
		})
		return l
	}

	fileSize := func(dir, name string) int64 {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			return 0
		}
		return st.Size()
	}
	var maxWAL, maxSnap int64
	start := time.Now()
	for sent := 0; sent < entries; sent += batch {
		l := leader()
		for i := sent; i < sent+batch; i++ {
			for l.Propose(fmt.Appendf(nil, "k%d=v%d", i%keySpace, i)) != nil {
				l = leader()
			}
		}
		target := l.Log().LastIndex()
		waitFor(t, 60*time.Second, "followers to apply the batch", func() bool {
			for _, r := range nodes {
				if r.LastApplied() < target {
					return false
				}
			}
			return true
		})
		for _, id := range ids {
			maxWAL = max(maxWAL, fileSize(dirs[id], "raft.wal"))
			maxSnap = max(maxSnap, fileSize(dirs[id], snapshotFileName))
		}
	}
	elapsed := time.Since(start)
	t.Logf("%d entries in %v (%.0f/s); max WAL %d KiB, max snapshot %d KiB",
		entries, elapsed.Round(time.Second), float64(entries)/elapsed.Seconds(), maxWAL>>10, maxSnap>>10)

	// Bounded: the WAL holds at most about two snapshot intervals of entries
	// (compaction happens after the threshold is crossed), never the whole
	// history. Each entry is well under 100 bytes on disk.
	if limit := int64(2*threshold+2*batch) * 100; maxWAL > limit {
		t.Errorf("WAL grew to %d bytes, want at most %d for threshold %d", maxWAL, limit, threshold)
	}
	if base := nodes["soak-a"].Log().BaseIndex(); base == 0 {
		t.Error("log was never compacted")
	}

	// Restart one follower from disk and time its recovery.
	var victim string
	for _, id := range ids {
		if nodes[id].Role() != RoleLeader {
			victim = id
			break
		}
	}
	applied := nodes[victim].LastApplied()
	nodes[victim].Stop()
	restartStart := time.Now()
	sm := newKVSM()
	r, err := New(cfgFor(victim), sm)
	if err != nil {
		t.Fatal(err)
	}
	nodes[victim] = r
	restart := time.Since(restartStart)
	if sm.len() != keySpace || r.LastApplied() < applied-uint64(2*threshold) {
		t.Errorf("restart restored %d keys at index %d, want %d keys near %d", sm.len(), r.LastApplied(), keySpace, applied)
	}
	t.Logf("restart from disk: %v (restored %d keys, last applied %d)", restart.Round(time.Millisecond), sm.len(), r.LastApplied())
	if restart > 5*time.Second {
		t.Errorf("restart took %v, want under 5s with snapshots", restart)
	}
}
