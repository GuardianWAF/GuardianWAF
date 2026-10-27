package raft

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// kvSM is a snapshot-capable state machine: each command is "key=value".
type kvSM struct {
	mu sync.Mutex
	kv map[string]string
}

func newKVSM() *kvSM { return &kvSM{kv: map[string]string{}} }

func (s *kvSM) Apply(e LogEntry) {
	k, v, _ := strings.Cut(string(e.Command), "=")
	s.mu.Lock()
	s.kv[k] = v
	s.mu.Unlock()
}

func (s *kvSM) Snapshot() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Marshal(s.kv)
}

func (s *kvSM) Restore(data []byte) error {
	kv := map[string]string{}
	if err := json.Unmarshal(data, &kv); err != nil {
		return err
	}
	s.mu.Lock()
	s.kv = kv
	s.mu.Unlock()
	return nil
}

func (s *kvSM) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.kv)
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestLogStoreCompactionBase(t *testing.T) {
	l := NewLogStore()
	for i := range 10 {
		l.Append(uint64(1+i/5), []byte{byte(i)}) // terms 1×5, 2×5
	}
	if err := l.CompactTo(6); err != nil {
		t.Fatal(err)
	}
	if l.BaseIndex() != 6 || l.BaseTerm() != 2 || l.Len() != 4 || l.LastIndex() != 10 {
		t.Fatalf("after compact: base=%d/%d len=%d last=%d", l.BaseIndex(), l.BaseTerm(), l.Len(), l.LastIndex())
	}
	if _, ok := l.Get(6); ok {
		t.Fatal("compacted entry still readable")
	}
	if e, ok := l.Get(7); !ok || e.Index != 7 {
		t.Fatalf("Get(7) = %+v, %v", e, ok)
	}
	if l.Term(6) != 2 || l.Term(5) != 0 || l.Term(10) != 2 {
		t.Fatalf("Term: base=%d below=%d last=%d", l.Term(6), l.Term(5), l.Term(10))
	}
	if !l.HasAt(3, 99) || !l.HasAt(6, 2) || l.HasAt(6, 1) {
		t.Fatal("HasAt must treat indices below the base as matching and check the base term")
	}
	if l.EntriesFrom(6) != nil || len(l.EntriesFrom(7)) != 4 {
		t.Fatal("EntriesFrom must refuse compacted indices")
	}
	if l.TruncateFrom(5) {
		t.Fatal("truncating into the snapshot must be refused")
	}
	if idx := l.Append(3, nil); idx != 11 {
		t.Fatalf("append after compaction got index %d, want 11", idx)
	}
	if got := len(l.EntriesFromLimit(7, 2, 0)); got != 2 {
		t.Fatalf("EntriesFromLimit returned %d entries, want 2", got)
	}

	// ResetToSnapshot keeps a matching suffix, discards on mismatch.
	if !l.ResetToSnapshot(9, 2) || l.BaseIndex() != 9 || l.LastIndex() != 11 {
		t.Fatalf("matching reset: base=%d last=%d", l.BaseIndex(), l.LastIndex())
	}
	if l.ResetToSnapshot(20, 5) || l.BaseIndex() != 20 || l.Len() != 0 || l.LastTerm() != 5 {
		t.Fatalf("mismatching reset: base=%d len=%d lastTerm=%d", l.BaseIndex(), l.Len(), l.LastTerm())
	}
}

func TestSnapshotFileRoundTripAndCorruption(t *testing.T) {
	dir := t.TempDir()
	if _, ok, err := readSnapshotFile(dir); ok || err != nil {
		t.Fatalf("missing snapshot: ok=%v err=%v", ok, err)
	}
	want := stateSnapshot{Index: 42, Term: 3, Data: []byte(`{"a":"1"}`)}
	if err := writeSnapshotFile(dir, want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := readSnapshotFile(dir)
	if err != nil || !ok || got.Index != 42 || got.Term != 3 || string(got.Data) != string(want.Data) {
		t.Fatalf("round trip: %+v ok=%v err=%v", got, ok, err)
	}
	path := filepath.Join(dir, snapshotFileName)
	raw, _ := os.ReadFile(path)
	raw[len(raw)-6] ^= 0xff
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readSnapshotFile(dir); err == nil {
		t.Fatal("a corrupt snapshot must be an error, not silently ignored")
	}
	if err := writeSnapshotFile(dir, stateSnapshot{Data: make([]byte, maxSnapshotSize+1)}); err == nil {
		t.Fatal("oversized snapshot accepted")
	}
}

// A WAL written with a log base replays to the same base; legacy snapshot
// records (no base) still replay.
func TestWALSnapshotBaseReplay(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenWAL(dir)
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPersistentState()
	ps.SetWAL(w)
	for i := range 8 {
		ps.Log().Append(1, []byte{byte(i)})
	}
	if err := ps.Log().CompactTo(5); err != nil {
		t.Fatal(err)
	}
	if err := ps.Snapshot(); err != nil {
		t.Fatal(err)
	}
	ps.Log().Append(1, []byte("after"))
	_ = w.Close()

	w2, err := OpenWAL(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	ps2 := NewPersistentState()
	if err := w2.Replay(ps2); err != nil {
		t.Fatal(err)
	}
	if ps2.Log().BaseIndex() != 5 || ps2.Log().LastIndex() != 9 || ps2.Log().Len() != 4 {
		t.Fatalf("replayed base=%d last=%d len=%d, want 5/9/4", ps2.Log().BaseIndex(), ps2.Log().LastIndex(), ps2.Log().Len())
	}

	legacy := encodeWALRecord(WALRecord{Type: WALSnapshot, Term: 2, Entries: []LogEntry{{Term: 2, Index: 1}}})
	rec, err := decodeWALPayload(legacy[4 : len(legacy)-4])
	if err != nil || rec.Type != WALSnapshot || rec.BaseIndex != 0 || len(rec.Entries) != 1 {
		t.Fatalf("legacy snapshot record: %+v err=%v", rec, err)
	}
}

func proposeAll(t *testing.T, r *Raft, from, to int) {
	t.Helper()
	for i := from; i < to; i++ {
		if err := r.Propose(fmt.Appendf(nil, "k%d=v%d", i, i)); err != nil {
			t.Fatalf("propose %d: %v", i, err)
		}
	}
}

// Snapshots bound the log and the WAL, and a restart restores the state
// machine from the snapshot plus the WAL suffix.
func TestSnapshotRestartRestoresStateMachine(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		NodeID: "solo", Secret: testSecret, BindAddr: "127.0.0.1:0", DataDir: dir,
		ElectionTimeoutMin: 50 * time.Millisecond, ElectionTimeoutMax: 100 * time.Millisecond,
		HeartbeatInterval: 10 * time.Millisecond, SnapshotThreshold: 10,
	}
	sm := newKVSM()
	r, err := New(cfg, sm)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "leadership", func() bool { return r.Role() == RoleLeader })
	proposeAll(t, r, 0, 35)
	waitFor(t, 5*time.Second, "35 applied", func() bool { return r.LastApplied() >= 35 })
	if base := r.Log().BaseIndex(); base < 30 || r.Log().Len() > 10 {
		t.Fatalf("log not compacted: base=%d len=%d", base, r.Log().Len())
	}
	r.Stop()

	sm2 := newKVSM()
	r2, err := New(cfg, sm2)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Stop()
	base := r2.Log().BaseIndex()
	if base < 30 || sm2.len() < int(base) || r2.LastApplied() != base {
		t.Fatalf("restart: base=%d restored keys=%d lastApplied=%d", base, sm2.len(), r2.LastApplied())
	}
	if err := r2.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "leadership after restart", func() bool { return r2.Role() == RoleLeader })
	proposeAll(t, r2, 35, 36) // a current-term entry commits the replayed suffix
	waitFor(t, 5*time.Second, "all 36 keys", func() bool { return sm2.len() == 36 })
}

// A follower that starts after the leader compacted its log catches up via
// InstallSnapshot.
func TestLaggingFollowerCatchesUpViaInstallSnapshot(t *testing.T) {
	ids := []string{"node-a", "node-b", "node-c"}
	sms := map[string]*kvSM{}
	nodes := map[string]*Raft{}
	for _, id := range ids {
		sms[id] = newKVSM()
		r, err := New(Config{
			NodeID: id, Secret: testSecret, BindAddr: "127.0.0.1:0",
			ElectionTimeoutMin: 300 * time.Millisecond, ElectionTimeoutMax: 600 * time.Millisecond,
			HeartbeatInterval: 30 * time.Millisecond, SnapshotThreshold: 20,
		}, sms[id])
		if err != nil {
			t.Fatal(err)
		}
		nodes[id] = r
		defer r.Stop()
	}
	for _, id := range ids {
		var peers []Peer
		for _, other := range ids {
			if other != id {
				peers = append(peers, Peer{ID: other, Addr: nodes[other].Transport().LocalAddr()})
			}
		}
		nodes[id].UpdatePeers(peers)
	}
	// node-c stays down while a and b form a quorum and compact.
	for _, id := range ids[:2] {
		if err := nodes[id].Start(); err != nil {
			t.Fatal(err)
		}
	}
	var leader *Raft
	waitFor(t, 10*time.Second, "leader among a/b", func() bool {
		for _, id := range ids[:2] {
			if nodes[id].Role() == RoleLeader {
				leader = nodes[id]
				return true
			}
		}
		return false
	})
	proposeAll(t, leader, 0, 60)
	waitFor(t, 10*time.Second, "leader applied 60", func() bool { return leader.LastApplied() >= 60 })
	if leader.Log().BaseIndex() < 40 {
		t.Fatalf("leader did not compact: base=%d", leader.Log().BaseIndex())
	}

	if err := nodes["node-c"].Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "node-c caught up", func() bool { return sms["node-c"].len() == 60 })
	if c := nodes["node-c"]; c.Log().BaseIndex() == 0 {
		t.Fatal("node-c caught up without installing a snapshot")
	}
}
