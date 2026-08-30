package clustersync

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/cluster/raft"
)

// --- Command encode/decode ---

func TestCommandEncodeDecode(t *testing.T) {
	cmd := Command{Type: CmdBanIP, Payload: json.RawMessage(`{"ip":"1.2.3.4"}`)}
	data, err := cmd.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeCommand(data)
	if err != nil {
		t.Fatalf("DecodeCommand: %v", err)
	}
	if decoded.Type != CmdBanIP {
		t.Errorf("Type = %d, want %d", decoded.Type, CmdBanIP)
	}
}

func TestNewBanCommand(t *testing.T) {
	cmd, err := NewBanCommand("10.0.0.1", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewBanCommand: %v", err)
	}
	if cmd.Type != CmdBanIP {
		t.Fatalf("Type = %d, want %d", cmd.Type, CmdBanIP)
	}
	var p BanIPPayload
	if err := cmd.DecodePayload(&p); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if p.IP != "10.0.0.1" {
		t.Errorf("IP = %q, want %q", p.IP, "10.0.0.1")
	}
	if p.Duration != 5*time.Minute {
		t.Errorf("Duration = %v, want %v", p.Duration, 5*time.Minute)
	}
}

func TestNewSetRuleCommand(t *testing.T) {
	rule := json.RawMessage(`{"pattern":"sql-injection","action":"block"}`)
	cmd, err := NewSetRuleCommand("sqli-1", rule)
	if err != nil {
		t.Fatalf("NewSetRuleCommand: %v", err)
	}
	var p SetRulePayload
	if err := cmd.DecodePayload(&p); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if p.RuleID != "sqli-1" {
		t.Errorf("RuleID = %q, want %q", p.RuleID, "sqli-1")
	}
}

func TestNewIncrCounterCommand(t *testing.T) {
	cmd, err := NewIncrCounterCommand("rate:1.2.3.4", 5, 1000)
	if err != nil {
		t.Fatalf("NewIncrCounterCommand: %v", err)
	}
	var p IncrCounterPayload
	if err := cmd.DecodePayload(&p); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if p.Key != "rate:1.2.3.4" || p.Delta != 5 || p.Window != 1000 {
		t.Errorf("payload = %+v, want {rate:1.2.3.4 5 1000}", p)
	}
}

func TestDecodeCommand_InvalidJSON(t *testing.T) {
	_, err := DecodeCommand([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// --- Store: ban list ---

func TestStore_BanUnban(t *testing.T) {
	s := NewReplicatedStore()

	// Initially not banned.
	if s.IsBanned("1.2.3.4") {
		t.Fatal("IP should not be banned initially")
	}

	// Ban via command.
	cmd, _ := NewBanCommand("1.2.3.4", time.Hour)
	if err := s.Apply(cmd); err != nil {
		t.Fatalf("Apply ban: %v", err)
	}
	if !s.IsBanned("1.2.3.4") {
		t.Fatal("IP should be banned after Apply")
	}

	// Unban via command.
	cmd2, _ := NewUnbanCommand("1.2.3.4")
	if err := s.Apply(cmd2); err != nil {
		t.Fatalf("Apply unban: %v", err)
	}
	if s.IsBanned("1.2.3.4") {
		t.Fatal("IP should not be banned after unban")
	}
}

func TestStore_BanExpiration(t *testing.T) {
	s := NewReplicatedStore()

	cmd, _ := NewBanCommand("9.9.9.9", 50*time.Millisecond)
	s.Apply(cmd)

	if !s.IsBanned("9.9.9.9") {
		t.Fatal("should be banned immediately")
	}
	time.Sleep(80 * time.Millisecond)
	if s.IsBanned("9.9.9.9") {
		t.Fatal("should be expired after 80ms")
	}
}

func TestStore_PurgeExpiredBans(t *testing.T) {
	s := NewReplicatedStore()

	// Add a permanent ban (duration 0).
	cmd, _ := NewBanCommand("1.1.1.1", 0)
	s.Apply(cmd)

	// Add a short ban.
	cmd2, _ := NewBanCommand("2.2.2.2", 10*time.Millisecond)
	s.Apply(cmd2)

	time.Sleep(30 * time.Millisecond)

	purged := s.PurgeExpiredBans(time.Now())
	if purged != 1 {
		t.Errorf("purged %d, want 1", purged)
	}

	// Permanent ban should still be present.
	if !s.IsBanned("1.1.1.1") {
		t.Error("permanent ban should survive purge")
	}
	if s.IsBanned("2.2.2.2") {
		t.Error("expired ban should have been purged")
	}
}

func TestStore_BannedIPs(t *testing.T) {
	s := NewReplicatedStore()
	s.Apply(mustCmd(NewBanCommand("10.0.0.1", time.Hour)))
	s.Apply(mustCmd(NewBanCommand("10.0.0.2", time.Hour)))

	ips := s.BannedIPs()
	if len(ips) != 2 {
		t.Fatalf("BannedIPs len = %d, want 2", len(ips))
	}
}

func TestStore_BanOverwrite(t *testing.T) {
	s := NewReplicatedStore()

	// Ban for 1 hour.
	s.Apply(mustCmd(NewBanCommand("5.5.5.5", time.Hour)))

	// Ban again with shorter duration — should overwrite.
	s.Apply(mustCmd(NewBanCommand("5.5.5.5", 10*time.Millisecond)))
	if !s.IsBanned("5.5.5.5") {
		t.Fatal("should be banned")
	}

	time.Sleep(30 * time.Millisecond)
	if s.IsBanned("5.5.5.5") {
		t.Fatal("should be expired after overwrite with short duration")
	}
}

// --- Store: rules ---

func TestStore_SetDeleteRule(t *testing.T) {
	s := NewReplicatedStore()
	rule := json.RawMessage(`{"action":"block"}`)

	cmd, _ := NewSetRuleCommand("rule-1", rule)
	s.Apply(cmd)

	got, ok := s.GetRule("rule-1")
	if !ok {
		t.Fatal("rule should exist")
	}
	if string(got) != `{"action":"block"}` {
		t.Errorf("rule = %s, want {\"action\":\"block\"}", got)
	}

	// AllRules
	all := s.AllRules()
	if len(all) != 1 {
		t.Fatalf("AllRules len = %d, want 1", len(all))
	}

	// Delete
	cmd2, _ := NewDeleteRuleCommand("rule-1")
	s.Apply(cmd2)
	_, ok = s.GetRule("rule-1")
	if ok {
		t.Fatal("rule should be deleted")
	}
}

func TestStore_SetRuleOverwrite(t *testing.T) {
	s := NewReplicatedStore()

	s.Apply(mustCmd(NewSetRuleCommand("r1", json.RawMessage(`{"v":1}`))))
	s.Apply(mustCmd(NewSetRuleCommand("r1", json.RawMessage(`{"v":2}`))))

	got, ok := s.GetRule("r1")
	if !ok {
		t.Fatal("rule should exist")
	}
	if string(got) != `{"v":2}` {
		t.Errorf("rule = %s, want {\"v\":2}", got)
	}
}

// --- Store: counters ---

func TestStore_IncrCounter(t *testing.T) {
	s := NewReplicatedStore()

	// Increment within window 100.
	s.Apply(mustCmd(NewIncrCounterCommand("k1", 5, 100)))
	s.Apply(mustCmd(NewIncrCounterCommand("k1", 3, 100)))

	if v := s.GetCounter("k1", 100); v != 8 {
		t.Errorf("counter = %d, want 8", v)
	}

	// New window resets.
	s.Apply(mustCmd(NewIncrCounterCommand("k1", 2, 101)))
	if v := s.GetCounter("k1", 101); v != 2 {
		t.Errorf("counter = %d, want 2 (new window)", v)
	}
	// Old window should return 0 (stale).
	if v := s.GetCounter("k1", 100); v != 0 {
		t.Errorf("counter old window = %d, want 0 (stale)", v)
	}
}

func TestStore_ResetCounter(t *testing.T) {
	s := NewReplicatedStore()

	s.Apply(mustCmd(NewIncrCounterCommand("k1", 10, 1)))
	s.Apply(mustCmd(NewResetCounterCommand("k1")))

	if v := s.GetCounter("k1", 1); v != 0 {
		t.Errorf("counter = %d, want 0 after reset", v)
	}
}

func TestStore_CounterNegative(t *testing.T) {
	s := NewReplicatedStore()

	s.Apply(mustCmd(NewIncrCounterCommand("k1", -5, 1)))
	if v := s.GetCounter("k1", 1); v != -5 {
		t.Errorf("counter = %d, want -5", v)
	}
}

// --- Store: Apply error handling ---

func TestStore_ApplyUnknownCmdType(t *testing.T) {
	s := NewReplicatedStore()
	err := s.Apply(Command{Type: CmdType(99), Payload: nil})
	if err == nil {
		t.Fatal("expected error for unknown command type")
	}
}

func TestStore_ApplyMalformedPayload(t *testing.T) {
	s := NewReplicatedStore()
	err := s.Apply(Command{Type: CmdBanIP, Payload: json.RawMessage(`not json`)})
	if err == nil {
		t.Fatal("expected error for malformed payload")
	}
}

// --- Store: Stats ---

func TestStore_Stats(t *testing.T) {
	s := NewReplicatedStore()
	s.Apply(mustCmd(NewBanCommand("1.1.1.1", time.Hour)))
	s.Apply(mustCmd(NewBanCommand("2.2.2.2", time.Hour)))
	s.Apply(mustCmd(NewSetRuleCommand("r1", json.RawMessage(`{}`))))
	s.Apply(mustCmd(NewIncrCounterCommand("c1", 1, 1)))

	stats := s.Stats()
	if stats.Bans != 2 {
		t.Errorf("Bans = %d, want 2", stats.Bans)
	}
	if stats.Rules != 1 {
		t.Errorf("Rules = %d, want 1", stats.Rules)
	}
	if stats.Counters != 1 {
		t.Errorf("Counters = %d, want 1", stats.Counters)
	}
}

// --- StateMachine adapter ---

func TestStoreStateMachine_Apply(t *testing.T) {
	store := NewReplicatedStore()
	sm := NewStoreStateMachine(store, nil)

	cmd, _ := NewBanCommand("3.3.3.3", time.Hour)
	data, _ := cmd.Encode()

	sm.Apply(fakeLogEntry(1, 1, data))

	if !store.IsBanned("3.3.3.3") {
		t.Fatal("IP should be banned after StateMachine.Apply")
	}
}

func TestStoreStateMachine_ApplyMalformed(t *testing.T) {
	store := NewReplicatedStore()
	sm := NewStoreStateMachine(store, nil)

	// Malformed command — should not panic.
	sm.Apply(fakeLogEntry(1, 1, []byte("garbage")))

	// Store should be empty.
	if store.Stats().Bans != 0 {
		t.Error("store should be empty after malformed command")
	}
}

// --- Full replication round-trip (encode → decode → apply) ---

func TestReplicationRoundTrip(t *testing.T) {
	// Simulate two nodes: leader proposes, follower applies.
	leader := NewReplicatedStore()
	follower := NewReplicatedStore()

	ops := []func() (Command, error){
		func() (Command, error) { return NewBanCommand("10.0.0.1", time.Hour) },
		func() (Command, error) { return NewSetRuleCommand("rule-1", json.RawMessage(`{"action":"log"}`)) },
		func() (Command, error) { return NewIncrCounterCommand("rate:10.0.0.1", 1, 1) },
		func() (Command, error) { return NewIncrCounterCommand("rate:10.0.0.1", 1, 1) },
		func() (Command, error) { return NewBanCommand("10.0.0.2", 0) },
	}

	for _, op := range ops {
		cmd, err := op()
		if err != nil {
			t.Fatalf("build command: %v", err)
		}
		// Encode on leader, decode on follower.
		data, err := cmd.Encode()
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		decoded, err := DecodeCommand(data)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if err := follower.Apply(decoded); err != nil {
			t.Fatalf("apply: %v", err)
		}
		// Also apply to leader for comparison.
		leader.Apply(cmd)
	}

	// Both stores should have identical state.
	lStats := leader.Stats()
	fStats := follower.Stats()
	if lStats != fStats {
		t.Errorf("leader %+v != follower %+v", lStats, fStats)
	}
	if fStats.Bans != 2 {
		t.Errorf("bans = %d, want 2", fStats.Bans)
	}
	if fStats.Rules != 1 {
		t.Errorf("rules = %d, want 1", fStats.Rules)
	}
	if fStats.Counters != 1 {
		t.Errorf("counters = %d, want 1", fStats.Counters)
	}

	// Verify specific reads.
	if follower.GetCounter("rate:10.0.0.1", 1) != 2 {
		t.Error("counter should be 2")
	}
}

// --- API deadcode coverage ---

func TestAPI_DeadcodeCoverage(t *testing.T) {
	store := NewReplicatedStore()
	sm := NewStoreStateMachine(store, nil)

	// Exercise StoreStateMachine.Store()
	if sm.Store() == nil {
		t.Fatal("Store() returned nil")
	}

	// Create a Raft node (not started) so Propose returns ErrNotLeader,
	// but all API code paths are exercised.
	r, err := raft.New(raft.Config{
		NodeID:             "api-test",
		Secret:             testClusterSecret,
		BindAddr:           "127.0.0.1:0",
		ElectionTimeoutMin: 150 * time.Millisecond,
		ElectionTimeoutMax: 300 * time.Millisecond,
		HeartbeatInterval:  50 * time.Millisecond,
	}, sm)
	if err != nil {
		t.Fatalf("raft.New: %v", err)
	}

	api := NewAPI(r, store)
	if api.Store() == nil {
		t.Fatal("API.Store() returned nil")
	}

	// All Propose methods will return ErrRaftNotLeader since the node isn't
	// started. The point is to exercise the encode + propose code paths.
	if err := api.ProposeBan("10.0.0.1", time.Hour); err == nil {
		t.Error("ProposeBan should fail on non-started node")
	}
	if err := api.ProposeUnban("10.0.0.1"); err == nil {
		t.Error("ProposeUnban should fail on non-started node")
	}
	if err := api.ProposeSetRule("rule-1", json.RawMessage(`{}`)); err == nil {
		t.Error("ProposeSetRule should fail on non-started node")
	}
	if err := api.ProposeDeleteRule("rule-1"); err == nil {
		t.Error("ProposeDeleteRule should fail on non-started node")
	}
	if err := api.ProposeIncrCounter("key", 1, 1); err == nil {
		t.Error("ProposeIncrCounter should fail on non-started node")
	}
	if err := api.ProposeResetCounter("key"); err == nil {
		t.Error("ProposeResetCounter should fail on non-started node")
	}
}

// --- helpers ---

func fakeLogEntry(term, index uint64, data []byte) raft.LogEntry {
	return raft.LogEntry{Term: term, Index: index, Command: data}
}

func mustCmd(c Command, err error) Command {
	if err != nil {
		panic(err)
	}
	return c
}

func TestStore_IncrementCounter_Sequence(t *testing.T) {
	s := NewReplicatedStore()

	// First increment in a new window returns 1.
	if v := s.IncrementCounter("k1", 100); v != 1 {
		t.Fatalf("first increment = %d, want 1", v)
	}
	// Subsequent increments within same window accumulate.
	if v := s.IncrementCounter("k1", 100); v != 2 {
		t.Fatalf("second increment = %d, want 2", v)
	}
	if v := s.IncrementCounter("k1", 100); v != 3 {
		t.Fatalf("third increment = %d, want 3", v)
	}
	// GetCounter should see the same value.
	if v := s.GetCounter("k1", 100); v != 3 {
		t.Fatalf("GetCounter = %d, want 3", v)
	}
}

func TestStore_IncrementCounter_WindowRollover(t *testing.T) {
	s := NewReplicatedStore()

	s.IncrementCounter("k1", 100)
	s.IncrementCounter("k1", 100)
	s.IncrementCounter("k1", 100)

	// New window resets to 1.
	if v := s.IncrementCounter("k1", 101); v != 1 {
		t.Fatalf("new window increment = %d, want 1", v)
	}
	// Old window is now stale.
	if v := s.GetCounter("k1", 100); v != 0 {
		t.Fatalf("stale window GetCounter = %d, want 0", v)
	}
}

func TestStore_IncrementCounter_Concurrent(t *testing.T) {
	s := NewReplicatedStore()

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			s.IncrementCounter("k1", 200)
		}()
	}
	close(start)
	wg.Wait()

	// All goroutines incremented exactly once; no lost updates.
	if v := s.GetCounter("k1", 200); v != goroutines {
		t.Fatalf("concurrent result = %d, want %d (lost updates detected)", v, goroutines)
	}
}

func TestStore_IncrementCounter_IndependentKeys(t *testing.T) {
	s := NewReplicatedStore()

	s.IncrementCounter("a", 1)
	s.IncrementCounter("b", 1)
	s.IncrementCounter("a", 1)

	if v := s.GetCounter("a", 1); v != 2 {
		t.Fatalf("key 'a' = %d, want 2", v)
	}
	if v := s.GetCounter("b", 1); v != 1 {
		t.Fatalf("key 'b' = %d, want 1", v)
	}
}
