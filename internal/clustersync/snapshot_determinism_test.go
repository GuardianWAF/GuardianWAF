package clustersync

import (
	"encoding/json"
	"testing"
	"time"
)

// Regression: applyBanIP stamped BannedAt with the apply-time clock, so
// replaying the Raft log after a restart re-banned an IP for its full
// duration even when the ban had long expired, and nodes disagreed on expiry.
func TestBanExpiryIsFixedAtProposalTime(t *testing.T) {
	cmd, err := NewBanCommand("203.0.113.7", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var p BanIPPayload
	if err := cmd.DecodePayload(&p); err != nil || p.BannedAt.IsZero() {
		t.Fatalf("payload %+v err=%v: BannedAt must be set at proposal time", p, err)
	}

	// Two nodes (or a node and its later replay) apply the same command.
	a, b := NewReplicatedStore(), NewReplicatedStore()
	if err := a.Apply(cmd); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := b.Apply(cmd); err != nil {
		t.Fatal(err)
	}
	if ea, eb := a.BannedIPs()[0].ExpiresAt, b.BannedIPs()[0].ExpiresAt; !ea.Equal(eb) {
		t.Fatalf("expiry differs between applies: %v vs %v", ea, eb)
	}

	// Replaying an already-expired ban must not resurrect it.
	old, _ := json.Marshal(BanIPPayload{IP: "203.0.113.8", Duration: time.Minute, BannedAt: time.Now().Add(-time.Hour)})
	s := NewReplicatedStore()
	if err := s.Apply(Command{Type: CmdBanIP, Payload: old}); err != nil {
		t.Fatal(err)
	}
	if s.IsBanned("203.0.113.8") {
		t.Fatal("replaying an expired ban resurrected it")
	}
}

func TestStoreSnapshotRoundTrip(t *testing.T) {
	sm := NewStoreStateMachine(NewReplicatedStore(), nil)
	for _, mk := range []func() (Command, error){
		func() (Command, error) { return NewBanCommand("198.51.100.1", 0) },
		func() (Command, error) { return NewBanCommand("198.51.100.2", time.Hour) },
		func() (Command, error) { return NewSetRuleCommand("r1", json.RawMessage(`{"a":1}`)) },
		func() (Command, error) { return NewIncrCounterCommand("ip:1", 3, 100) },
	} {
		cmd, err := mk()
		if err != nil {
			t.Fatal(err)
		}
		if err := sm.Store().Apply(cmd); err != nil {
			t.Fatal(err)
		}
	}
	data, err := sm.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	restored := NewStoreStateMachine(NewReplicatedStore(), nil)
	cmd, _ := NewSetRuleCommand("stale", json.RawMessage(`{}`))
	_ = restored.Store().Apply(cmd) // pre-existing state must be replaced
	if err := restored.Restore(data); err != nil {
		t.Fatal(err)
	}
	st := restored.Store()
	if !st.IsBanned("198.51.100.1") || !st.IsBanned("198.51.100.2") {
		t.Fatal("bans not restored")
	}
	if _, ok := st.GetRule("r1"); !ok {
		t.Fatal("rule not restored")
	}
	if _, ok := st.GetRule("stale"); ok {
		t.Fatal("restore merged instead of replacing state")
	}
	if got := st.GetCounter("ip:1", 100); got != 3 {
		t.Fatalf("counter = %d, want 3", got)
	}
	if err := restored.Restore([]byte("not json")); err == nil {
		t.Fatal("corrupt snapshot accepted")
	}
}
