package gossip

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Member state machine tests
// ---------------------------------------------------------------------------

func TestMemberState_String(t *testing.T) {
	tests := []struct {
		s    MemberState
		want string
	}{
		{StateAlive, "alive"},
		{StateSuspect, "suspect"},
		{StateDead, "dead"},
		{MemberState(99), "unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("MemberState(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestMemberList_AddGet(t *testing.T) {
	ml := NewMemberList("self")
	ml.Add(Member{ID: "n1", Addr: "10.0.0.1:7946", Incarnation: 1, State: StateAlive})

	got, ok := ml.Get("n1")
	if !ok {
		t.Fatal("expected to find n1")
	}
	if got.Addr != "10.0.0.1:7946" {
		t.Fatalf("addr = %q, want 10.0.0.1:7946", got.Addr)
	}
	if got.State != StateAlive {
		t.Fatalf("state = %s, want alive", got.State)
	}
}

func TestMemberList_GetMissing(t *testing.T) {
	ml := NewMemberList("self")
	if _, ok := ml.Get("nope"); ok {
		t.Fatal("expected missing member to return ok=false")
	}
}

func TestMemberList_HigherIncarnationWins(t *testing.T) {
	ml := NewMemberList("self")
	ml.Add(Member{ID: "n1", Addr: "a", Incarnation: 1, State: StateAlive})
	// Lower incarnation — should be ignored.
	ml.Add(Member{ID: "n1", Addr: "b", Incarnation: 0, State: StateAlive})
	got, _ := ml.Get("n1")
	if got.Incarnation != 1 {
		t.Fatalf("incarnation = %d, want 1", got.Incarnation)
	}
	// Higher incarnation — should overwrite.
	ml.Add(Member{ID: "n1", Addr: "c", Incarnation: 2, State: StateAlive})
	got, _ = ml.Get("n1")
	if got.Incarnation != 2 {
		t.Fatalf("incarnation = %d, want 2", got.Incarnation)
	}
	if got.Addr != "c" {
		t.Fatalf("addr = %q, want c", got.Addr)
	}
}

func TestMemberList_SuspectTransition(t *testing.T) {
	ml := NewMemberList("self")
	ml.Add(Member{ID: "n1", Addr: "a", Incarnation: 1, State: StateAlive})

	if !ml.MarkSuspect("n1") {
		t.Fatal("MarkSuspect returned false for alive member")
	}
	got, _ := ml.Get("n1")
	if got.State != StateSuspect {
		t.Fatalf("state = %s, want suspect", got.State)
	}
	// Suspecting an already-suspect member should return false.
	if ml.MarkSuspect("n1") {
		t.Fatal("MarkSuspect returned true for already-suspect member")
	}
}

func TestMemberList_DeadTransition(t *testing.T) {
	ml := NewMemberList("self")
	ml.Add(Member{ID: "n1", Addr: "a", Incarnation: 1, State: StateAlive})

	if !ml.MarkDead("n1") {
		t.Fatal("MarkDead returned false for alive member")
	}
	got, _ := ml.Get("n1")
	if got.State != StateDead {
		t.Fatalf("state = %s, want dead", got.State)
	}
	// Dead is idempotent.
	if ml.MarkDead("n1") {
		t.Fatal("MarkDead returned true for already-dead member")
	}
}

func TestMemberList_AliveOverridesSuspect(t *testing.T) {
	ml := NewMemberList("self")
	ml.Add(Member{ID: "n1", Addr: "a", Incarnation: 1, State: StateAlive})
	ml.MarkSuspect("n1")
	// Higher incarnation alive should override suspect.
	ml.Add(Member{ID: "n1", Addr: "a", Incarnation: 2, State: StateAlive})
	got, _ := ml.Get("n1")
	if got.State != StateAlive {
		t.Fatalf("state = %s, want alive (recovery)", got.State)
	}
	if got.Incarnation != 2 {
		t.Fatalf("incarnation = %d, want 2", got.Incarnation)
	}
}

func TestMemberList_AliveIgnoredWhenDead(t *testing.T) {
	ml := NewMemberList("self")
	ml.Add(Member{ID: "n1", Addr: "a", Incarnation: 1, State: StateAlive})
	ml.MarkDead("n1")
	// Same incarnation alive should not revive a dead member.
	ml.Add(Member{ID: "n1", Addr: "a", Incarnation: 1, State: StateAlive})
	got, _ := ml.Get("n1")
	if got.State != StateDead {
		t.Fatalf("state = %s, want dead (no revival)", got.State)
	}
}

func TestMemberList_AllMembers(t *testing.T) {
	ml := NewMemberList("self")
	ml.Add(Member{ID: "n1", Addr: "a", Incarnation: 1, State: StateAlive})
	ml.Add(Member{ID: "n2", Addr: "b", Incarnation: 1, State: StateAlive})
	ml.MarkDead("n2")
	all := ml.AllMembers()
	if len(all) != 2 {
		t.Fatalf("AllMembers returned %d, want 2", len(all))
	}
}

func TestMemberList_AliveMembers(t *testing.T) {
	ml := NewMemberList("self")
	ml.Add(Member{ID: "n1", Addr: "a", Incarnation: 1, State: StateAlive})
	ml.Add(Member{ID: "n2", Addr: "b", Incarnation: 1, State: StateAlive})
	ml.Add(Member{ID: "n3", Addr: "c", Incarnation: 1, State: StateAlive})
	ml.MarkDead("n3")
	alive := ml.AliveMembers()
	if len(alive) != 2 {
		t.Fatalf("AliveMembers returned %d, want 2", len(alive))
	}
}

func TestMemberList_RandomMember(t *testing.T) {
	ml := NewMemberList("self")
	ml.Add(Member{ID: "n1", Addr: "a", Incarnation: 1, State: StateAlive})
	ml.Add(Member{ID: "n2", Addr: "b", Incarnation: 1, State: StateAlive})

	m, ok := ml.RandomMember("self")
	if !ok {
		t.Fatal("RandomMember returned ok=false with live members")
	}
	if m.ID == "self" {
		t.Fatal("RandomMember returned local node")
	}
	if m.State == StateDead {
		t.Fatal("RandomMember returned dead member")
	}
}

func TestMemberList_RandomMemberNoneAvailable(t *testing.T) {
	ml := NewMemberList("self")
	if _, ok := ml.RandomMember("self"); ok {
		t.Fatal("expected ok=false with no members")
	}
}

func TestMemberList_Contains(t *testing.T) {
	ml := NewMemberList("self")
	ml.Add(Member{ID: "n1", Addr: "a", Incarnation: 1, State: StateAlive})
	if !ml.Contains("n1") {
		t.Fatal("Contains(n1) = false, want true")
	}
	if ml.Contains("n2") {
		t.Fatal("Contains(n2) = true, want false")
	}
}

func TestMemberList_Len(t *testing.T) {
	ml := NewMemberList("self")
	if ml.Len() != 0 {
		t.Fatalf("Len = %d, want 0", ml.Len())
	}
	ml.Add(Member{ID: "n1", Addr: "a", Incarnation: 1, State: StateAlive})
	if ml.Len() != 1 {
		t.Fatalf("Len = %d, want 1", ml.Len())
	}
}

func TestMemberList_DeadMembersPurged(t *testing.T) {
	ml := NewMemberList("self")
	ml.Add(Member{ID: "n1", Addr: "a", Incarnation: 1, State: StateAlive})
	ml.MarkDead("n1")
	// PurgeDead should remove the dead member.
	purged := ml.PurgeDead()
	if purged != 1 {
		t.Fatalf("PurgeDead purged %d, want 1", purged)
	}
	if ml.Contains("n1") {
		t.Fatal("dead member still present after purge")
	}
}

// ---------------------------------------------------------------------------
// Message encoding tests
// ---------------------------------------------------------------------------

func TestMessage_EncodeDecode(t *testing.T) {
	original := &Message{
		Seq:     12345,
		Type:    TypePing,
		Source:  "node-abc",
		Payload: []byte("hello"),
	}

	data, err := original.EncodeMessage()
	if err != nil {
		t.Fatalf("EncodeMessage: %v", err)
	}

	decoded, err := DecodeMessageBytes(data)
	if err != nil {
		t.Fatalf("DecodeMessageBytes: %v", err)
	}

	if decoded.Seq != original.Seq {
		t.Errorf("Seq = %d, want %d", decoded.Seq, original.Seq)
	}
	if decoded.Type != original.Type {
		t.Errorf("Type = %d, want %d", decoded.Type, original.Type)
	}
	if decoded.Source != original.Source {
		t.Errorf("Source = %q, want %q", decoded.Source, original.Source)
	}
	if string(decoded.Payload) != string(original.Payload) {
		t.Errorf("Payload = %q, want %q", decoded.Payload, original.Payload)
	}
}

func TestMessage_EmptyPayload(t *testing.T) {
	original := &Message{
		Seq:     1,
		Type:    TypeAck,
		Source:  "",
		Payload: nil,
	}

	data, err := original.EncodeMessage()
	if err != nil {
		t.Fatalf("EncodeMessage: %v", err)
	}

	decoded, err := DecodeMessageBytes(data)
	if err != nil {
		t.Fatalf("DecodeMessageBytes: %v", err)
	}

	if decoded.Source != "" {
		t.Errorf("Source = %q, want empty", decoded.Source)
	}
	if len(decoded.Payload) != 0 {
		t.Errorf("Payload len = %d, want 0", len(decoded.Payload))
	}
}

func TestMessage_LargeSourceID(t *testing.T) {
	longID := make([]byte, 300) // exceeds maxSourceIDLen (255)
	for i := range longID {
		longID[i] = 'x'
	}
	msg := &Message{Seq: 1, Type: TypePing, Source: string(longID)}
	if _, err := msg.EncodeMessage(); err == nil {
		t.Fatal("expected error for oversized source ID")
	}
}

func TestEncodeDecodeMembers(t *testing.T) {
	original := []Member{
		{ID: "n1", Addr: "10.0.0.1:7946", Incarnation: 1, State: StateAlive},
		{ID: "n2", Addr: "10.0.0.2:7946", Incarnation: 5, State: StateSuspect},
		{ID: "n3", Addr: "10.0.0.3:7946", Incarnation: 10, State: StateDead},
	}

	data := EncodeMembers(original)
	decoded, err := DecodeMembers(data)
	if err != nil {
		t.Fatalf("DecodeMembers: %v", err)
	}
	if len(decoded) != 3 {
		t.Fatalf("decoded %d members, want 3", len(decoded))
	}
	for i, m := range decoded {
		if m.ID != original[i].ID {
			t.Errorf("member[%d].ID = %q, want %q", i, m.ID, original[i].ID)
		}
		if m.Addr != original[i].Addr {
			t.Errorf("member[%d].Addr = %q, want %q", i, m.Addr, original[i].Addr)
		}
		if m.Incarnation != original[i].Incarnation {
			t.Errorf("member[%d].Incarnation = %d, want %d", i, m.Incarnation, original[i].Incarnation)
		}
		if m.State != original[i].State {
			t.Errorf("member[%d].State = %s, want %s", i, m.State, original[i].State)
		}
	}
}

func TestDecodeMembers_Truncated(t *testing.T) {
	// 4 bytes is too short for a single member record.
	_, err := DecodeMembers([]byte{1, 2, 3, 4})
	if err == nil {
		t.Fatal("expected error for truncated member data")
	}
}

func TestDecodeMembers_Empty(t *testing.T) {
	members, err := DecodeMembers(nil)
	if err != nil {
		t.Fatalf("DecodeMembers(nil): %v", err)
	}
	if len(members) != 0 {
		t.Fatalf("expected 0 members, got %d", len(members))
	}
}

func TestMessageType_String(t *testing.T) {
	tests := []struct {
		mt   MessageType
		want string
	}{
		{TypePing, "PING"},
		{TypeAck, "ACK"},
		{TypePingReq, "PING-REQ"},
		{TypeAlive, "ALIVE"},
		{TypeSuspect, "SUSPECT"},
		{TypeDead, "DEAD"},
		{TypePushPull, "PUSH-PULL"},
		{MessageType(99), "UNKNOWN(99)"},
	}
	for _, tt := range tests {
		if got := tt.mt.String(); got != tt.want {
			t.Errorf("MessageType(%d).String() = %q, want %q", tt.mt, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Piggyback tests
// ---------------------------------------------------------------------------

func TestPiggyback_EnqueueTake(t *testing.T) {
	g := &Gossip{
		config:  Config{NodeID: "self"},
		members: NewMemberList("self"),
	}

	m1 := Member{ID: "n1", Addr: "a", Incarnation: 1, State: StateAlive}
	g.enqueuePiggyback(m1)

	// takePiggyback returns encoded bytes.
	pb := g.takePiggyback()
	if len(pb) == 0 {
		t.Fatal("takePiggyback returned empty payload")
	}

	// Decode to verify the member is present.
	members, err := DecodeMembers(pb)
	if err != nil {
		t.Fatalf("DecodeMembers: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("decoded %d members, want 1", len(members))
	}
	if members[0].ID != "n1" {
		t.Fatalf("members[0].ID = %q, want n1", members[0].ID)
	}

	// Second take should be empty.
	pb2 := g.takePiggyback()
	if pb2 != nil {
		t.Fatalf("second takePiggyback returned %d bytes, want 0", len(pb2))
	}
}

func TestPiggyback_MaxPerMsg(t *testing.T) {
	g := &Gossip{
		config:  Config{NodeID: "self"},
		members: NewMemberList("self"),
	}

	// Enqueue more than maxPiggybackPerMsg updates.
	for i := 0; i < maxPiggybackPerMsg+10; i++ {
		g.enqueuePiggyback(Member{
			ID:          "n" + string(rune('a'+i)),
			Addr:        "a",
			Incarnation: 1,
			State:       StateAlive,
		})
	}

	// takePiggyback returns encoded bytes with at most maxPiggybackPerMsg members.
	pb := g.takePiggyback()
	members, err := DecodeMembers(pb)
	if err != nil {
		t.Fatalf("DecodeMembers: %v", err)
	}
	if len(members) != maxPiggybackPerMsg {
		t.Fatalf("decoded %d members, want %d", len(members), maxPiggybackPerMsg)
	}
}

// ---------------------------------------------------------------------------
// Multi-node integration test (real UDP)
// ---------------------------------------------------------------------------

func TestGossip_MultiNodeUDP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-node UDP test in short mode")
	}

	// Create 3 nodes on ephemeral ports.
	nodes := make([]*Gossip, 3)
	cleanup := func() {
		for _, n := range nodes {
			if n != nil {
				n.Stop()
			}
		}
	}
	defer cleanup()

	for i := range nodes {
		nodeID := "node-" + string(rune('0'+i))
		g, err := New(Config{
			NodeID:           nodeID,
			Addr:             "127.0.0.1:0",
			ProbeInterval:    50 * time.Millisecond,
			ProbeTimeout:     20 * time.Millisecond,
			SuspicionTimeout: 200 * time.Millisecond,
			GossipInterval:   20 * time.Millisecond,
			GossipFanout:     3,
			IndirectChecks:   2,
			Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
		if err != nil {
			t.Fatalf("node %d: New: %v", i, err)
		}
		if err := g.Start(); err != nil {
			t.Fatalf("node %d: Start: %v", i, err)
		}
		nodes[i] = g
	}

	// Bootstrap: node-0 joins node-1, node-1 joins node-2.
	// Gossip will propagate the rest.
	nodes[0].Join([]string{nodes[1].LocalMember().Addr})
	nodes[1].Join([]string{nodes[2].LocalMember().Addr})

	// Wait for convergence — all nodes should know about all others.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		allKnow := true
		for i, n := range nodes {
			count := n.MemberCount()
			if count < 3 {
				t.Logf("node-%d knows %d members", i, count)
				allKnow = false
				break
			}
		}
		if allKnow {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Verify convergence.
	for i, n := range nodes {
		count := n.MemberCount()
		if count < 3 {
			t.Errorf("node-%d: only %d members, want >= 3", i, count)
		}
	}
}

// ---------------------------------------------------------------------------
// UDP transport tests
// ---------------------------------------------------------------------------

func TestUDPTransport_BasicSendReceive(t *testing.T) {
	// Create two UDP transports.
	t1, err := NewUDPTransport("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewUDPTransport t1: %v", err)
	}
	defer t1.Close()

	t2, err := NewUDPTransport("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewUDPTransport t2: %v", err)
	}
	defer t2.Close()

	// Send from t1 to t2.
	msg := &Message{Seq: 42, Type: TypePing, Source: "t1"}
	data, err := msg.EncodeMessage()
	if err != nil {
		t.Fatalf("EncodeMessage: %v", err)
	}

	if err := t1.Send(t2.LocalAddr(), data); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Receive on t2.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	received, from, err := t2.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}

	decoded, err := DecodeMessageBytes(received)
	if err != nil {
		t.Fatalf("DecodeMessageBytes: %v", err)
	}
	if decoded.Seq != 42 {
		t.Errorf("Seq = %d, want 42", decoded.Seq)
	}
	if decoded.Source != "t1" {
		t.Errorf("Source = %q, want t1", decoded.Source)
	}

	// Verify sender address.
	host, _, _ := net.SplitHostPort(from)
	expectedHost, _, _ := net.SplitHostPort(t1.LocalAddr())
	if host != expectedHost {
		t.Errorf("from host = %q, want %q", host, expectedHost)
	}
}

func TestUDPTransport_ReceiveTimeout(t *testing.T) {
	t1, err := NewUDPTransport("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewUDPTransport: %v", err)
	}
	defer t1.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, _, err = t1.Receive(ctx)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
