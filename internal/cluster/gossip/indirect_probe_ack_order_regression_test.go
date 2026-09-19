package gossip

// Regression (bug-hunt round 2026-09-18, closing the parked note from the
// 2026-09-16-round2 hunt): indirectProbe registered its ack channel AFTER the
// PingReq send loop, while directProbe correctly registers BEFORE sending.
// An ack for the probe's seq that arrives inside that window is silently
// dropped by signalAck's map lookup (no channel registered yet), so the probe
// waits the full ProbeTimeout*2 and marks a healthy member suspect — the same
// false-suspect endpoint the round-10/25 starvation/addressing fixes had
// eliminated for every other ack timing.
//
// Reachability: over real UDP an indirect ack needs ≥3 network RTTs, so the
// send→register window (nanoseconds of the probing goroutine) cannot lose a
// production ack — this is a latent ordering defect, deterministically
// reachable through the Transport boundary (a synchronous transport delivers
// the ack inside Send). The fix mirrors directProbe: register the ack channel
// before the first PingReq hits the wire.
//
// The harness below replaces ONLY the network: every other step — seal/open
// authentication, message encode/decode, handleMessage dispatch, signalAck
// correlation, member state transitions — runs the production code.

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

// ackingTransport stands in for the UDP wire. Send unseals the outgoing
// datagram; a PingReq is answered SYNCHRONOUSLY — inside Send, before
// indirectProbe can reach registerAck — with a valid same-seq TypeAck fed
// through the real receive path (handleMessage, exactly what runReceiver
// does after open()). TypePing (direct probes) go unanswered, forcing the
// indirect path. ackSeq!=0 overrides the ack's seq for the foreign-seq
// control; ackPingReq=false disables answering entirely for the no-ack
// control.
type ackingTransport struct {
	g          *Gossip // back-reference, wired after NewWithTransport
	secret     []byte
	ackPingReq bool
	ackSeq     uint32
	local      string
}

func (t *ackingTransport) Send(addr string, data []byte) error {
	body, err := open(t.secret, data)
	if err != nil {
		return nil // not ours — drop like a foreign datagram
	}
	msg, err := DecodeMessageBytes(body)
	if err != nil {
		return nil
	}
	if msg.Type != TypePingReq || !t.ackPingReq {
		return nil
	}
	seq := msg.Seq
	if t.ackSeq != 0 {
		seq = t.ackSeq
	}
	ack := Message{Seq: seq, Type: TypeAck, Source: "peer-1"}
	ackBody, err := ack.EncodeMessage()
	if err != nil {
		return nil
	}
	t.g.handleMessage(ackBody, addr)
	return nil
}

func (t *ackingTransport) Receive(ctx context.Context) ([]byte, string, error) {
	<-ctx.Done()
	return nil, "", ctx.Err()
}

func (t *ackingTransport) LocalAddr() string { return t.local }
func (t *ackingTransport) Close() error      { return nil }

// newAckOrderTestGossip builds a Gossip on the synchronous transport with a
// healthy target and one healthy peer in the member list. ProbeTimeout is
// small so the pre-fix timeout path is fast; SuspicionTimeout is long so the
// armed suspect→dead timer never fires mid-test (Stop() cancels it anyway).
func newAckOrderTestGossip(t *testing.T, ackPingReq bool, ackSeq uint32) (*Gossip, Member) {
	t.Helper()
	secret := []byte("0123456789abcdef0123456789abcdef") // 32 bytes = MinSecretLen
	tr := &ackingTransport{secret: secret, ackPingReq: ackPingReq, ackSeq: ackSeq, local: "127.0.0.1:7946"}
	cfg := DefaultConfig("self", "")
	cfg.ProbeTimeout = 20 * time.Millisecond
	cfg.SuspicionTimeout = time.Minute
	cfg.Secret = secret
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	g, err := NewWithTransport(cfg, tr)
	if err != nil {
		t.Fatalf("setup: NewWithTransport: %v", err)
	}
	tr.g = g
	t.Cleanup(func() { g.Stop() })

	target := Member{ID: "target", Addr: "127.0.0.9:7946", Incarnation: 1, State: StateAlive}
	peer := Member{ID: "peer-1", Addr: "127.0.0.2:7946", Incarnation: 1, State: StateAlive}
	g.members.Add(target)
	g.members.Add(peer)
	return g, target
}

// TestIndirectProbeAckDeliveredDuringSendIsHonored is the defect case: the
// peer chain (peer + target healthy) answers so fast that the ack lands
// inside the PingReq send itself. The probe must honor it — the member stays
// alive and the probe does not burn the full timeout.
func TestIndirectProbeAckDeliveredDuringSendIsHonored(t *testing.T) {
	g, target := newAckOrderTestGossip(t, true, 0)

	start := time.Now()
	g.indirectProbe(target)
	elapsed := time.Since(start)

	m, ok := g.members.Get(target.ID)
	if !ok {
		t.Fatalf("FAIL: target member %q missing from the member list", target.ID)
	}
	if m.State != StateAlive {
		t.Fatalf("FAIL: an indirect ack delivered synchronously during the PingReq send (before registerAck ran) was dropped — healthy member %q marked %v after %v; the ack channel must be registered before the send loop (cf. directProbe)", target.ID, m.State, elapsed)
	}
	if elapsed >= g.config.ProbeTimeout*2 {
		t.Fatalf("FAIL: indirect probe waited the full timeout (%v) despite a same-seq ack arriving inside the send loop", elapsed)
	}
}

// Control: with no ack at all the probe must still time out and mark the
// member suspect — proves the harness observes the failure path rather than
// trivially passing.
func TestIndirectProbeMarksSuspectWhenNoAckArrives(t *testing.T) {
	g, target := newAckOrderTestGossip(t, false, 0)

	g.indirectProbe(target)

	m, ok := g.members.Get(target.ID)
	if !ok {
		t.Fatalf("FAIL: target member %q missing from the member list", target.ID)
	}
	if m.State != StateSuspect {
		t.Fatalf("FAIL: harness control — an indirect probe with no ack must mark the member suspect, got %v", m.State)
	}
}

// Control: an ack carrying a foreign seq must be ignored (seq correlation
// intact) and the probe must still mark the member suspect.
func TestIndirectProbeIgnoresAckForForeignSeq(t *testing.T) {
	g, target := newAckOrderTestGossip(t, true, 9999)

	g.indirectProbe(target)

	m, ok := g.members.Get(target.ID)
	if !ok {
		t.Fatalf("FAIL: target member %q missing from the member list", target.ID)
	}
	if m.State != StateSuspect {
		t.Fatalf("FAIL: harness control — an ack for a foreign seq must be ignored, got state %v (want suspect)", m.State)
	}
}
