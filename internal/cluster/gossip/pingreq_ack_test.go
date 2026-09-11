package gossip

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// Regression: two defects in the same seam made indirect probes (PingReq)
// unsatisfiable, so one failed direct probe marked a healthy member suspect
// (→ dead → Raft peer eviction via the peer-sync bridge):
//
//  1. handlePingReq ran the blocking probe inline on the single receiver
//     goroutine — starving that goroutine of exactly the target's ack the
//     wait depends on, so every indirect probe timed out by construction.
//  2. The completion ack was addressed to msg.Source — an opaque node ID,
//     not a routable address — so even a correctly-probed target's ack was
//     never delivered (handlePing/handlePushPull already answered `from`).
//
// This test exercises the real wire path: a live target, a live witness, and
// a raw requester socket sending an authenticated PingReq whose Source is a
// non-routable node ID (the production shape: cfg.Cluster.NodeID is a
// free-form operator string). The requester must receive the witness's ack.
func TestPingReqAckReachesRequesterAddress(t *testing.T) {
	secret := []byte("pingreq-ack-regression-test-secret-0123456789abcdef")

	newNode := func(id string) *Gossip {
		cfg := DefaultConfig(id, "127.0.0.1:0")
		cfg.Secret = secret
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
		g, err := New(cfg)
		if err != nil {
			t.Fatalf("New(%s): %v", id, err)
		}
		if err := g.Start(); err != nil {
			t.Fatalf("Start(%s): %v", id, err)
		}
		t.Cleanup(g.Stop)
		return g
	}

	target := newNode("test-target")
	witness := newNode("test-witness")
	targetAddr := target.LocalMember().Addr
	witnessAddr := witness.LocalMember().Addr

	req, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("requester socket: %v", err)
	}
	defer req.Close()

	send := func(addr string, msg Message) {
		t.Helper()
		var body bytes.Buffer
		if err := msg.Encode(&body); err != nil {
			t.Fatalf("encode: %v", err)
		}
		uaddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			t.Fatalf("resolve %s: %v", addr, err)
		}
		if _, err := req.WriteToUDP(sealForTest(secret, body.Bytes()), uaddr); err != nil {
			t.Fatalf("send to %s: %v", addr, err)
		}
	}

	// Positive control: the target acks a direct ping unconditionally. Proves
	// the crafted datagrams are well-formed and handled end-to-end.
	send(targetAddr, Message{Seq: 7, Type: TypePing, Source: "test-requester"})
	assertAck(t, req, secret, 7, 3*time.Second)

	// Defect path: the witness must probe the live target and ack the
	// requester's transport address (not the opaque node ID).
	send(witnessAddr, Message{Seq: 42, Type: TypePingReq, Source: "test-requester", Payload: []byte(targetAddr)})
	assertAck(t, req, secret, 42, 5*time.Second)
}

// sealForTest mirrors auth.go seal(): body || nonce || ts || HMAC-SHA256.
func sealForTest(secret, body []byte) []byte {
	out := make([]byte, 0, len(body)+authTrailerSize)
	out = append(out, body...)
	nonce := make([]byte, authNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	out = append(out, nonce...)
	var ts [authTimestampSize]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixNano()))
	out = append(out, ts[:]...)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(out)
	return mac.Sum(out)
}

// assertAck waits for one authenticated datagram and checks its seq/type.
func assertAck(t *testing.T, conn *net.UDPConn, secret []byte, wantSeq uint32, deadline time.Duration) {
	t.Helper()
	buf := make([]byte, 65507)
	if err := conn.SetReadDeadline(time.Now().Add(deadline)); err != nil {
		t.Fatalf("read deadline: %v", err)
	}
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no ack within %s: %v", deadline, err)
	}
	const trailer = authNonceSize + authTimestampSize + authTagSize
	if n < trailer+8 {
		t.Fatalf("short datagram (%d bytes)", n)
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(buf[:n-authTagSize])
	if !hmac.Equal(buf[n-authTagSize:n], mac.Sum(nil)) {
		t.Fatalf("ack failed authentication")
	}
	body := buf[:n-trailer]
	if len(body) < 8 {
		t.Fatalf("ack body too short (%d bytes)", len(body))
	}
	seq := binary.LittleEndian.Uint32(body[0:4])
	mt := MessageType(body[4])
	if seq != wantSeq || mt != TypeAck {
		t.Fatalf("reply seq=%d type=%v (want seq=%d ACK)", seq, mt, wantSeq)
	}
}
