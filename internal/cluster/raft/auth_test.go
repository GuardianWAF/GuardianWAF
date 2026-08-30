package raft

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// TestTransportRejectsUnauthenticatedPeer is the regression test for the
// cluster's most serious gap: the Raft transport accepted any TCP connection
// and dispatched every frame straight into the state machine. Because
// handleAppendEntries trusts the term and leader ID it is given, and the
// replicated commands are CmdBanIP / CmdUnbanIP / CmdSetRule / CmdDeleteRule,
// reaching the port was equivalent to controlling WAF enforcement fleet-wide.
func TestTransportRejectsUnauthenticatedPeer(t *testing.T) {
	tr, err := NewTCPTransport("127.0.0.1:0", "node-a", time.Second, testSecret)
	if err != nil {
		t.Fatalf("NewTCPTransport: %v", err)
	}
	defer tr.Close()

	handled := make(chan struct{}, 1)
	tr.SetHandler(func(RPCType, []byte) ([]byte, error) {
		handled <- struct{}{}
		return nil, nil
	})
	if err := tr.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	conn, err := net.Dial("tcp", tr.LocalAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// An attacker who does not hold the cluster secret sends a well-formed but
	// unauthenticated AppendEntries claiming a huge term.
	payload := []byte(`{"term":999999,"leader_id":"attacker"}`)
	if err := EncodeRequest(conn, RPCAppendEntriesRequest, payload); err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}

	select {
	case <-handled:
		t.Fatal("unauthenticated frame reached the Raft handler")
	case <-time.After(250 * time.Millisecond):
		// Correct: the frame was dropped before dispatch.
	}
}

// TestTransportRejectsWrongSecret confirms a peer holding a different secret is
// not admitted.
func TestTransportRejectsWrongSecret(t *testing.T) {
	tr, err := NewTCPTransport("127.0.0.1:0", "node-a", time.Second, testSecret)
	if err != nil {
		t.Fatalf("NewTCPTransport: %v", err)
	}
	defer tr.Close()

	handled := make(chan struct{}, 1)
	tr.SetHandler(func(RPCType, []byte) ([]byte, error) {
		handled <- struct{}{}
		return nil, nil
	})
	if err := tr.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	conn, err := net.Dial("tcp", tr.LocalAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	wrong := []byte("a-different-cluster-secret-0123456789abc")
	if err := EncodeAuthenticatedRequest(conn, wrong, RPCAppendEntriesRequest, []byte(`{"term":1}`)); err != nil {
		t.Fatalf("EncodeAuthenticatedRequest: %v", err)
	}

	select {
	case <-handled:
		t.Fatal("frame signed with the wrong secret reached the Raft handler")
	case <-time.After(250 * time.Millisecond):
	}
}

// TestTransportRequiresSecret pins the fail-closed constructor.
func TestTransportRequiresSecret(t *testing.T) {
	for _, secret := range [][]byte{nil, {}, []byte("short")} {
		if _, err := NewTCPTransport("127.0.0.1:0", "node-a", time.Second, secret); !errors.Is(err, ErrSecretRequired) {
			t.Fatalf("NewTCPTransport with %d-byte secret: err = %v, want ErrSecretRequired", len(secret), err)
		}
	}
}

// TestSealOpenRoundTrip covers the happy path plus tampering and expiry.
func TestSealOpenRoundTrip(t *testing.T) {
	payload := []byte(`{"term":7,"leader_id":"node-a"}`)

	sealed, err := sealPayload(testSecret, RPCAppendEntriesRequest, payload)
	if err != nil {
		t.Fatalf("sealPayload: %v", err)
	}

	got, err := openPayload(testSecret, RPCAppendEntriesRequest, sealed)
	if err != nil {
		t.Fatalf("openPayload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round trip = %q, want %q", got, payload)
	}

	t.Run("tampered payload is rejected", func(t *testing.T) {
		bad := bytes.Clone(sealed)
		bad[0] ^= 0xFF
		if _, err := openPayload(testSecret, RPCAppendEntriesRequest, bad); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("err = %v, want ErrUnauthenticated", err)
		}
	})

	t.Run("replaying under a different RPC type is rejected", func(t *testing.T) {
		if _, err := openPayload(testSecret, RPCRequestVoteRequest, sealed); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("err = %v, want ErrUnauthenticated", err)
		}
	})

	t.Run("stale frame is rejected", func(t *testing.T) {
		restore := timeNow
		timeNow = func() time.Time { return restore().Add(authMaxSkew + time.Minute) }
		defer func() { timeNow = restore }()

		if _, err := openPayload(testSecret, RPCAppendEntriesRequest, sealed); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("err = %v, want ErrUnauthenticated", err)
		}
	})

	t.Run("truncated frame is rejected", func(t *testing.T) {
		if _, err := openPayload(testSecret, RPCAppendEntriesRequest, sealed[:authTrailerSize-1]); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("err = %v, want ErrUnauthenticated", err)
		}
	})
}

// TestAuthenticatedPeersInteroperate confirms the added authentication does not
// break legitimate peer traffic.
func TestAuthenticatedPeersInteroperate(t *testing.T) {
	tr, err := NewTCPTransport("127.0.0.1:0", "node-a", 2*time.Second, testSecret)
	if err != nil {
		t.Fatalf("NewTCPTransport: %v", err)
	}
	defer tr.Close()

	tr.SetHandler(func(_ RPCType, payload []byte) ([]byte, error) {
		return append([]byte("echo:"), payload...), nil
	})
	if err := tr.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	client, err := NewTCPTransport("127.0.0.1:0", "node-b", 2*time.Second, testSecret)
	if err != nil {
		t.Fatalf("client transport: %v", err)
	}
	defer client.Close()

	_, resp, err := client.SendRPC(tr.LocalAddr(), RPCAppendEntriesRequest, []byte("hello"))
	if err != nil {
		t.Fatalf("SendRPC between authenticated peers failed: %v", err)
	}
	if string(resp) != "echo:hello" {
		t.Fatalf("resp = %q, want %q", resp, "echo:hello")
	}
}
