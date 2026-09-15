package raft

import (
	"strings"
	"testing"
	"time"
)

// The server reaps connections idle past timeout*10 (handleConn's read
// deadline), but the client pool holds its connection indefinitely — the
// first RPC after each idle window used to fail on the stale pooled
// connection (broken pipe). SendRPC now heals the stale pool with one
// fresh-connection attempt (only when a pooled connection was reused;
// fresh-dial failures are not retried, so partition behavior is unchanged).

func TestTCPTransport_StalePooledConnectionHealed(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	srv, err := NewTCPTransport("127.0.0.1:0", "srv", 30*time.Millisecond, secret)
	if err != nil {
		t.Fatalf("server setup: %v", err)
	}
	defer srv.Close()
	srv.SetHandler(func(_ RPCType, p []byte) ([]byte, error) { return p, nil })
	if err := srv.Start(); err != nil {
		t.Fatalf("server start: %v", err)
	}

	client, err := NewTCPTransport("127.0.0.1:0", "client", 500*time.Millisecond, secret)
	if err != nil {
		t.Fatalf("client setup: %v", err)
	}
	defer client.Close()

	if _, _, err := client.SendRPC(srv.LocalAddr(), RPCRequestVoteRequest, []byte("ping")); err != nil {
		t.Fatalf("pool warm-up RPC: %v", err)
	}

	// Idle past the server's reap window (30ms * 10 = 300ms).
	time.Sleep(800 * time.Millisecond)

	respType, payload, err := client.SendRPC(srv.LocalAddr(), RPCRequestVoteRequest, []byte("ping"))
	if err != nil {
		t.Fatalf("first RPC after idle window failed (stale pooled connection not healed): %v", err)
	}
	if respType != RPCRequestVoteResponse || string(payload) != "ping" {
		t.Errorf("unexpected response respType=%v payload=%q", respType, string(payload))
	}
}
