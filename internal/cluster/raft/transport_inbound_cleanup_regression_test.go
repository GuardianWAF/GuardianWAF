package raft

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

type raftInboundCleanupConn struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
	closed  atomic.Bool
}

func (c *raftInboundCleanupConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Read(p)
}
func (c *raftInboundCleanupConn) Close() error { c.closed.Store(true); return c.Conn.Close() }

func TestTCPTransportClosesAcceptedSockets(t *testing.T) {
	for _, mode := range []string{"blocked", "peer-close", "late"} {
		t.Run(mode, func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()
			in := &raftInboundCleanupConn{Conn: server, entered: make(chan struct{})}
			tr := &TCPTransport{conns: map[string]net.Conn{}, secret: []byte("0123456789abcdef0123456789abcdef")}
			done := make(chan struct{})
			release := make(chan struct{})
			go func() { <-release; tr.handleConn(in); close(done) }()
			if mode == "late" {
				tr.Close()
			}
			close(release)
			if mode != "late" {
				<-in.entered
				if mode == "peer-close" {
					client.Close()
					<-done
				}
				if err := tr.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if mode != "peer-close" {
				<-done
			}
			if !in.closed.Load() {
				t.Fatal("socket not closed")
			}
			tr.Close()
			tr.Close()
			tr.connMu.Lock()
			n := len(tr.inbound)
			tr.connMu.Unlock()
			if n != 0 {
				t.Fatalf("accepted sockets retained: %d", n)
			}
			if mode == "late" {
				select {
				case <-in.entered:
					t.Fatal("read started after shutdown")
				default:
				}
			}
		})
	}
}
