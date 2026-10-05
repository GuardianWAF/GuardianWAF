package raft

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type raftDialLifecycleConn struct{ closed atomic.Bool }

func (c *raftDialLifecycleConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *raftDialLifecycleConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *raftDialLifecycleConn) Close() error                     { c.closed.Store(true); return nil }
func (c *raftDialLifecycleConn) LocalAddr() net.Addr              { return nil }
func (c *raftDialLifecycleConn) RemoteAddr() net.Addr             { return nil }
func (c *raftDialLifecycleConn) SetDeadline(time.Time) error      { return nil }
func (c *raftDialLifecycleConn) SetReadDeadline(time.Time) error  { return nil }
func (c *raftDialLifecycleConn) SetWriteDeadline(time.Time) error { return nil }
func TestTCPTransportDiscardsLateDial(t *testing.T) {
	for _, mode := range []string{"close", "replace"} {
		started := make(chan struct{})
		release := make(chan struct{})
		done := make(chan error, 1)
		late := &raftDialLifecycleConn{}
		tr := &TCPTransport{conns: map[string]net.Conn{}, dialer: func(string, string) (net.Conn, error) { close(started); <-release; return late, nil }}
		go func() { _, err := tr.getConn("peer"); done <- err }()
		<-started
		if mode == "close" {
			tr.Close()
			tr.Close()
		} else {
			tr.SetDialer(func(string, string) (net.Conn, error) { return &raftDialLifecycleConn{}, nil })
		}
		close(release)
		err := <-done
		if err == nil || tr.hasConn("peer") || !late.closed.Load() {
			t.Fatalf("%s: err=%v pooled=%v closed=%v", mode, err, tr.hasConn("peer"), late.closed.Load())
		}
		if mode == "replace" {
			if _, err := tr.getConn("peer"); err != nil {
				t.Fatalf("new generation failed: %v", err)
			}
		}
		tr.Close()
	}
	calls := 0
	tr := &TCPTransport{conns: map[string]net.Conn{}, dialer: func(string, string) (net.Conn, error) { calls++; return &raftDialLifecycleConn{}, nil }}
	tr.Close()
	if _, err := tr.getConn("peer"); err == nil || calls != 0 {
		t.Fatal("closed transport admitted dial")
	}
	tr = &TCPTransport{conns: map[string]net.Conn{}, dialer: func(string, string) (net.Conn, error) { return nil, io.ErrUnexpectedEOF }}
	if _, err := tr.getConn("peer"); err == nil || tr.hasConn("peer") {
		t.Fatal("failed dial was pooled")
	}
	tr.Close()
	t.Log("FIX VERIFIED")
}
