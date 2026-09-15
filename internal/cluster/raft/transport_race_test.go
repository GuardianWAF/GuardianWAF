package raft

import (
	"net"
	"strings"
	"sync"
	"testing"
)

// SetDialer writes t.dialer under connMu; getConn used to read the field
// AFTER unlocking connMu, racing with SetDialer (the documented runtime
// partition-simulation entry point — the clustersync partition tests swap
// the dialer while heartbeat/election goroutines dial concurrently). Run
// under -race: the unsynchronized read/write fired the detector pre-fix.

func TestTCPTransport_SetDialerConcurrentWithDial(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32)) // MinSecretLen
	tr, err := NewTCPTransport("127.0.0.1:0", "test", 0, secret)
	if err != nil {
		t.Fatalf("transport setup: %v", err)
	}
	defer tr.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			tr.SetDialer(net.Dial)
		}
	}()

	go func() {
		defer wg.Done()
		// 127.0.0.1:1 refuses instantly, so every SendRPC takes the dial
		// path and reads t.dialer.
		for i := 0; i < 500; i++ {
			_, _, _ = tr.SendRPC("127.0.0.1:1", RPCRequestVoteRequest, nil)
		}
	}()

	wg.Wait()
}
