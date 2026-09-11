package siem

import (
	"net"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (bug-hunt round 27): Exporter.write held the lifecycle mutex
// (e.mu) across all network I/O — the conn write and, on reconnect, the full
// dial timeout. Export takes e.mu.RLock before it does anything, so an
// unresponsive SIEM peer blocked every Export call for the whole dial window
// (default Timeout: 5s), stalling the event-bus consumer while
// EventBus.Publish silently dropped SIEM events into the overflowing
// subscriber buffer. The package contract is that Export never blocks
// ("fully asynchronous: Export never blocks the request path").
//
// The fix moved all I/O outside e.mu (the conn is goroutine-confined to the
// run goroutine; the mutex only orders the pointer). This test pins that:
// with a peer that accepts TCP but never completes the TLS handshake, the
// flush loop dials until Timeout — pre-fix each Export sample below blocked
// ~Timeout behind the in-flight dial; post-fix it stays sub-millisecond.
//
// Margins: post-fix samples measure in the µs range against a 500ms bound;
// pre-fix samples measured ~1s against a 1s dial timeout.

func TestExportNonBlockingWhileFlushDialsDeadPeer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accept-and-hold: the TLS handshake never completes, so the exporter's
	// dial blocks until its Timeout. Recycle conns after 5s.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				time.Sleep(5 * time.Second)
				_ = c.Close()
			}(c)
		}
	}()

	exp, err := NewExporter(ExporterConfig{
		Endpoint:      ln.Addr().String(),
		Format:        "cef",
		UseTLS:        true,
		Timeout:       time.Second,
		FlushInterval: 25 * time.Millisecond,
		BatchSize:     50,
	})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	defer func() { _ = exp.Close() }()

	ev := engine.Event{ID: "nonblocking-regression", Action: engine.ActionBlock, Path: "/x"}

	// Settle into the flush loop's dialing window (timer fires at 25ms; the
	// dial then holds the pre-fix mutex for ~1s out of every ~1.025s).
	time.Sleep(250 * time.Millisecond)

	var max time.Duration
	for i := 0; i < 6; i++ {
		t0 := time.Now()
		exp.Export(ev)
		if d := time.Since(t0); d > max {
			max = d
		}
		time.Sleep(10 * time.Millisecond)
	}

	if max > 500*time.Millisecond {
		t.Fatalf("FAIL: Export blocked for %v while the flush loop dialed a dead peer; flush I/O must run outside the exporter mutex", max)
	}
}
