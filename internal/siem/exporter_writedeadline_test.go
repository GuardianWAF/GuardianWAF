package siem

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression (bug-hunt round 28): the exporter never applied a write
// deadline — ExporterConfig.Timeout is documented as "connect/write timeout"
// but only the connect half was implemented. A peer that completes the TCP
// connect but never drains (hung collector, NAT half-open, partition without
// RST) wedged the flush goroutine FOREVER inside a kernel write: Sent,
// Failed, and Connects froze and every subsequent event was dropped until
// process restart.
//
// The fix bounds every conn write by cfg.Timeout (writeWithTimeout), so a
// stalled write returns at the deadline, the conn is closed, and the normal
// reconnect path resumes. This test pins the recovery contract: against a
// peer that accepts but never reads, flush attempts must keep happening —
// pre-fix the counters freeze permanently (proven: failed 0→0, sent 40→40,
// connects 1→1 over 8s), post-fix they advance every deadline cycle.

func TestExporterRecoversFromNeverDrainingPeer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accept-and-hold, NEVER read: kernel buffers are the only sink.
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
		Timeout:       time.Second, // documented connect/write timeout
		FlushInterval: 50 * time.Millisecond,
		BatchSize:     20,
	})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	defer func() { _ = exp.Close() }()

	// Phase 1: saturate the peer's kernel buffers (~30MB/s offered vs socket
	// buffers of a few hundred KB at most).
	ev := engine.Event{ID: "write-deadline-regression", Action: engine.ActionBlock, Path: strings.Repeat("A", 64<<10)}
	saturate := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(saturate) {
		exp.Export(ev)
	}

	// Phase 2: the recovery contract — flush attempts must keep happening
	// within the observation window.
	s0 := exp.Stats()
	time.Sleep(6 * time.Second)
	s1 := exp.Stats()

	attempts := (s1.Failed - s0.Failed) + (s1.Sent - s0.Sent)
	reconnects := s1.Connects - s0.Connects
	t.Logf("post-saturation window: attempts=%d reconnects=%d (failed %d→%d, sent %d→%d)",
		attempts, reconnects, s0.Failed, s1.Failed, s0.Sent, s1.Sent)

	if attempts < 2 || reconnects < 1 {
		t.Fatalf("FAIL: flush wedged permanently against a never-draining peer: attempts=%d reconnects=%d in 6s — conn writes must be bounded by the configured timeout", attempts, reconnects)
	}
}
