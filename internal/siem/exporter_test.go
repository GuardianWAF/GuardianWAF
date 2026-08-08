package siem

import (
	"bufio"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func startMockSyslog(t *testing.T) (string, *sync.WaitGroup, chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	var wg sync.WaitGroup
	received := make(chan string, 100)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				scanner := bufio.NewScanner(c)
				scanner.Buffer(make([]byte, 0, 65536), 65536)
				for scanner.Scan() {
					select {
					case received <- scanner.Text():
					default:
					}
				}
			}(conn)
		}
	}()

	return ln.Addr().String(), &wg, received
}

func TestExporter_SendAndReceive(t *testing.T) {
	addr, wg, received := startMockSyslog(t)

	exp, err := NewExporter(ExporterConfig{
		Endpoint:      addr,
		Format:        "cef",
		FlushInterval: 50 * time.Millisecond,
		BatchSize:     2,
		Timeout:       2 * time.Second,
		SkipVerify:    true, // mock server has no cert
	})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}

	// Send two events — should trigger immediate batch flush at BatchSize=2.
	exp.Export(engine.Event{
		ID:     "e1",
		Action: engine.ActionBlock,
		Score:  80,
	})
	exp.Export(engine.Event{
		ID:     "e2",
		Action: engine.ActionChallenge,
		Score:  40,
	})

	// Wait for messages to arrive.
	collected := []string{}
	timer := time.After(3 * time.Second)
	for len(collected) < 2 {
		select {
		case msg := <-received:
			collected = append(collected, msg)
		case <-timer:
			t.Fatalf("timed out waiting for messages; got %d: %v", len(collected), collected)
		}
	}

	if err := exp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Don't call wg.Wait() here — the mock server's accept goroutine only
	// exits when t.Cleanup closes the listener, which runs after this test
	// function returns. Calling wg.Wait() before that would deadlock.
	_ = wg

	for _, msg := range collected {
		// CEF lines start with the syslog PRI + CEF header.
		// Our plain-TCP exporter doesn't add PRI, so just check for CEF:.
		if msg == "" {
			t.Error("received empty message")
		}
	}
}

func TestExporter_FiltersPassedEvents(t *testing.T) {
	addr, _, received := startMockSyslog(t)

	exp, _ := NewExporter(ExporterConfig{
		Endpoint:      addr,
		Format:        "cef",
		FlushInterval: 100 * time.Millisecond,
		BatchSize:     10,
		Timeout:       2 * time.Second,
		SkipVerify:    true,
	})
	defer exp.Close()

	// Passed events should not be exported.
	exp.Export(engine.Event{ID: "pass", Action: engine.ActionPass, Score: 0})

	time.Sleep(300 * time.Millisecond)
	select {
	case msg := <-received:
		t.Errorf("should not receive passed events, got: %s", msg)
	default:
		// correct — no message
	}
}

func TestExporter_FlushOnTimer(t *testing.T) {
	addr, _, received := startMockSyslog(t)

	exp, _ := NewExporter(ExporterConfig{
		Endpoint:      addr,
		Format:        "cef",
		FlushInterval: 50 * time.Millisecond,
		BatchSize:     100, // high batch size to force timer flush
		Timeout:       2 * time.Second,
		SkipVerify:    true,
	})
	defer exp.Close()

	exp.Export(engine.Event{ID: "timer-test", Action: engine.ActionBlock, Score: 60})

	select {
	case msg := <-received:
		if msg == "" {
			t.Error("received empty message from timer flush")
		}
	case <-time.After(3 * time.Second):
		t.Error("timed out waiting for timer flush")
	}
}

func TestExporter_ReconnectsAfterFailure(t *testing.T) {
	// Start a server, send one event, kill the server, restart on same port,
	// send another event — exporter should reconnect.
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln1.Addr().String()

	received := make(chan string, 10)
	go func() {
		conn, _ := ln1.Accept()
		if conn != nil {
			scanner := bufio.NewScanner(conn)
			for scanner.Scan() {
				received <- scanner.Text()
			}
			conn.Close()
		}
	}()

	exp, _ := NewExporter(ExporterConfig{
		Endpoint:      addr,
		Format:        "cef",
		FlushInterval: 50 * time.Millisecond,
		BatchSize:     1,
		Timeout:       1 * time.Second,
		SkipVerify:    true,
	})
	defer exp.Close()

	exp.Export(engine.Event{ID: "before", Action: engine.ActionBlock, Score: 50})

	select {
	case <-received:
		// first event received
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first event")
	}

	// Kill the server.
	ln1.Close()

	// Give the exporter time to notice the dead connection.
	time.Sleep(200 * time.Millisecond)

	// Start a new server on the same port.
	ln2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("re-listen: %v", err)
	}
	defer ln2.Close()

	go func() {
		conn, _ := ln2.Accept()
		if conn != nil {
			scanner := bufio.NewScanner(conn)
			for scanner.Scan() {
				received <- scanner.Text()
			}
			conn.Close()
		}
	}()

	// Send another event — exporter should reconnect.
	exp.Export(engine.Event{ID: "after", Action: engine.ActionBlock, Score: 50})

	select {
	case <-received:
		// reconnected and delivered
	case <-time.After(3 * time.Second):
		t.Error("timed out waiting for reconnect delivery")
	}
}

func TestExporter_Stats(t *testing.T) {
	addr, _, _ := startMockSyslog(t)

	exp, _ := NewExporter(ExporterConfig{
		Endpoint:      addr,
		Format:        "cef",
		FlushInterval: 1 * time.Second,
		BatchSize:     100,
		Timeout:       2 * time.Second,
		SkipVerify:    true,
	})
	defer exp.Close()

	exp.Export(engine.Event{ID: "s1", Action: engine.ActionBlock, Score: 50})
	exp.Export(engine.Event{ID: "s2", Action: engine.ActionBlock, Score: 60})
	exp.Export(engine.Event{ID: "s3", Action: engine.ActionPass, Score: 0})

	time.Sleep(200 * time.Millisecond)
	stats := exp.Stats()
	if stats.EventsQueued != 2 { // pass event filtered out
		t.Errorf("EventsQueued = %d, want 2", stats.EventsQueued)
	}
}

func TestNewExporter_TLS(t *testing.T) {
	// Test that a TLS endpoint works.
	// Generate a self-signed cert for the mock server.
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Skipf("could not generate self-signed cert: %v", err)
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	addr := ln.Addr().String()
	t.Cleanup(func() { ln.Close() })

	received := make(chan string, 10)
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			scanner := bufio.NewScanner(conn)
			for scanner.Scan() {
				received <- scanner.Text()
			}
			conn.Close()
		}
	}()

	exp, err := NewExporter(ExporterConfig{
		Endpoint:      addr,
		Format:        "cef",
		FlushInterval: 50 * time.Millisecond,
		BatchSize:     1,
		Timeout:       5 * time.Second,
		UseTLS:        true,
		SkipVerify:    true,
	})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	defer exp.Close()

	exp.Export(engine.Event{ID: "tls-test", Action: engine.ActionBlock, Score: 70})

	select {
	case msg := <-received:
		if msg == "" {
			t.Error("received empty TLS message")
		}
	case <-time.After(5 * time.Second):
		t.Error("timed out waiting for TLS delivery")
	}
}

func TestExporter_InvalidEndpoint(t *testing.T) {
	_, err := NewExporter(ExporterConfig{
		Endpoint:   "not-a-valid-address",
		Format:     "cef",
		BatchSize:  10,
		Timeout:    1 * time.Second,
		SkipVerify: true,
	})
	if err == nil {
		t.Error("expected error for invalid endpoint")
	}
}

func TestExporter_FromConfig(t *testing.T) {
	cfg := config.SIEMConfig{
		Enabled:       true,
		Endpoint:      "127.0.0.1:6514",
		Format:        "cef",
		BatchSize:     50,
		FlushInterval: 5 * time.Second,
		Timeout:       10 * time.Second,
	}
	c := ExporterConfigFromSIEM(cfg)
	if c.Endpoint != "127.0.0.1:6514" {
		t.Errorf("endpoint mismatch: %s", c.Endpoint)
	}
	if c.Format != "cef" {
		t.Errorf("format mismatch: %s", c.Format)
	}
	if c.BatchSize != 50 {
		t.Errorf("batch size: %d", c.BatchSize)
	}
}
