package alerting

// Regression for the 2026-09-25 SMTP-deadline fix in email.go: both email
// delivery paths are deadline-bounded (emailDialTimeout / emailSessionTimeout,
// mirroring the webhook HTTP client's 10s/15s bounds). Previously the plain
// path (net/smtp.SendMail) dialed with a bare net.Dial and ran its textproto
// session without read/write deadlines, and sendTLS used a bare tls.Dial with
// no session deadline — an accept-then-silent server blocked its delivery
// goroutine forever, wedging one of the maxAlertDispatchConcurrency dispatch
// slots shared with webhooks and silently starving the whole alert pipeline.
// Red/green proof history:
// .temp_files/proof-driven-bug-hunter/2026-09-25-alerting-smtp-deadline/.

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// shortenEmailDeadlines bounds delivery to 0.5s dial / 1s session so
// stalled-server tests stay fast. No test in this package runs
// t.Parallel, so swapping the package vars under t.Cleanup is safe.
func shortenEmailDeadlines(t *testing.T) {
	t.Helper()
	oldDial, oldSession := emailDialTimeout, emailSessionTimeout
	emailDialTimeout = 500 * time.Millisecond
	emailSessionTimeout = 1 * time.Second
	t.Cleanup(func() {
		emailDialTimeout, emailSessionTimeout = oldDial, oldSession
	})
}

// dlBlackHoleSMTP accepts connections and never sends a byte. Accepted
// conns are retained so the client's first read blocks.
type dlBlackHoleSMTP struct {
	ln    net.Listener
	conns []net.Conn
	mu    sync.Mutex
}

func startDlBlackHoleSMTP(t *testing.T) *dlBlackHoleSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("black-hole listener: %v", err)
	}
	bh := &dlBlackHoleSMTP{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			bh.mu.Lock()
			bh.conns = append(bh.conns, conn)
			bh.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		bh.mu.Lock()
		defer bh.mu.Unlock()
		for _, c := range bh.conns {
			c.Close()
		}
	})
	return bh
}

func (bh *dlBlackHoleSMTP) port() int { return bh.ln.Addr().(*net.TCPAddr).Port }

// dlCompliantSMTP speaks enough ESMTP for a full plaintext transaction and
// counts completed (QUIT) dialogues.
type dlCompliantSMTP struct {
	ln     net.Listener
	served atomic.Int64
}

func startDlCompliantSMTP(t *testing.T) *dlCompliantSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("compliant listener: %v", err)
	}
	cs := &dlCompliantSMTP{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveDlCompliant(conn, &cs.served)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return cs
}

func serveDlCompliant(conn net.Conn, served *atomic.Int64) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	writeLine := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
	writeLine("220 dl-test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimRight(line, "\r\n"))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			writeLine("250-dl-test")
			writeLine("250 OK")
		case strings.HasPrefix(cmd, "MAIL FROM"):
			writeLine("250 OK")
		case strings.HasPrefix(cmd, "RCPT TO"):
			writeLine("250 OK")
		case strings.HasPrefix(cmd, "DATA"):
			writeLine("354 End data with <CR><LF>.<CR><LF>")
			for {
				dl, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dl, "\r\n") == "." {
					break
				}
			}
			writeLine("250 OK: message accepted")
		case strings.HasPrefix(cmd, "QUIT"):
			writeLine("221 Bye")
			served.Add(1)
			return
		default:
			writeLine("250 OK")
		}
	}
}

func (cs *dlCompliantSMTP) port() int { return cs.ln.Addr().(*net.TCPAddr).Port }

func dlEmailCfg(name string, port int, useTLS bool) config.EmailConfig {
	return config.EmailConfig{
		Name:     name,
		SMTPHost: "127.0.0.1",
		SMTPPort: port,
		From:     "waf@dl-test.test",
		To:       []string{"ops@dl-test.test"},
		Events:   []string{"all"},
		Cooldown: time.Millisecond,
		UseTLS:   useTLS,
	}
}

func dlEvent(id, ip string) *engine.Event {
	return &engine.Event{
		ID: id, Timestamp: time.Now(), ClientIP: ip,
		Method: "GET", Path: "/dl-test", Action: engine.ActionBlock,
	}
}

// sendWithin sends one email and requires the call to return within budget.
func sendWithin(t *testing.T, m *Manager, et *EmailTarget, ev *engine.Event, budget time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- m.SendEmail(et, ev) }()
	select {
	case err := <-done:
		return err
	case <-time.After(budget):
		t.Fatalf("FAIL: SendEmail still blocked after %s — delivery is not deadline-bounded", budget)
		return nil
	}
}

// The plain path must give up on an accept-then-silent server within the
// session deadline instead of blocking forever.
func TestEmailPlainSendStalledServerBounded(t *testing.T) {
	shortenEmailDeadlines(t)
	m := NewManager(nil)
	m.SetLogger(func(level, msg string) {})
	bh := startDlBlackHoleSMTP(t)
	et := NewEmailTarget(dlEmailCfg("stall-plain", bh.port(), false))
	if err := sendWithin(t, m, et, dlEvent("dl-plain-stall", "10.4.0.1"), 10*time.Second); err == nil {
		t.Fatalf("FAIL: SendEmail succeeded against a silent server")
	}
}

// The TLS path must give up during dial+handshake against a silent server
// (pre-fix: bare tls.Dial blocked forever in the handshake read).
func TestEmailTLSDialStalledServerBounded(t *testing.T) {
	shortenEmailDeadlines(t)
	m := NewManager(nil)
	m.SetLogger(func(level, msg string) {})
	bh := startDlBlackHoleSMTP(t)
	et := NewEmailTarget(dlEmailCfg("stall-tls", bh.port(), true))
	if err := sendWithin(t, m, et, dlEvent("dl-tls-stall", "10.4.0.2"), 10*time.Second); err == nil {
		t.Fatalf("FAIL: TLS SendEmail succeeded against a silent server")
	}
}

// Control: a compliant server still receives a full transaction.
func TestEmailCompliantDeliveryStillWorks(t *testing.T) {
	shortenEmailDeadlines(t)
	m := NewManager(nil)
	m.SetLogger(func(level, msg string) {})
	cs := startDlCompliantSMTP(t)
	et := NewEmailTarget(dlEmailCfg("healthy", cs.port(), false))
	if err := sendWithin(t, m, et, dlEvent("dl-compliant", "10.4.0.3"), 10*time.Second); err != nil {
		t.Fatalf("FAIL: compliant delivery errored: %v", err)
	}
	if cs.served.Load() != 1 {
		t.Fatalf("FAIL: compliant server saw %d transactions, want 1", cs.served.Load())
	}
}

// Impact regression: stalled deliveries must release their dispatch slots so
// the shared pool recovers and a healthy target gets served.
func TestEmailDispatchPoolRecoversAfterStalls(t *testing.T) {
	shortenEmailDeadlines(t)
	bh := startDlBlackHoleSMTP(t)
	cs := startDlCompliantSMTP(t)
	m := NewManagerWithEmail(nil, []config.EmailConfig{dlEmailCfg("stall", bh.port(), false)})
	m.SetLogger(func(level, msg string) {})

	for i := 0; i < maxAlertDispatchConcurrency; i++ {
		m.HandleEvent(dlEvent(fmt.Sprintf("dl-sat-%d", i), fmt.Sprintf("10.3.%d.%d", i/250, i%250+1)))
		time.Sleep(2 * time.Millisecond)
	}
	if !m.RemoveEmailTarget("stall") {
		t.Fatalf("FAIL: could not remove stalled email target")
	}
	m.AddEmailTarget(dlEmailCfg("healthy", cs.port(), false))

	recoverBy := time.Now().Add(20 * time.Second)
	delivered := false
	for i := 0; time.Now().Before(recoverBy); i++ {
		m.HandleEvent(dlEvent(fmt.Sprintf("dl-rec-%d", i), fmt.Sprintf("10.2.0.%d", i%250+1)))
		if cs.served.Load() > 0 {
			delivered = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Drain in-flight dispatch goroutines before returning: sendMailWith-
	// Deadline reads emailDialTimeout/emailSessionTimeout, and t.Cleanup's
	// restore of those vars races with any send still running (the same
	// test-global class as the round-79 flag-restore fix). In production
	// the vars are never written, so this is harness hygiene, not a fix.
	drainCtx, drainCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer drainCancel()
	_ = m.CloseWithContext(drainCtx)

	if !delivered {
		t.Fatalf("FAIL: dispatch pool never recovered after stalled deliveries — healthy target starved")
	}
}
