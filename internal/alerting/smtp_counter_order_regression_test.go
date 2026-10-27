package alerting

import (
	"net"
	"net/smtp"
	"strings"
	"sync/atomic"
	"testing"
)

type ackCompletionGateConn struct {
	net.Conn
	release chan struct{}
}

func (c ackCompletionGateConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	if strings.HasPrefix(string(p), "221 ") {
		<-c.release
	}
	return n, e
}
func TestEmailCompletionPublishedBeforeAckReturn(t *testing.T) {
	run := func(before bool) int64 {
		server, client := net.Pipe()
		defer client.Close()
		release := make(chan struct{})
		done := make(chan struct{})
		var served atomic.Int64
		go func() { defer close(done); serveDlCompliant(ackCompletionGateConn{server, release}, &served) }()
		c, e := smtp.NewClient(client, "localhost")
		if e != nil {
			t.Fatal(e)
		}
		if e = c.Quit(); e != nil {
			t.Fatal(e)
		}
		if before {
			got := served.Load()
			close(release)
			<-done
			return got
		}
		close(release)
		<-done
		return served.Load()
	}
	if got := run(false); got != 1 {
		t.Fatalf("invalid control: %d", got)
	}
	if got := run(true); got != 1 {
		t.Fatalf("completion count after acknowledged QUIT = %d, want 1 before server Write returns", got)
	}
}
