package smuggling_test

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestGoStdlibResolvesRequestSmugglingBeforeTheWAF documents, with a live
// server rather than a synthetic context, why this detector's vectors do not
// fire in production — and why that is not a hole.
//
// The detector reads ctx.Headers["Content-Length"] and
// ctx.Headers["Transfer-Encoding"], but net/http deletes both from r.Header
// while parsing. A CL+TE desync request reaches the handler with both header
// values empty, r.TransferEncoding = ["chunked"] and r.ContentLength = -1:
// the stdlib has already resolved the ambiguity in favour of chunked and
// discarded the Content-Length, so no residual signal survives for a detector
// to score. The malformed variants never reach a handler at all — Go answers
// them itself with 400/501.
//
// The practical consequence is that GuardianWAF relies on net/http for
// HTTP/1.1 request-smuggling defence, and the detector's unit tests pass only
// because they populate ctx.Headers by hand. This test exists so that a future
// maintainer who notices the detector never fires does not "fix" it by trusting
// ctx.Headers, and so that the reliance on the stdlib is a recorded decision
// rather than an accident.
func TestGoStdlibResolvesRequestSmugglingBeforeTheWAF(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type seen struct {
		clHeader, teHeader string
		transferEncoding   []string
		contentLength      int64
	}
	got := make(chan seen, 1)

	srv := &http.Server{
		ReadHeaderTimeout: 2 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got <- seen{
				clHeader:         r.Header.Get("Content-Length"),
				teHeader:         r.Header.Get("Transfer-Encoding"),
				transferEncoding: r.TransferEncoding,
				contentLength:    r.ContentLength,
			}
			w.WriteHeader(http.StatusOK)
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// A classic CL.TE desync attempt.
	raw := "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
	if _, err := fmt.Fprint(conn, raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := bufio.NewReader(conn).ReadString('\n'); err != nil {
		t.Fatalf("read status line: %v", err)
	}

	select {
	case s := <-got:
		if s.clHeader != "" {
			t.Errorf("net/http now preserves Content-Length in Header (%q); the detector's header lookup may be reachable again — re-evaluate", s.clHeader)
		}
		if s.teHeader != "" {
			t.Errorf("net/http now preserves Transfer-Encoding in Header (%q); re-evaluate the detector", s.teHeader)
		}
		if len(s.transferEncoding) == 0 || s.transferEncoding[0] != "chunked" {
			t.Errorf("r.TransferEncoding = %v, want [chunked]", s.transferEncoding)
		}
		if s.contentLength != -1 {
			t.Errorf("r.ContentLength = %d, want -1 (stdlib discarded the ambiguous Content-Length)", s.contentLength)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler never ran")
	}
}
