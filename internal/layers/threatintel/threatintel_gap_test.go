package threatintel

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNewFeedManager_FallbackTransport(t *testing.T) {
	old := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = old })

	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("unused")
	})

	fm := NewFeedManager(&FeedConfig{Type: "url", URL: "https://8.8.8.8/feed"})
	if fm == nil {
		t.Fatal("expected feed manager")
	}
	if _, ok := fm.client.Transport.(*http.Transport); !ok {
		t.Fatalf("transport type = %T, want *http.Transport", fm.client.Transport)
	}
}

func TestFeedManagerHTTPClientDialContext_SplitHostPortAndDNSFailure(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{Type: "url", URL: "https://8.8.8.8/feed"})
	transport := fm.client.Transport.(*http.Transport)

	if _, err := transport.DialContext(context.Background(), "tcp", "8.8.8.8"); err == nil {
		t.Fatal("expected dial error for host without port")
	}

	if _, err := transport.DialContext(context.Background(), "tcp", "definitely-not-a-real-hostname-12345.invalid:443"); err == nil {
		t.Fatal("expected DNS lookup failure")
	}
}

func TestFeedManagerHTTPClientDialContext_PublicAddressBranch(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{Type: "url", URL: "https://8.8.8.8/feed"})
	transport := fm.client.Transport.(*http.Transport)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	conn, err := transport.DialContext(ctx, "tcp", "8.8.8.8:443")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil && conn == nil {
		t.Fatal("expected either a connection or an error")
	}
}

func TestFeedManagerHTTPClientCheckRedirect_AllowsPrivateWhenConfigured(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{Type: "url", URL: "https://8.8.8.8/feed", AllowPrivateURLs: true})
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/feed", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := fm.client.CheckRedirect(req, nil); err != nil {
		t.Fatalf("expected private redirect to be allowed, got %v", err)
	}
}

func TestFeedManagerHTTPClientCheckRedirect_AcceptsPublicURL(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{Type: "url", URL: "https://8.8.8.8/feed"})
	req, err := http.NewRequest(http.MethodGet, "http://8.8.8.8/feed", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := fm.client.CheckRedirect(req, nil); err != nil {
		t.Fatalf("expected public redirect to be allowed, got %v", err)
	}
}

func TestFeedManagerRefreshLoop_RecoversPanic(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/feed.jsonl"
	if err := osWriteFile(path, []byte(`{"ip":"1.2.3.4","score":50,"type":"test"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fm := NewFeedManager(&FeedConfig{Type: "file", Path: path, Format: "jsonl", Refresh: 5 * time.Millisecond})
	triggered := make(chan struct{})
	exited := make(chan struct{})
	fm.SetUpdateCallback(func([]ThreatEntry) {
		select {
		case <-triggered:
		default:
			close(triggered)
		}
		panic("boom")
	})

	fm.wg.Add(1)
	go func() {
		fm.refreshLoop()
		close(exited)
	}()

	select {
	case <-triggered:
	case <-time.After(time.Second):
		t.Fatal("refresh loop callback was not triggered")
	}

	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("refresh loop did not recover and exit after panic")
	}
}

func TestFeedManagerRefreshLoop_DefaultRefreshBranch(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{Refresh: 0})
	fm.wg.Add(1)
	close(fm.stopCh)
	fm.refreshLoop()
}

func TestFeedManagerLoadURL_InvalidRequestURL(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{Type: "url", URL: "%", AllowPrivateURLs: true})
	if _, err := fm.LoadOnce(context.Background()); err == nil {
		t.Fatal("expected invalid request URL error")
	}
}

func TestFeedResponseLimitReader_ReturnsEOFAtExactLimit(t *testing.T) {
	reader := limitFeedResponseReader(strings.NewReader("abc"), 3)
	buf := make([]byte, 3)

	n, err := reader.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("first read error = %v", err)
	}
	if n != 3 {
		t.Fatalf("first read bytes = %d, want 3", n)
	}

	n, err = reader.Read(buf)
	if err != io.EOF {
		t.Fatalf("second read error = %v, want EOF", err)
	}
	if n != 0 {
		t.Fatalf("second read bytes = %d, want 0", n)
	}
}

func TestParseJSONL_TruncatesAtMaxFeedEntries(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{Format: "jsonl"})
	var b strings.Builder
	for i := 0; i < maxFeedEntries+1; i++ {
		fmt.Fprintf(&b, `{"ip":"10.0.0.%d","score":1}`+"\n", i%250)
	}

	entries, err := fm.parseJSONL(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("parseJSONL failed: %v", err)
	}
	if len(entries) != maxFeedEntries {
		t.Fatalf("entries = %d, want %d", len(entries), maxFeedEntries)
	}
}

func TestParseJSON_TruncatesAtMaxFeedEntries(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{Format: "json"})
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < maxFeedEntries+1; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"ip":"10.0.1.%d","score":1}`, i%250)
	}
	b.WriteByte(']')

	entries, err := fm.parseJSON(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("parseJSON failed: %v", err)
	}
	if len(entries) != maxFeedEntries {
		t.Fatalf("entries = %d, want %d", len(entries), maxFeedEntries)
	}
}

func TestParseCSV_TruncatesAtMaxFeedEntries(t *testing.T) {
	fm := NewFeedManager(&FeedConfig{Format: "csv"})
	var b strings.Builder
	for i := 0; i < maxFeedEntries+1; i++ {
		fmt.Fprintf(&b, "10.0.2.%d,1,test,src\n", i%250)
	}

	entries, err := fm.parseCSV(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("parseCSV failed: %v", err)
	}
	if len(entries) != maxFeedEntries {
		t.Fatalf("entries = %d, want %d", len(entries), maxFeedEntries)
	}
}

func TestValidateFeedURL_ResolvedPrivateHostname(t *testing.T) {
	err := validateFeedURL("http://localhost.localdomain/feed")
	if err == nil {
		t.Fatal("expected private-resolving hostname to be rejected")
	}
	if !strings.Contains(err.Error(), "resolves to private/loopback") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateFeedURL_ResolvedPublicHostname(t *testing.T) {
	if err := validateFeedURL("https://dns.google/feed"); err != nil {
		t.Fatalf("expected public hostname to be allowed, got %v", err)
	}
}

func TestLayerOrder(t *testing.T) {
	layer, err := NewLayer(&Config{Enabled: true})
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}
	if got := layer.Order(); got != engine.OrderThreatIntel {
		t.Fatalf("Order() = %d, want %d", got, engine.OrderThreatIntel)
	}
}

func osWriteFile(name string, data []byte, perm uint32) error {
	return os.WriteFile(name, data, os.FileMode(perm))
}
