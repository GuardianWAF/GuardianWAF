package proxy

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func init() {
	allowPrivateTargets.Store(true)
}

type hijackableRecorder struct {
	*httptest.ResponseRecorder
	conn net.Conn
	rw   *bufio.ReadWriter
	err  error
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, h.rw, h.err
}

func TestProxyErrorHijack_Unsupported(t *testing.T) {
	pe := &proxyError{ResponseWriter: httptest.NewRecorder()}
	conn, rw, err := pe.Hijack()
	if err == nil {
		t.Fatal("expected hijack error")
	}
	if conn != nil || rw != nil {
		t.Fatal("expected nil hijack results")
	}
}

func TestProxyErrorHijack_Delegates(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	rw := bufio.NewReadWriter(bufio.NewReader(clientConn), bufio.NewWriter(clientConn))
	wantErr := errors.New("sentinel hijack error")
	pe := &proxyError{ResponseWriter: &hijackableRecorder{ResponseRecorder: httptest.NewRecorder(), conn: serverConn, rw: rw, err: wantErr}}

	gotConn, gotRW, err := pe.Hijack()
	if !errors.Is(err, wantErr) {
		t.Fatalf("Hijack() error = %v, want %v", err, wantErr)
	}
	if gotConn != serverConn || gotRW != rw {
		t.Fatal("Hijack() did not delegate to underlying ResponseWriter")
	}
}

func TestTargetServeHTTP_TargetClosed(t *testing.T) {
	target, err := NewTarget("http://localhost:3000", 1)
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}
	target.Close()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if err := target.ServeHTTP(w, req, ""); err != nil {
		t.Fatalf("ServeHTTP() error = %v, want nil", err)
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("ServeHTTP() code = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(w.Body.String(), "Target closed") {
		t.Fatalf("ServeHTTP() body = %q, want target closed message", w.Body.String())
	}
}

func TestIsPrivateOrReservedIP_DNSFailureReturnsNil(t *testing.T) {
	if err := IsPrivateOrReservedIP("nonexistent.invalid"); err != nil {
		t.Fatalf("IsPrivateOrReservedIP() error = %v, want nil on lookup failure", err)
	}
}

func TestIsPrivateOrReservedIPWithPolicy_AllowPrivateShortCircuits(t *testing.T) {
	if err := IsPrivateOrReservedIPWithPolicy("127.0.0.1:8080", TargetPolicy{AllowPrivateTargets: true}); err != nil {
		t.Fatalf("IsPrivateOrReservedIPWithPolicy() error = %v, want nil", err)
	}
}

func TestIsPrivateOrReservedIPWithPolicy_HostnameBranches(t *testing.T) {
	cidrs, err := ParseAllowedUpstreamCIDRs([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatalf("ParseAllowedUpstreamCIDRs() error = %v", err)
	}
	if err := IsPrivateOrReservedIPWithPolicy("localhost", TargetPolicy{AllowedCIDRs: cidrs}); err != nil {
		t.Fatalf("IsPrivateOrReservedIPWithPolicy(localhost) error = %v, want nil", err)
	}
	if err := IsPrivateOrReservedIPWithPolicy("nonexistent.invalid", TargetPolicy{}); err != nil {
		t.Fatalf("IsPrivateOrReservedIPWithPolicy(lookup fail) error = %v, want nil", err)
	}
}

func TestClassifyIPWithAllowedCIDRs_InterfaceLocalMulticast(t *testing.T) {
	ip := net.ParseIP("ff01::1")
	if ip == nil {
		t.Fatal("expected multicast IP to parse")
	}
	if err := classifyIPWithAllowedCIDRs(ip, "ff01::1", nil); err == nil {
		t.Fatal("expected interface-local multicast to be blocked")
	}
}

func TestParseAllowedUpstreamCIDRs_AdditionalBranches(t *testing.T) {
	parsed, err := ParseAllowedUpstreamCIDRs([]string{"  ", "2001:db8::1", "224.0.0.1"})
	if err == nil {
		t.Fatal("expected multicast IP error")
	}
	if parsed != nil {
		t.Fatal("expected parsed result to be nil on error")
	}

	parsed, err = ParseAllowedUpstreamCIDRs([]string{"  ", "2001:db8::1"})
	if err != nil {
		t.Fatalf("ParseAllowedUpstreamCIDRs() error = %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("len(parsed) = %d, want 1", len(parsed))
	}
	ones, bits := parsed[0].Mask.Size()
	if ones != 128 || bits != 128 {
		t.Fatalf("IPv6 host mask = %d/%d, want 128/128", ones, bits)
	}

	if _, err := ParseAllowedUpstreamCIDRs([]string{"1.2.3.4/0"}); err == nil {
		t.Fatal("expected all-address CIDR to be rejected")
	}
}

func TestSSRFDialContextWithPolicy_NoPortAndDNSFailure(t *testing.T) {
	dial := SSRFDialContextWithPolicy(TargetPolicy{})
	if _, err := dial(context.Background(), "tcp", "nonexistent.invalid"); err == nil {
		t.Fatal("expected DNS lookup failure")
	}
}

func TestRouterServeHTTP_RetryExhaustedAfterNoHealthyTargets(t *testing.T) {
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	failURL := failServer.URL
	failServer.Close()

	failTarget, err := NewTarget(failURL, 1)
	if err != nil {
		t.Fatalf("NewTarget(fail) error = %v", err)
	}
	failTarget.circuit.threshold = 1

	spareTarget, err := NewTarget("http://spare.invalid:8080", 1)
	if err != nil {
		t.Fatalf("NewTarget(spare) error = %v", err)
	}
	spareTarget.SetHealthy(false)

	router := NewRouter([]Route{{PathPrefix: "/", Balancer: NewBalancer([]*Target{failTarget, spareTarget}, StrategyRoundRobin)}})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", strings.NewReader("body"))
	req.ContentLength = int64(len("body"))
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("ServeHTTP() code = %d, want %d", w.Code, http.StatusBadGateway)
	}
}

func TestRouterClose_NilReceiver(t *testing.T) {
	var rt *Router
	rt.Close()
}

func TestHealthCheckPolicy_DefaultBranches(t *testing.T) {
	assertZeroPolicy := func(name string, got TargetPolicy) {
		t.Helper()
		if got.AllowPrivateTargets {
			t.Fatalf("%s AllowPrivateTargets = true, want false", name)
		}
		if got.AllowedCIDRs != nil {
			t.Fatalf("%s AllowedCIDRs = %v, want nil", name, got.AllowedCIDRs)
		}
	}

	assertZeroPolicy("nil", healthCheckPolicy(nil))
	assertZeroPolicy("empty", healthCheckPolicy(NewBalancer(nil, StrategyRoundRobin)))
	assertZeroPolicy("nil target", healthCheckPolicy(NewBalancer([]*Target{nil}, StrategyRoundRobin)))
}

func TestMinHealthCheckDuration_Branches(t *testing.T) {
	if got := minHealthCheckDuration(0, time.Second); got != time.Second {
		t.Fatalf("minHealthCheckDuration(0, 1s) = %v, want 1s", got)
	}
	if got := minHealthCheckDuration(2*time.Second, time.Second); got != time.Second {
		t.Fatalf("minHealthCheckDuration(2s, 1s) = %v, want 1s", got)
	}
	if got := minHealthCheckDuration(500*time.Millisecond, time.Second); got != 500*time.Millisecond {
		t.Fatalf("minHealthCheckDuration(500ms, 1s) = %v, want 500ms", got)
	}
}
