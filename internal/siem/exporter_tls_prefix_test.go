package siem

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: ExporterConfigFromSIEM must strip the "tls://" scheme prefix
// from the endpoint. The scheme selects the transport (UseTLS); the dialer
// must never receive it — "tls://host" is not a resolvable hostname, so every
// flush failed DNS lookup and all block/challenge events were silently lost.
// The existing TLS test constructed ExporterConfig directly with a bare
// address, bypassing the converter, which is why this survived.

func TestExporterConfigFromSIEMTLSPrefixStripped(t *testing.T) {
	c := ExporterConfigFromSIEM(config.SIEMConfig{Endpoint: "tls://siem.example.com:6514"})
	if !c.UseTLS {
		t.Fatalf("UseTLS = false, want true for tls:// endpoint")
	}
	if c.Endpoint != "siem.example.com:6514" {
		t.Fatalf("Endpoint = %q, want scheme prefix stripped", c.Endpoint)
	}

	// Plain endpoint must pass through verbatim, UseTLS false.
	p := ExporterConfigFromSIEM(config.SIEMConfig{Endpoint: "127.0.0.1:6514"})
	if p.UseTLS {
		t.Fatalf("UseTLS = true, want false for plain endpoint")
	}
	if p.Endpoint != "127.0.0.1:6514" {
		t.Fatalf("Endpoint = %q, want verbatim", p.Endpoint)
	}

	// Boundary: a scheme-only endpoint strips to empty and must be rejected
	// by NewExporter like any missing endpoint.
	bare := ExporterConfigFromSIEM(config.SIEMConfig{Endpoint: "tls://"})
	if bare.UseTLS != true || bare.Endpoint != "" {
		t.Fatalf("scheme-only endpoint: got %+v, want UseTLS=true Endpoint=\"\"", bare)
	}
	if _, err := NewExporter(bare); err == nil {
		t.Fatalf("NewExporter accepted empty endpoint after scheme strip")
	}
}

func TestExporterConfigFromSIEMTLSEndToEnd(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "regression"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		line, _ := bufio.NewReader(conn).ReadString('\n')
		received <- line
	}()

	// The operator-facing shape: scheme-prefixed endpoint straight from config.
	cfg := ExporterConfigFromSIEM(config.SIEMConfig{
		Endpoint:      "tls://" + ln.Addr().String(),
		Format:        "json",
		Timeout:       2 * time.Second,
		FlushInterval: 50 * time.Millisecond,
		BatchSize:     1,
		SkipVerify:    true,
	})
	exp, err := NewExporter(cfg)
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}

	exp.Export(engine.Event{ID: "tls-prefix-regression", Action: engine.ActionBlock, Score: 90})

	select {
	case line := <-received:
		var m map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &m); err != nil {
			t.Fatalf("delivered line is not JSON: %v (%q)", err, line)
		}
		if m["action"] != "block" {
			t.Fatalf("unexpected delivered event: %v", m)
		}
	case <-time.After(5 * time.Second):
		st := exp.Stats()
		exp.Close()
		t.Fatalf("no event delivered within 5s; Stats()=%+v", st)
	}

	exp.Close()
	if st := exp.Stats(); st.Sent < 1 || st.Failed != 0 {
		t.Fatalf("Stats()=%+v, want Sent>=1 Failed==0", st)
	}
}
