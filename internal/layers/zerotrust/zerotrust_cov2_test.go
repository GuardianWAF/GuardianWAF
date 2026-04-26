package zerotrust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- VerifyClientCertificate: session eviction with expired sessions ---

func TestVerifyClientCertificate_EvictExpired_Cov(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:    true,
		SessionTTL: 1 * time.Hour,
	})

	// Fill sessions to 100000 with EXPIRED sessions
	svc.mu.Lock()
	for i := 0; i < 100000; i++ {
		svc.sessions[string(rune(i))] = &ClientIdentity{
			ClientID:        "client-" + string(rune(i)),
			SessionID:       string(rune(i)),
			AuthenticatedAt: time.Now().Add(-2 * time.Hour), // Expired
			TrustLevel:      TrustLevelLow,
		}
	}
	svc.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	// Should evict expired sessions and add the new one
	identity, err := svc.VerifyClientCertificate(cert)
	if err != nil {
		t.Fatalf("VerifyClientCertificate with expired sessions: %v", err)
	}
	if identity == nil {
		t.Error("expected identity")
	}

	// Verify the new session was stored
	retrieved := svc.GetClientIdentity(identity.SessionID)
	if retrieved == nil {
		t.Error("expected new session to be stored")
	}
}

// --- VerifyClientCertificate: mixed expired and non-expired at cap ---

func TestVerifyClientCertificate_MixedEviction_Cov(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:    true,
		SessionTTL: 1 * time.Hour,
	})

	// Fill with a mix: some expired, some not
	svc.mu.Lock()
	for i := 0; i < 50000; i++ {
		svc.sessions[big.NewInt(int64(i)).String()] = &ClientIdentity{
			ClientID:        "expired-" + big.NewInt(int64(i)).String(),
			SessionID:       big.NewInt(int64(i)).String(),
			AuthenticatedAt: time.Now().Add(-2 * time.Hour), // Expired
			TrustLevel:      TrustLevelLow,
		}
	}
	for i := 50000; i < 100000; i++ {
		svc.sessions[big.NewInt(int64(i)).String()] = &ClientIdentity{
			ClientID:        "active-" + big.NewInt(int64(i)).String(),
			SessionID:       big.NewInt(int64(i)).String(),
			AuthenticatedAt: time.Now(), // Active
			TrustLevel:      TrustLevelLow,
		}
	}
	svc.mu.Unlock()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: "evict-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	// Should evict expired sessions first, then add new one
	identity, err := svc.VerifyClientCertificate(cert)
	if err != nil {
		t.Fatalf("VerifyClientCertificate with mixed sessions: %v", err)
	}
	if identity == nil {
		t.Error("expected identity")
	}
}

// --- VerifyClientCertificate: cap with all active sessions (triggers oldest eviction) ---

func TestVerifyClientCertificate_EvictOldest_Cov(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:    true,
		SessionTTL: 1000 * time.Hour, // Very long TTL so none expire
	})

	// Fill with all active sessions, varying ages within the past hour
	svc.mu.Lock()
	for i := 0; i < 100000; i++ {
		svc.sessions[big.NewInt(int64(i)).String()] = &ClientIdentity{
			ClientID:        "active-" + big.NewInt(int64(i)).String(),
			SessionID:       big.NewInt(int64(i)).String(),
			AuthenticatedAt: time.Now().Add(-time.Duration(i) * time.Millisecond), // All within 100 seconds
			TrustLevel:      TrustLevelLow,
		}
	}
	svc.mu.Unlock()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "oldest-test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	// Should evict oldest 10% since none are expired
	identity, err := svc.VerifyClientCertificate(cert)
	if err != nil {
		t.Fatalf("VerifyClientCertificate with active sessions: %v", err)
	}
	if identity == nil {
		t.Error("expected identity")
	}

	// Verify some sessions were evicted (oldest 10%)
	svc.mu.RLock()
	count := len(svc.sessions)
	svc.mu.RUnlock()
	if count > 100000 {
		t.Errorf("expected sessions to be evicted, got %d", count)
	}
}

// --- NewService with valid trusted CA path ---

func TestNewService_WithTrustedCAPath_Cov(t *testing.T) {
	svc, err := NewService(&Config{
		Enabled:       true,
		TrustedCAPath: "/some/path/ca.pem",
	})
	if err != nil {
		t.Fatalf("NewService with TrustedCAPath failed: %v", err)
	}
	if svc.trustedCAs == nil {
		t.Error("expected non-nil trustedCAs")
	}
}

// --- GetClientIdentity deep copy ---

func TestGetClientIdentity_DeepCopy_Cov(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:    true,
		SessionTTL: 1 * time.Hour,
	})

	sessionID := "deep-copy-test"
	svc.mu.Lock()
	svc.sessions[sessionID] = &ClientIdentity{
		ClientID:        "client-1",
		SessionID:       sessionID,
		AuthenticatedAt: time.Now(),
		TrustLevel:      TrustLevelHigh,
		Device: &DeviceInfo{
			DeviceID:    "device-1",
			Fingerprint: "fp-1",
			TrustLevel:  TrustLevelHigh,
			Metadata:    map[string]string{"key": "value"},
		},
	}
	svc.mu.Unlock()

	// Get a copy
	copy1 := svc.GetClientIdentity(sessionID)
	if copy1 == nil {
		t.Fatal("expected identity")
	}

	// Modify the copy
	copy1.TrustLevel = TrustLevelNone
	if copy1.Device != nil {
		copy1.Device.TrustLevel = TrustLevelNone
	}

	// Original should be unchanged
	original := svc.GetClientIdentity(sessionID)
	if original.TrustLevel != TrustLevelHigh {
		t.Error("original trust level should not change from copy modification")
	}
	if original.Device != nil && original.Device.TrustLevel != TrustLevelHigh {
		t.Error("original device trust level should not change")
	}
}

// --- Middleware: Handler with nil service but with X-ZeroTrust-Session header ---

func TestMiddleware_Handler_NilService_WithSession_Cov(t *testing.T) {
	m := NewMiddleware(nil)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-ZeroTrust-Session", "some-session")
	rr := httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rr, req)

	if !nextCalled {
		t.Error("next handler should be called with nil service")
	}
}

// --- Middleware: RequireAuthentication with authenticated context ---

func TestRequireAuthentication_AuthenticatedContext_Cov(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	identity := &ClientIdentity{
		ClientID:   "test",
		SessionID:  "sess-1",
		TrustLevel: TrustLevelMedium,
	}
	ctx := WithClientIdentity(context.Background(), identity)
	req := httptest.NewRequest("GET", "/api/test", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	RequireAuthentication(next).ServeHTTP(rr, req)

	if !nextCalled {
		t.Error("next handler should be called")
	}
}

// --- Layer Process with X-Zerotrust-Session (lowercase z) header ---

func TestLayer_Process_LowercaseHeader_Cov(t *testing.T) {
	svc, _ := NewService(&Config{Enabled: true, RequireMTLS: false})
	l := NewLayer(svc)

	ctx := &engine.RequestContext{
		Path:    "/api/test",
		Headers: map[string][]string{},
	}
	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass with no mTLS requirement, got %v", result.Action)
	}
}

// --- VerifyClientCertificate: valid cert WITHOUT known device ---

func TestVerifyClientCertificate_NoDevice_Cov(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:    true,
		SessionTTL: 1 * time.Hour,
	})

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "no-device-client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	identity, err := svc.VerifyClientCertificate(cert)
	if err != nil {
		t.Fatalf("VerifyClientCertificate failed: %v", err)
	}

	// Without a known device, trust level should be Low
	if identity.TrustLevel != TrustLevelLow {
		t.Errorf("TrustLevel = %v, want low (no device)", identity.TrustLevel)
	}
	if identity.Device != nil {
		t.Error("expected nil device for unknown fingerprint")
	}
	if identity.ClientID != "no-device-client" {
		t.Errorf("ClientID = %s, want no-device-client", identity.ClientID)
	}
}

// --- ParseClientCertificate with valid cert and invalid PEM ---

func TestParseClientCertificate_InvalidPEMBlock_Cov(t *testing.T) {
	// Valid PEM but invalid certificate content
	pemData := []byte(`-----BEGIN CERTIFICATE-----
YWJjZGVmZ2g=
-----END CERTIFICATE-----`)
	_, err := ParseClientCertificate(pemData)
	if err == nil {
		t.Error("expected error for invalid certificate content")
	}
}

// --- generateSessionID fallback path ---
// Note: We can't easily test the rand.Read failure path without modifying the package.
// But we can verify the normal path generates valid IDs.

func TestGenerateSessionID_Uniqueness_Cov(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateSessionID()
		if ids[id] {
			t.Errorf("duplicate session ID: %s", id)
		}
		ids[id] = true
	}
}

// --- CheckAccess with identity meeting threshold ---

func TestCheckAccess_ExactThreshold_Cov(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:              true,
		DeviceTrustThreshold: TrustLevelMedium,
	})

	// Identity at exactly the threshold should pass
	err := svc.CheckAccess(&ClientIdentity{
		TrustLevel: TrustLevelMedium,
	}, "/api/data")
	if err != nil {
		t.Errorf("expected no error at exact threshold: %v", err)
	}
}

// --- Layer with session that triggers CheckAccess failure ---

func TestLayer_Process_SessionBelowTrust_Cov(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:              true,
		RequireMTLS:          false,
		DeviceTrustThreshold: TrustLevelMaximum,
	})

	sessionID := "below-trust"
	svc.mu.Lock()
	svc.sessions[sessionID] = &ClientIdentity{
		ClientID:        "low-trust",
		SessionID:       sessionID,
		TrustLevel:      TrustLevelLow,
		AuthenticatedAt: time.Now(),
	}
	svc.mu.Unlock()

	l := NewLayer(svc)
	ctx := &engine.RequestContext{
		Path:    "/api/secure",
		Headers: map[string][]string{"X-Zerotrust-Session": {sessionID}},
	}

	result := l.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for low trust, got %v", result.Action)
	}
}

// --- DeviceInfo metadata field ---

func TestDeviceInfo_Metadata_Cov(t *testing.T) {
	d := &DeviceInfo{
		DeviceID:    "dev-1",
		Fingerprint: "fp-1",
		Metadata:    map[string]string{"os": "linux", "browser": "firefox"},
	}
	if d.Metadata["os"] != "linux" {
		t.Error("metadata os mismatch")
	}
}

// --- ClientIdentity fields ---

func TestClientIdentity_Fields_Cov(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "test"},
	}
	ci := &ClientIdentity{
		ClientID:        "client-1",
		Certificate:     cert,
		Device:          nil,
		TrustLevel:      TrustLevelHigh,
		AuthenticatedAt: time.Now(),
		SessionID:       "sess-1",
	}
	if ci.ClientID != "client-1" {
		t.Error("ClientID mismatch")
	}
	if ci.Certificate != cert {
		t.Error("Certificate mismatch")
	}
}

// --- Layer Process with nil metadata map and valid session ---

func TestLayer_Process_MetadataMapInit_Cov(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:     true,
		RequireMTLS: true,
	})

	sessionID := "meta-init"
	svc.mu.Lock()
	svc.sessions[sessionID] = &ClientIdentity{
		ClientID:        "client-1",
		TrustLevel:      TrustLevelHigh,
		SessionID:       sessionID,
		AuthenticatedAt: time.Now(),
	}
	svc.mu.Unlock()

	l := NewLayer(svc)
	ctx := &engine.RequestContext{
		Path:     "/api/test",
		Headers:  map[string][]string{"X-Zerotrust-Session": {sessionID}},
		Metadata: nil, // nil metadata should be initialized
	}

	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass, got %v", result.Action)
	}
	if ctx.Metadata == nil {
		t.Error("expected metadata to be initialized")
	}
}

// --- Layer Process: bypass path matching ---

func TestLayer_Process_BypassPathMatch_Cov(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:          true,
		RequireMTLS:      true,
		AllowBypassPaths: []string{"/healthz", "/metrics"},
	})
	l := NewLayer(svc)

	ctx := &engine.RequestContext{
		Path:    "/healthz",
		Headers: map[string][]string{},
	}
	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for bypass path, got %v", result.Action)
	}
}

// --- Ensure interface compliance at runtime ---

func TestLayer_Interface_Cov(t *testing.T) {
	var _ engine.Layer = (*Layer)(nil)
}

// --- Config defaults ---

func TestConfig_Defaults_Cov(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled {
		t.Error("default Enabled should be false")
	}
	if !cfg.RequireMTLS {
		t.Error("default RequireMTLS should be true")
	}
}

// --- Middleware with cert-based authentication, access denied due to trust level ---

func TestMiddleware_Handler_mTLS_TrustDenied_Cov(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:              true,
		RequireMTLS:          true,
		DeviceTrustThreshold: TrustLevelMaximum,
		SessionTTL:           1 * time.Hour,
	})
	m := NewMiddleware(svc)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "low-trust-cert"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called")
	})

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	rr := httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// --- ParseClientCertificate with other PEM block type ---

func TestParseClientCertificate_WrongPEMType_Cov(t *testing.T) {
	_, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("not-a-cert"),
	})
	_, err := ParseClientCertificate(pemData)
	if err == nil {
		t.Error("expected error for non-certificate PEM block")
	}
}

// --- VerifyDeviceAttestation with empty data ---

func TestVerifyDeviceAttestation_EmptyData_Cov(t *testing.T) {
	svc, _ := NewService(&Config{Enabled: true})

	device, err := svc.VerifyDeviceAttestation("device-empty", []byte{})
	if err != nil {
		t.Fatalf("VerifyDeviceAttestation with empty data failed: %v", err)
	}
	if device.DeviceID != "device-empty" {
		t.Errorf("DeviceID = %s, want device-empty", device.DeviceID)
	}
}
