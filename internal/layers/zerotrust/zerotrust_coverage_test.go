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

// --- Middleware tests ---

func TestMiddleware_Handler_NilService(t *testing.T) {
	m := NewMiddleware(nil)

	handlerCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	req := httptest.NewRequest("GET", "/api/test", nil)
	rr := httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("next handler should be called when service is nil")
	}
}

func TestMiddleware_Handler_DisabledService(t *testing.T) {
	svc, _ := NewService(&Config{Enabled: false})
	m := NewMiddleware(svc)

	handlerCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	req := httptest.NewRequest("GET", "/api/test", nil)
	rr := httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("next handler should be called when service is disabled")
	}
}

func TestMiddleware_Handler_BypassPath(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:          true,
		RequireMTLS:      true,
		AllowBypassPaths: []string{"/healthz"},
	})
	m := NewMiddleware(svc)

	handlerCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	req := httptest.NewRequest("GET", "/healthz", nil)
	rr := httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("next handler should be called for bypass path")
	}
}

func TestMiddleware_Handler_ValidSession(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:     true,
		RequireMTLS: true,
		SessionTTL:  1 * time.Hour,
	})

	// Register a session
	sessionID := "test-sess-mw"
	svc.mu.Lock()
	svc.sessions[sessionID] = &ClientIdentity{
		ClientID:        "client-1",
		TrustLevel:      TrustLevelHigh,
		SessionID:       sessionID,
		AuthenticatedAt: time.Now(),
	}
	svc.mu.Unlock()

	m := NewMiddleware(svc)

	handlerCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		// Verify identity is in context
		identity := GetClientIdentityFromContext(r.Context())
		if identity == nil || identity.ClientID != "client-1" {
			t.Error("expected client identity in context")
		}
	})

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("X-ZeroTrust-Session", sessionID)
	rr := httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("next handler should be called")
	}
}

func TestMiddleware_Handler_InvalidSession_NoMTLS(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:     true,
		RequireMTLS: false,
	})
	m := NewMiddleware(svc)

	handlerCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("X-ZeroTrust-Session", "invalid-session")
	rr := httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("next handler should be called when mTLS not required and session invalid")
	}
}

func TestMiddleware_Handler_InvalidSession_RequireMTLS_NoCert(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:     true,
		RequireMTLS: true,
	})
	m := NewMiddleware(svc)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called")
	})

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("X-ZeroTrust-Session", "invalid-session")
	rr := httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestMiddleware_Handler_SessionAccessDenied(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:              true,
		RequireMTLS:          false,
		DeviceTrustThreshold: TrustLevelHigh,
	})

	// Register a session with low trust
	sessionID := "low-trust-sess"
	svc.mu.Lock()
	svc.sessions[sessionID] = &ClientIdentity{
		ClientID:        "low-client",
		TrustLevel:      TrustLevelLow,
		SessionID:       sessionID,
		AuthenticatedAt: time.Now(),
	}
	svc.mu.Unlock()

	m := NewMiddleware(svc)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called")
	})

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("X-ZeroTrust-Session", sessionID)
	rr := httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestMiddleware_Handler_mTLS_WithCert(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:     true,
		RequireMTLS: true,
		SessionTTL:  1 * time.Hour,
	})
	m := NewMiddleware(svc)

	// Build a self-signed cert for testing
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	handlerCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		// Verify identity is in context
		identity := GetClientIdentityFromContext(r.Context())
		if identity == nil {
			t.Error("expected identity in context")
		}
	})

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	rr := httptest.NewRecorder()
	m.Handler(next).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("next handler should be called with valid cert")
	}
	// Verify session ID header was set
	if rr.Header().Get("X-ZeroTrust-Session") == "" {
		t.Error("expected X-ZeroTrust-Session header in response")
	}
}

func TestMiddleware_Handler_mTLS_ExpiredCert(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:     true,
		RequireMTLS: true,
	})
	m := NewMiddleware(svc)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour), // expired
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

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestMiddleware_authenticateWithCertificate_NoTLS(t *testing.T) {
	svc, _ := NewService(&Config{Enabled: true})
	m := NewMiddleware(svc)

	req := httptest.NewRequest("GET", "/api/test", nil)
	// req.TLS is nil
	_, err := m.authenticateWithCertificate(req)
	if err == nil {
		t.Error("expected error when no TLS state")
	}
}

func TestMiddleware_authenticateWithCertificate_NoPeerCerts(t *testing.T) {
	svc, _ := NewService(&Config{Enabled: true})
	m := NewMiddleware(svc)

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.TLS = &tls.ConnectionState{} // no peer certificates
	_, err := m.authenticateWithCertificate(req)
	if err == nil {
		t.Error("expected error when no peer certificates")
	}
}

// --- RequireAuthentication middleware ---

func TestRequireAuthentication_Unauthenticated(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called")
	})

	req := httptest.NewRequest("GET", "/api/test", nil)
	rr := httptest.NewRecorder()
	RequireAuthentication(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestRequireAuthentication_Authenticated(t *testing.T) {
	handlerCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	identity := &ClientIdentity{
		ClientID:  "test",
		SessionID: "sess-1",
	}
	ctx := WithClientIdentity(context.Background(), identity)
	req := httptest.NewRequest("GET", "/api/test", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	RequireAuthentication(next).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("next handler should be called for authenticated request")
	}
}

// --- RequireTrustLevel middleware ---

func TestRequireTrustLevel_Insufficient(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called")
	})

	identity := &ClientIdentity{
		ClientID:   "test",
		TrustLevel: TrustLevelLow,
	}
	ctx := WithClientIdentity(context.Background(), identity)
	req := httptest.NewRequest("GET", "/api/test", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	RequireTrustLevel(TrustLevelHigh)(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestRequireTrustLevel_Sufficient(t *testing.T) {
	handlerCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	identity := &ClientIdentity{
		ClientID:   "test",
		TrustLevel: TrustLevelHigh,
	}
	ctx := WithClientIdentity(context.Background(), identity)
	req := httptest.NewRequest("GET", "/api/test", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	RequireTrustLevel(TrustLevelMedium)(next).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("next handler should be called with sufficient trust level")
	}
}

func TestRequireTrustLevel_NoIdentity(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called")
	})

	req := httptest.NewRequest("GET", "/api/test", nil)
	rr := httptest.NewRecorder()
	RequireTrustLevel(TrustLevelLow)(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

// --- VerifyClientCertificate valid cert paths ---

func TestVerifyClientCertificate_ValidCert(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:    true,
		SessionTTL: 1 * time.Hour,
	})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	identity, err := svc.VerifyClientCertificate(cert)
	if err != nil {
		t.Fatalf("VerifyClientCertificate failed: %v", err)
	}

	if identity.ClientID != "test-client" {
		t.Errorf("ClientID = %s, want test-client", identity.ClientID)
	}
	if identity.TrustLevel != TrustLevelLow {
		t.Errorf("TrustLevel = %v, want low (no device)", identity.TrustLevel)
	}
	if identity.SessionID == "" {
		t.Error("expected non-empty session ID")
	}

	// Verify session is stored
	retrieved := svc.GetClientIdentity(identity.SessionID)
	if retrieved == nil {
		t.Fatal("expected session to be stored")
	}
	if retrieved.ClientID != "test-client" {
		t.Errorf("retrieved ClientID = %s, want test-client", retrieved.ClientID)
	}
}

func TestVerifyClientCertificate_WithKnownDevice(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:    true,
		SessionTTL: 1 * time.Hour,
	})

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	// Register the device that will be matched by fingerprint
	fingerprint := calculateDeviceFingerprint(cert)
	svc.mu.Lock()
	svc.devices[fingerprint] = &DeviceInfo{
		DeviceID:    "device-1",
		Fingerprint: fingerprint,
		TrustLevel:  TrustLevelHigh,
		LastSeenAt:  time.Now().Add(-1 * time.Hour),
	}
	svc.mu.Unlock()

	identity, err := svc.VerifyClientCertificate(cert)
	if err != nil {
		t.Fatalf("VerifyClientCertificate failed: %v", err)
	}

	if identity.TrustLevel != TrustLevelHigh {
		t.Errorf("TrustLevel = %v, want high (known device)", identity.TrustLevel)
	}
	if identity.Device == nil {
		t.Error("expected device info")
	}
}

func TestVerifyClientCertificate_SessionCapEviction(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:    true,
		SessionTTL: 1 * time.Hour,
	})

	// Fill sessions to capacity
	svc.mu.Lock()
	for i := 0; i < 100000; i++ {
		svc.sessions[string(rune(i))] = &ClientIdentity{
			ClientID:        "client-" + string(rune(i)),
			SessionID:       string(rune(i)),
			AuthenticatedAt: time.Now(),
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

	// This should trigger eviction and not panic
	identity, err := svc.VerifyClientCertificate(cert)
	if err != nil {
		t.Fatalf("VerifyClientCertificate with full sessions: %v", err)
	}
	if identity == nil {
		t.Error("expected identity")
	}
}

// --- loadTrustedCAs ---

func TestLoadTrustedCAs(t *testing.T) {
	svc2, err := NewService(&Config{
		Enabled:       true,
		TrustedCAPath: "", // empty path should skip loading
	})
	if err != nil {
		t.Fatal(err)
	}
	if svc2.trustedCAs != nil {
		t.Error("expected nil trustedCAs when path is empty")
	}

	// Explicit call with non-empty path should set trustedCAs
	svc3, _ := NewService(&Config{Enabled: true})
	svc3.loadTrustedCAs("some-path")
	if svc3.trustedCAs == nil {
		t.Error("expected non-nil trustedCAs after loadTrustedCAs")
	}
}

func TestNewService_TrustedCAPathError(t *testing.T) {
	// The current implementation of loadTrustedCAs always succeeds
	// (it just creates a new empty pool). Test that it doesn't error.
	svc, err := NewService(&Config{
		Enabled:       true,
		TrustedCAPath: "/some/path/ca.pem",
	})
	if err != nil {
		t.Fatalf("NewService should not fail: %v", err)
	}
	if svc == nil {
		t.Error("expected service")
	}
}

// --- GetTrustLevel with invalid session ---

func TestGetTrustLevel_InvalidSession(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:    true,
		SessionTTL: 1 * time.Hour,
	})

	req := &http.Request{}
	req.Header = make(http.Header)
	req.Header.Set("X-ZeroTrust-Session", "non-existent")

	level := svc.GetTrustLevel(req)
	if level != TrustLevelNone {
		t.Errorf("GetTrustLevel = %v, want none for non-existent session", level)
	}
}

// --- ParseClientCertificate valid path ---

func TestParseClientCertificate_ValidPEM(t *testing.T) {
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
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	cert, err := ParseClientCertificate(pemData)
	if err != nil {
		t.Fatalf("ParseClientCertificate failed: %v", err)
	}
	if cert.Subject.CommonName != "test-client" {
		t.Errorf("CommonName = %s, want test-client", cert.Subject.CommonName)
	}
}

// --- DefaultConfig ---

func TestDefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled {
		t.Error("default should be disabled")
	}
	if !cfg.RequireMTLS {
		t.Error("default RequireMTLS should be true")
	}
	if cfg.RequireAttestation {
		t.Error("default RequireAttestation should be false")
	}
	if cfg.SessionTTL != 1*time.Hour {
		t.Errorf("SessionTTL = %v, want 1h", cfg.SessionTTL)
	}
	if cfg.AttestationTTL != 24*time.Hour {
		t.Errorf("AttestationTTL = %v, want 24h", cfg.AttestationTTL)
	}
	if cfg.DeviceTrustThreshold != TrustLevelMedium {
		t.Errorf("DeviceTrustThreshold = %v, want medium", cfg.DeviceTrustThreshold)
	}
	if len(cfg.AllowBypassPaths) != 2 {
		t.Errorf("AllowBypassPaths = %v, want 2 entries", cfg.AllowBypassPaths)
	}
}

// --- Layer Process with CheckAccess failure (valid session, low trust) ---

func TestLayer_Process_SessionLowTrust_Blocked(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:              true,
		RequireMTLS:          true,
		DeviceTrustThreshold: TrustLevelHigh,
	})

	sessionID := "low-trust-session"
	svc.mu.Lock()
	svc.sessions[sessionID] = &ClientIdentity{
		ClientID:        "low-client",
		TrustLevel:      TrustLevelLow,
		SessionID:       sessionID,
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
		t.Errorf("expected block for low trust session, got %v", result.Action)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings")
	}
	if result.Findings[0].Category != "access_control" {
		t.Errorf("category = %q, want access_control", result.Findings[0].Category)
	}
}

// --- Layer Process with metadata initialization ---

func TestLayer_Process_MetadataInit(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:     true,
		RequireMTLS: false,
	})

	sessionID := "meta-sess"
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
		Path:    "/api/test",
		Headers: map[string][]string{"X-Zerotrust-Session": {sessionID}},
		// Metadata is nil — layer should initialize it
	}

	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass, got %v", result.Action)
	}
	if ctx.Metadata == nil {
		t.Error("expected metadata to be initialized")
	}
	if ctx.Metadata["zt_trust_level"] != "high" {
		t.Errorf("zt_trust_level = %v, want high", ctx.Metadata["zt_trust_level"])
	}
}

// --- Device attestation copy safety ---

func TestVerifyDeviceAttestation_CopySafety(t *testing.T) {
	svc, _ := NewService(&Config{Enabled: true})

	originalData := []byte("original-attestation")
	device, err := svc.VerifyDeviceAttestation("device-1", originalData)
	if err != nil {
		t.Fatal(err)
	}

	// Mutate original — device data should not change
	originalData[0] = 'X'

	svc.mu.RLock()
	stored := svc.devices[device.Fingerprint]
	svc.mu.RUnlock()

	if stored.AttestationData[0] == 'X' {
		t.Error("stored attestation data should not be affected by caller mutations")
	}
}

// --- calculateDeviceFingerprint with valid cert ---

func TestCalculateDeviceFingerprint_WithPublicKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	fp := calculateDeviceFingerprint(cert)
	if fp == "" {
		t.Error("expected non-empty fingerprint")
	}
}

// --- calculateDeviceFingerprintFromData ---

func TestCalculateDeviceFingerprintFromData_Consistency(t *testing.T) {
	fp1 := calculateDeviceFingerprintFromData([]byte("test-data"))
	fp2 := calculateDeviceFingerprintFromData([]byte("test-data"))
	if fp1 != fp2 {
		t.Error("same data should produce same fingerprint")
	}
	fp3 := calculateDeviceFingerprintFromData([]byte("different-data"))
	if fp1 == fp3 {
		t.Error("different data should produce different fingerprint")
	}
}

// --- Concurrent access test ---

func TestService_ConcurrentAccess(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:    true,
		SessionTTL: 1 * time.Hour,
	})

	sessionID := "concurrent-sess"
	svc.mu.Lock()
	svc.sessions[sessionID] = &ClientIdentity{
		ClientID:        "client-1",
		TrustLevel:      TrustLevelHigh,
		SessionID:       sessionID,
		AuthenticatedAt: time.Now(),
	}
	svc.mu.Unlock()

	done := make(chan struct{})

	// Concurrent reads
	go func() {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 100; i++ {
			svc.GetClientIdentity(sessionID)
		}
	}()

	// Concurrent writes (attestations)
	go func() {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 100; i++ {
			svc.VerifyDeviceAttestation("device-"+string(rune(i)), []byte("data"))
		}
	}()

	// Concurrent revocations
	go func() {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 100; i++ {
			svc.CleanupExpiredSessions()
		}
	}()

	<-done
	<-done
	<-done
}

// --- GetSessionIDFromContext nil identity ---

func TestGetSessionIDFromContext_NilIdentity(t *testing.T) {
	ctx := context.Background()
	id := GetSessionIDFromContext(ctx)
	if id != "" {
		t.Errorf("expected empty session ID, got %q", id)
	}
}

// --- GetTrustLevelFromContext nil identity ---

func TestGetTrustLevelFromContext_NilIdentity(t *testing.T) {
	ctx := context.Background()
	level := GetTrustLevelFromContext(ctx)
	if level != TrustLevelNone {
		t.Errorf("expected none, got %v", level)
	}
}

// --- VerifyClientCertificate with trusted CAs (verification failure) ---

func TestVerifyClientCertificate_WithTrustedCAs(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:    true,
		SessionTTL: 1 * time.Hour,
	})

	// Force trustedCAs to a non-empty pool to trigger the verify path
	svc.trustedCAs = x509.NewCertPool()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	// Should fail verification because cert is self-signed and not in pool
	_, err = svc.VerifyClientCertificate(cert)
	if err == nil {
		t.Error("expected verification failure with empty trusted CA pool")
	}
}

// --- Middleware mTLS with cert but access denied ---

func TestMiddleware_Handler_mTLS_AccessDenied(t *testing.T) {
	svc, _ := NewService(&Config{
		Enabled:              true,
		RequireMTLS:          true,
		DeviceTrustThreshold: TrustLevelMaximum, // very high threshold
	})
	m := NewMiddleware(svc)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-client"},
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

// --- VerifyDeviceAttestation metadata ---

func TestVerifyDeviceAttestation_Metadata(t *testing.T) {
	svc, _ := NewService(&Config{Enabled: true})

	device, err := svc.VerifyDeviceAttestation("device-meta", []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if device.Metadata == nil {
		t.Error("expected non-nil metadata map")
	}
	if device.AttestedAt.IsZero() {
		t.Error("expected non-zero AttestedAt")
	}
	if device.LastSeenAt.IsZero() {
		t.Error("expected non-zero LastSeenAt")
	}
}
