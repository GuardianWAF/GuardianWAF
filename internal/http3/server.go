//go:build http3

// Package http3 provides HTTP/3 and QUIC support for GuardianWAF.
// This package requires the http3 build tag to be enabled.
package http3

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Config holds HTTP/3 server configuration.
type Config struct {
	Enabled            bool          `yaml:"enabled"`
	Listen            string        `yaml:"listen"`              // UDP listen address (e.g., ":443")
	MaxHeaderBytes    int           `yaml:"max_header_bytes"`    // Max header size (default: 1MB)
	ReadTimeout       time.Duration `yaml:"read_timeout"`        // Request read timeout
	WriteTimeout      time.Duration `yaml:"write_timeout"`       // Response write timeout
	IdleTimeout       time.Duration `yaml:"idle_timeout"`        // Connection idle timeout
	Enable0RTT        bool          `yaml:"enable_0rtt"`         // Enable 0-RTT (requires TLS 1.3)
	EnableDatagrams   bool          `yaml:"enable_datagrams"`    // Enable HTTP/3 datagrams
	AltSvcPort        int           `yaml:"alt_svc_port"`        // Alt-Svc advertised port (0 = same as listen)
	AltSvcProtocol    string        `yaml:"alt_svc_protocol"`   // Alt-Svc protocol ID (default: h3)
	MaxRequestBodySize int64        `yaml:"max_request_body_size"`
}

// DefaultConfig returns default HTTP/3 configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled:            false,
		Listen:             ":443",
		MaxHeaderBytes:     1 << 20, // 1MB
		ReadTimeout:        30 * time.Second,
		WriteTimeout:       30 * time.Second,
		IdleTimeout:        120 * time.Second,
		Enable0RTT:         false, // Disabled by default — 0-RTT is vulnerable to replay attacks
		EnableDatagrams:    false,
		AltSvcPort:         0,
		AltSvcProtocol:     "h3",
		MaxRequestBodySize: 10 << 20, // 10MB
	}
}

// Server wraps an HTTP/3 server with QUIC support.
type Server struct {
	config       *Config
	http3Server  *http3.Server
	listener     *quic.EarlyListener
	handler      http.Handler
	tlsConfig    *tls.Config
	altSvcHeader string
	wg           sync.WaitGroup
}

// NewServer creates a new HTTP/3 server.
func NewServer(cfg *Config, handler http.Handler, tlsConfig *tls.Config) (*Server, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if !cfg.Enabled {
		return nil, fmt.Errorf("HTTP/3 is not enabled in configuration")
	}

	// Clone TLS config and ensure it supports TLS 1.3
	tlsConf := tlsConfig.Clone()
	tlsConf.MinVersion = tls.VersionTLS13

	// Enable 0-RTT if configured
	if cfg.Enable0RTT {
		tlsConf.ClientSessionCache = tls.NewLRUClientSessionCache(128)
	}

	// Build Alt-Svc header
	altSvcPort := cfg.AltSvcPort
	if altSvcPort == 0 {
		// Extract port from listen address
		_, port, err := net.SplitHostPort(cfg.Listen)
		if err == nil {
			altSvcPort, _ = strconv.Atoi(port)
		}
		if altSvcPort == 0 {
			altSvcPort = 443
		}
	}

	altSvcHeader := fmt.Sprintf(`%s=":%d"; ma=86400`, cfg.AltSvcProtocol, altSvcPort)

	return &Server{
		config:       cfg,
		handler:      handler,
		tlsConfig:    tlsConf,
		altSvcHeader: altSvcHeader,
	}, nil
}

// Start starts the HTTP/3 server.
func (s *Server) Start() error {
	if s.http3Server != nil {
		return fmt.Errorf("server already started")
	}

	s.http3Server = &http3.Server{
		Addr:           s.config.Listen,
		Handler:        s.handler,
		TLSConfig:      s.tlsConfig,
		MaxHeaderBytes: s.config.MaxHeaderBytes,
	}

	// Configure QUIC transport
	quicConf := &quic.Config{
		Allow0RTT:            s.config.Enable0RTT,
		EnableDatagrams:      s.config.EnableDatagrams,
		MaxIdleTimeout:       s.config.IdleTimeout,
		MaxIncomingStreams:   100_000, // Prevent stream exhaustion attacks
		MaxIncomingUniStreams: 10_000, // Limit unidirectional streams
	}

	// Listen for QUIC connections
	ln, err := quic.ListenAddrEarly(s.config.Listen, s.tlsConfig, quicConf)
	if err != nil {
		return fmt.Errorf("failed to listen for QUIC: %w", err)
	}
	s.listener = ln

	// Start serving in a tracked goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.http3Server.ServeListener(s.listener); err != nil && err != http.ErrServerClosed {
					slog.Warn("HTTP/3 server error", "error", err)

		}
	}()

	return nil
}

// Stop gracefully stops the HTTP/3 server.
func (s *Server) Stop() error {
	if s.http3Server == nil {
		return nil
	}

	// Close the listener first to stop accepting new connections
	if s.listener != nil {
		_ = s.listener.Close()
	}

	// Close the HTTP/3 server
	err := s.http3Server.Close()
	s.wg.Wait() // Wait for serve goroutine to finish
	return err
}

// AltSvcHeader returns the Alt-Svc header value for HTTP/2 upgrade hints.
func (s *Server) AltSvcHeader() string {
	return s.altSvcHeader
}

// IsRunning returns true if the server is running.
func (s *Server) IsRunning() bool {
	return s.http3Server != nil && s.listener != nil
}

// GetConfig returns the server configuration.
func (s *Server) GetConfig() *Config {
	return s.config
}

// Stats holds HTTP/3 server statistics.
type Stats struct {
	Connections    int64
	Requests       int64
	Errors         int64
	ZeroRTTUsed    int64
	MigrationCount int64
}

// GetStats returns current server statistics.
// Note: detailed per-connection stats require quic-go tracing hooks
// which are not exposed through the http3.Server API.
func (s *Server) GetStats() Stats {
	return Stats{}
}

// EnableAltSvc adds Alt-Svc header to HTTP responses for protocol upgrade.
func EnableAltSvc(next http.Handler, altSvcValue string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add Alt-Svc header to encourage clients to use HTTP/3
		if altSvcValue != "" {
			w.Header().Set("Alt-Svc", altSvcValue)
		}
		next.ServeHTTP(w, r)
	})
}

// IsHTTP3Request returns true if the request was made over HTTP/3.
func IsHTTP3Request(r *http.Request) bool {
	// HTTP/3 requests have specific protocol indicators
	return r.ProtoMajor == 3 || r.Header.Get("X-HTTP3") == "1"
}
