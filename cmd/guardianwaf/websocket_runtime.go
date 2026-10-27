package main

import (
	"net"
	"net/http"
	"net/url"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/websocket"
)

// setupWebSocketRuntime wires the WebSocket inspection layer into the engine's
// middleware chain when waf.websocket.enabled is true. The layer intercepts
// WebSocket upgrade requests, hijacks the connection, and inspects each text
// frame through the detection pipeline.
func setupWebSocketRuntime(cfg *config.Config, eng *engine.Engine) {
	if cfg == nil || eng == nil || !cfg.WAF.WebSocket.Enabled {
		return
	}

	wsLayer := websocket.NewLayer(&websocket.Config{
		Enabled:             cfg.WAF.WebSocket.Enabled,
		MaxFrameSize:        cfg.WAF.WebSocket.MaxFrameSize,
		BlockBinaryMessages: cfg.WAF.WebSocket.BlockBinaryMessages,
		BlockEmptyMessages:  cfg.WAF.WebSocket.BlockEmptyMessages,
		ScanPayloads:        cfg.WAF.WebSocket.ScanPayloads,
		AllowedOrigins:      cfg.WAF.WebSocket.AllowedOrigins,
		MaxConcurrentPerIP:  cfg.WAF.WebSocket.MaxConcurrentPerIP,
		IdleTimeout:         cfg.WAF.WebSocket.IdleTimeout,
		// The message-size cap must follow the operator's knob: it was
		// parsed into config and documented (ADR 0035: close with 1009 when
		// the message is too big) but never mapped here, so the relay's
		// reassembly buffer was bounded only by the hardcoded ceiling.
		MaxMessageSize: cfg.WAF.WebSocket.MaxMessageSize,
		// The layer dials the host the client targeted, so it refuses to hijack
		// unless that host is operator-constrained (the SSRF guard). Derive the
		// allowlist from the configured upstream targets — exactly the backends
		// the operator has declared. Without it Wrap returns the next handler
		// unchanged, so `waf.websocket.enabled: true` inspected nothing at all.
		AllowedBackendHosts: upstreamBackendHosts(cfg),
		CheckPayload: func(clientIP, path string, payload []byte) (int, bool) {
			return eng.ScanPayload(clientIP, path, string(payload))
		},
	})

	eng.SetWebSocketInterceptor(func(next http.Handler) http.Handler {
		return wsLayer.Wrap(next)
	})
}

// upstreamBackendHosts returns every configured upstream target's host, in both
// bare and host:port form. A client's Host header may carry a port or not
// (websocket.backendHostAllowed matches either against a bare entry), so both
// spellings of the operator's own backends are allowed — and nothing else.
func upstreamBackendHosts(cfg *config.Config) []string {
	var hosts []string
	seen := make(map[string]bool)
	add := func(h string) {
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		hosts = append(hosts, h)
	}

	for _, up := range cfg.Upstreams {
		for _, target := range up.Targets {
			u, err := url.Parse(target.URL)
			if err != nil || u.Host == "" {
				continue
			}
			host := u.Host
			if _, _, err := net.SplitHostPort(host); err != nil {
				add(host)
				if u.Scheme == "https" {
					add(net.JoinHostPort(host, "443"))
				} else {
					add(net.JoinHostPort(host, "80"))
				}
				continue
			}
			add(host)
			if h, _, err := net.SplitHostPort(host); err == nil {
				add(h)
			}
		}
	}
	return hosts
}
