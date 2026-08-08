package main

import (
	"net/http"

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
		ScanPayloads:        cfg.WAF.WebSocket.ScanPayloads,
		AllowedOrigins:      cfg.WAF.WebSocket.AllowedOrigins,
		MaxConcurrentPerIP:  cfg.WAF.WebSocket.MaxConcurrentPerIP,
		IdleTimeout:         cfg.WAF.WebSocket.IdleTimeout,
		CheckPayload: func(clientIP, path string, payload []byte) (int, bool) {
			return eng.ScanPayload(clientIP, path, string(payload))
		},
	})

	eng.SetWebSocketInterceptor(func(next http.Handler) http.Handler {
		return wsLayer.Wrap(next)
	})
}
