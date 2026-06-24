package dashboard

import (
	"net/http"
)

// registerConfig registers config routes.
func (d *Dashboard) registerConfig(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/config", d.authWrap(d.handleGetConfig))
	mux.HandleFunc("PUT /api/v1/config", d.authWrap(d.handleUpdateConfig))
	mux.HandleFunc("GET /api/v1/config/ratelimit", d.authWrap(d.handleGetRateLimitConfig))
	mux.HandleFunc("PUT /api/v1/config/ratelimit", d.authWrap(d.handleUpdateRateLimitConfig))
	mux.HandleFunc("GET /api/v1/config/bot", d.authWrap(d.handleGetBotConfig))
	mux.HandleFunc("PUT /api/v1/config/bot", d.authWrap(d.handleUpdateBotConfig))
	mux.HandleFunc("POST /api/v1/config/reload", d.authWrap(d.handleReloadConfig))
	mux.HandleFunc("OPTIONS /api/v1/config", handleCORS)
	mux.HandleFunc("POST /api/v1/cwv", d.handleCWVReport)
	mux.HandleFunc("GET /api/v1/cwv", d.authWrap(d.handleGetCWV))
}
