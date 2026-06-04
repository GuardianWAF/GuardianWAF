package dashboard

import (
	"net/http"
)

// registerRules registers rules CRUD and geoip routes.
func (d *Dashboard) registerRules(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/rules", d.authWrap(d.handleGetRules))
	mux.HandleFunc("POST /api/v1/rules", d.authWrap(d.handleAddRule))
	mux.HandleFunc("PUT /api/v1/rules/{id}", d.authWrap(d.handleUpdateRule))
	mux.HandleFunc("DELETE /api/v1/rules/{id}", d.authWrap(d.handleDeleteRule))
	mux.HandleFunc("GET /api/v1/geoip/lookup", d.authWrap(d.handleGeoIPLookup))
	mux.HandleFunc("POST /api/v1/geoip/lookup", d.authWrap(d.handleGeoIPLookupPost))
}
