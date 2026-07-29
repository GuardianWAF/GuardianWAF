package dashboard

import (
	"net/http"
)

// registerACL registers IP ACL and temporary ban routes.
func (d *Dashboard) registerACL(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/ipacl", d.authWrap(d.handleGetIPACL))
	mux.HandleFunc("POST /api/v1/ipacl", d.authAuditWrap(d.handleAddIPACL))
	mux.HandleFunc("DELETE /api/v1/ipacl", d.authAuditWrap(d.handleRemoveIPACL))
	mux.HandleFunc("GET /api/v1/bans", d.authWrap(d.handleGetBans))
	mux.HandleFunc("POST /api/v1/bans", d.authAuditWrap(d.handleAddBan))
	mux.HandleFunc("DELETE /api/v1/bans", d.authAuditWrap(d.handleRemoveBan))
	mux.HandleFunc("OPTIONS /api/v1/ipacl", handleCORS)
}
