package dashboard

import (
	"net/http"
)

// registerAI registers AI analysis routes.
func (d *Dashboard) registerAI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/ai/providers", d.authWrap(d.handleAIProviders))
	mux.HandleFunc("GET /api/v1/ai/config", d.authWrap(d.handleAIGetConfig))
	mux.HandleFunc("PUT /api/v1/ai/config", d.authWrap(d.handleAISetConfig))
	mux.HandleFunc("GET /api/v1/ai/history", d.authWrap(d.handleAIHistory))
	mux.HandleFunc("GET /api/v1/ai/stats", d.authWrap(d.handleAIStats))
	mux.HandleFunc("POST /api/v1/ai/analyze", d.authWrap(d.handleAIAnalyze))
	mux.HandleFunc("POST /api/v1/ai/test", d.authWrap(d.handleAITest))
}

// registerAlerting registers alerting routes.
func (d *Dashboard) registerAlerting(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/alerting/status", d.authWrap(d.handleAlertingStatus))
	mux.HandleFunc("GET /api/v1/alerting/webhooks", d.authWrap(d.handleGetWebhooks))
	mux.HandleFunc("POST /api/v1/alerting/webhooks", d.authWrap(d.handleAddWebhook))
	mux.HandleFunc("DELETE /api/v1/alerting/webhooks/{name}", d.authWrap(d.handleDeleteWebhook))
	mux.HandleFunc("GET /api/v1/alerting/emails", d.authWrap(d.handleGetEmails))
	mux.HandleFunc("POST /api/v1/alerting/emails", d.authWrap(d.handleAddEmail))
	mux.HandleFunc("DELETE /api/v1/alerting/emails/{name}", d.authWrap(d.handleDeleteEmail))
	mux.HandleFunc("POST /api/v1/alerting/test", d.authWrap(d.handleTestAlert))
}

// registerDocker registers Docker auto-discovery routes.
func (d *Dashboard) registerDocker(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/docker/services", d.authWrap(d.handleDockerServices))
}

// registerCompliance registers compliance reporting routes.
func (d *Dashboard) registerCompliance(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/compliance/controls", d.authWrap(d.handleComplianceControls))
	mux.HandleFunc("GET /api/v1/compliance/report/{framework}", d.authWrap(d.handleComplianceReport))
	mux.HandleFunc("GET /api/v1/compliance/audit-chain", d.authWrap(d.handleAuditChain))
}

// registerSPA is a no-op — SPA routes are registered in registerRouting.
func (d *Dashboard) registerSPA(mux *http.ServeMux) {}
