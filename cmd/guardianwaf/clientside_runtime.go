package main

import (
	"net/http"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/clientside"
)

// registerClientSideReportHandlers mounts the client report intake endpoints.
//
// The handler must be the clientside layer's OWN intake (see
// Layer.ReportHandler): the layer's CSP header emits the report-uri that
// makes browsers send these reports, so ingest and the dashboard/MCP readers
// must share one store. Without a layer (clientside protection disabled) the
// endpoints still function standalone.
func registerClientSideReportHandlers(mux *http.ServeMux, cs *clientside.Layer) {
	reportHandler := clientside.NewReportHandler()
	if cs != nil {
		reportHandler = cs.ReportHandler()
	}
	mux.Handle("/_guardian/report", reportHandler)
	mux.HandleFunc("/_guardian/csp-report", reportHandler.ServeCSPReport)
}

// clientsideLayerFrom resolves the clientside layer from the engine, or nil
// when the engine is nil or the layer is absent.
func clientsideLayerFrom(e *engine.Engine) *clientside.Layer {
	if e == nil {
		return nil
	}
	cs, _ := e.FindLayer("clientside").(*clientside.Layer)
	return cs
}
