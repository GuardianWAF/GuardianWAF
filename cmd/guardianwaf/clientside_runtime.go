package main

import (
	"net/http"

	"github.com/guardianwaf/guardianwaf/internal/layers/clientside"
)

func registerClientSideReportHandlers(mux *http.ServeMux) {
	reportHandler := clientside.NewReportHandler()
	if reportHandler == nil {
		return
	}
	mux.Handle("/_guardian/report", reportHandler)
	mux.HandleFunc("/_guardian/csp-report", reportHandler.ServeCSPReport)
}
