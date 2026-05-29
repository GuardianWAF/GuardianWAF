package main

import (
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// collectACMEDomains gathers all domains that need ACME certificates.
// Collects from tls.acme.domains and virtual_hosts that do not have manual certs.
func collectACMEDomains(cfg *config.Config) [][]string {
	var result [][]string

	if len(cfg.TLS.ACME.Domains) > 0 {
		result = append(result, cfg.TLS.ACME.Domains)
	}

	for _, vh := range cfg.VirtualHosts {
		if vh.TLS.CertFile == "" && vh.TLS.KeyFile == "" && len(vh.Domains) > 0 {
			var nonWild []string
			for _, d := range vh.Domains {
				if !strings.HasPrefix(d, "*.") {
					nonWild = append(nonWild, d)
				}
			}
			if len(nonWild) > 0 {
				result = append(result, nonWild)
			}
		}
	}

	return result
}
