package main

import (
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// upstreamSummary returns a short description of configured upstreams.
func upstreamSummary(cfg *config.Config) string {
	if len(cfg.Upstreams) == 0 {
		return "(no upstream)"
	}
	var targets []string
	for _, u := range cfg.Upstreams {
		for _, t := range u.Targets {
			targets = append(targets, t.URL)
		}
	}
	return strings.Join(targets, ", ")
}
