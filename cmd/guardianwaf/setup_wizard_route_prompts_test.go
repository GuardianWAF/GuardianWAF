package main

// Regression (round 2026-10-13-r23-routehost-dead-prompt): the setup wizard's
// promptRouting used to ask "Route domain/host pattern" and store the answer
// in w.routeHost — which buildConfig provably discarded ("_ = w.routeHost").
// An operator who answered the question saw it nowhere in the summary or the
// generated config and could reasonably believe host-pattern routing was
// configured. The wizard now asks only the route-path question, and the
// invariant is pinned: every question promptRouting asks has its answer
// reflected in the generated config, which must still parse.
//
// Harness note: drives the REAL promptRouting via the os.Stdin-swap harness
// (the dashboard-listen regression's convention) — never a copied template.

import (
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

func routePromptWizard(t *testing.T, stdin string) (routePath, configText string) {
	t.Helper()
	w := newSetupWizard("test-api-key")
	withStdin(t, stdin)
	w.promptRouting()

	// Minimal state so buildConfig emits every section (mirrors
	// TestSetupWizard_BuildConfig_Basic).
	w.listen = ":8088"
	w.mode = "enforce"
	w.tlsConfig = "\ntls:\n  enabled: false"
	w.numBackends = 1
	w.lb = "weighted"
	w.hcConfig = ""
	w.targets = []string{"      - url: \"http://localhost:3000\"\n        weight: 1"}
	w.blockThresh = "50"
	w.logThresh = "25"
	w.detectors = []string{"sqli"}
	w.detectorCfg = "      sqli:\n        enabled: true\n        multiplier: 1.0"
	w.botConfig = "\n  bot_detection:\n    enabled: false"
	w.rateLimitCfg = "\n  rate_limit:\n    enabled: false"
	w.corsConfig = "\n  cors:\n    enabled: false"
	w.atoConfig = "\n  ato_protection:\n    enabled: false"
	w.alertConfig = "\nalerting:\n  enabled: false"
	w.dockerConfig = "\ndocker:\n  enabled: false"
	w.dashboardListen = "127.0.0.1:9443"

	return w.routePath, w.buildConfig()
}

func TestSetupWizardRoutePromptAnswerIsReflected(t *testing.T) {
	routePath, cfg := routePromptWizard(t, "/distinctive-path\n")

	if routePath != "/distinctive-path" {
		t.Fatalf("route-path answer was not captured (got %q)", routePath)
	}
	if !strings.Contains(cfg, `path: "/distinctive-path"`) {
		t.Fatalf("the route-path answer %q does not appear in the generated config — the routing prompt's answer must be reflected", routePath)
	}

	node, err := config.Parse([]byte(cfg))
	if err != nil {
		t.Fatalf("generated config does not parse: %v\n--- config ---\n%s", err, cfg)
	}
	routes := node.Get("routes")
	if routes == nil || routes.Kind != config.SequenceNode || len(routes.Slice()) != 1 {
		t.Fatalf("generated config must contain exactly one route, got: %v", routes)
	}
}

// The wizard must not ask a route-domain question: there is no consumer for
// the answer (the generated config routes by path prefix to the default
// upstream and has no virtual-host section), so asking it was dead UX.
func TestSetupWizardGeneratedConfigHasNoHostPatternSection(t *testing.T) {
	_, cfg := routePromptWizard(t, "/\n")
	if strings.Contains(cfg, "virtual_hosts") || strings.Contains(cfg, "host_pattern") {
		t.Fatalf("generated config contains host-pattern routing the wizard no longer asks for:\n%s", cfg)
	}
}
