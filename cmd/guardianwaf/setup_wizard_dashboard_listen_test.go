package main

// Regression: the setup wizard must default the admin dashboard to loopback.
//
// The product's own hardening (pinned by TestDefaultDashboardListenIsLoopback in
// internal/config/defaults_hardening_test.go) states the contract:
//
//	"the admin dashboard shipped enabled on :9443 (all interfaces) with
//	 TLS:false — and dashboard.tls is REJECTED by the validator ('terminate
//	 TLS at an ingress'), so the listen address is the only posture control.
//	 The default must be loopback: the operator gets a working local admin
//	 UI, and remote exposure is an explicit dashboard.listen decision."
//
// internal/config/defaults.go therefore ships Dashboard.Listen = "127.0.0.1:9443".
//
// The setup wizard — the documented first-run onboarding path — never got the
// same treatment. It printed "Dashboard port [0.0.0.0:9443]" but defaulted to
// readLine(":9443"), and readLine returns its default whenever the operator
// simply presses Enter (main.go). So an operator accepting every default got:
//
//	dashboard:
//	  enabled: true
//	  listen: ":9443"      <- empty host: ALL interfaces
//
// validateListenAddr only checks the host:port shape, so the config loaded and
// the credential-bearing admin UI — which has no TLS — was reachable from every
// network interface with the API key crossing the wire in cleartext. The prompt
// compounded it by advertising 0.0.0.0:9443, so nothing on screen looked wrong.
//
// Remote exposure is still available, but only as a deliberate typed choice.
//
// Harness note: these tests drive the REAL promptDashboard by swapping
// os.Stdin. The wizard's templates are never copied into the test — a copied
// template keeps passing (or failing) independently of the production change,
// which is exactly what made the round-18 proof useless.

import (
	"net"
	"os"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// withStdin swaps os.Stdin so readLine is driven deterministically.
func withStdin(t *testing.T, content string) {
	t.Helper()
	old := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := w.WriteString(content); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	_ = w.Close()
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })
}

// isLoopbackOnly reports whether a host:port listen binds loopback only.
func isLoopbackOnly(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "" {
		return false // ":9443" — ALL interfaces
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(host, "localhost")
}

// wizardDashboardListen runs the real prompt + buildConfig for a given stdin.
func wizardDashboardListen(t *testing.T, stdin string) (listen string, configText string) {
	t.Helper()
	w := newSetupWizard("test-api-key")
	withStdin(t, stdin)
	w.promptDashboard()
	configText = w.buildConfig()

	node, err := config.Parse([]byte(configText))
	if err != nil {
		t.Fatalf("generated config does not parse: %v\n--- config ---\n%s", err, configText)
	}
	return node.Get("dashboard").Get("listen").String(), configText
}

func TestSetupWizardDefaultDashboardListenIsLoopback(t *testing.T) {
	listen, _ := wizardDashboardListen(t, "\n")
	if !isLoopbackOnly(listen) {
		t.Fatalf("setup wizard wrote dashboard.listen = %q — that binds ALL interfaces. The "+
			"admin dashboard has no TLS (dashboard.tls is rejected by the validator), so the "+
			"listen address is the only posture control, and DefaultConfig ships "+
			"127.0.0.1:9443 for exactly this reason", listen)
	}
}

// CONTROL: an explicit 0.0.0.0:9443 is an operator decision and must be honoured —
// only the DEFAULT is constrained.
func TestSetupWizardHonoursExplicitWildcardListen(t *testing.T) {
	listen, _ := wizardDashboardListen(t, "0.0.0.0:9443\n")
	if listen != "0.0.0.0:9443" {
		t.Fatalf("explicit operator input was not honoured — got %q, want 0.0.0.0:9443", listen)
	}
}

// CONTROL: an explicit loopback address is preserved verbatim.
func TestSetupWizardHonoursExplicitLoopbackListen(t *testing.T) {
	listen, _ := wizardDashboardListen(t, "localhost:9443\n")
	if listen != "localhost:9443" {
		t.Fatalf("explicit loopback input was not honoured — got %q, want localhost:9443", listen)
	}
}

// CONTROL: the generated config still parses and still enables the dashboard —
// the loopback default must not disable or truncate the section.
func TestSetupWizardGeneratedConfigStillEnablesDashboard(t *testing.T) {
	_, out := wizardDashboardListen(t, "\n")
	node, err := config.Parse([]byte(out))
	if err != nil {
		t.Fatalf("generated config does not parse: %v", err)
	}
	if enabled := node.Get("dashboard").Get("enabled").String(); enabled != "true" {
		t.Fatalf("dashboard.enabled = %q, want true — the wizard must still emit a dashboard", enabled)
	}
	if !strings.Contains(out, "mcp:") {
		t.Fatal("generated config is missing the mcp section — buildConfig regressed")
	}
}
