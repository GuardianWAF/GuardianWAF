package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIngressDoesNotExposeInternalEndpoints pins a shipped-manifest gap.
//
// /metrics, /healthz, /livez and /readyz are registered on the proxy listener
// as exact http.ServeMux patterns, so they are matched ahead of the "/" route
// and never traverse eng.Middleware. The reference Ingress routes "/" Prefix
// from a public host to that listener, which published Prometheus metrics —
// upstream route names, circuit-breaker state, block/pass counts, event-store
// internals — to anyone on the internet, directly contradicting docs/metrics.md
// ("do not expose it directly to the public internet").
func TestIngressDoesNotExposeInternalEndpoints(t *testing.T) {
	root := filepath.Join("..", "..")

	raw, err := os.ReadFile(filepath.Join(root, "contrib/k8s/ingress.yaml"))
	if err != nil {
		t.Fatalf("read ingress.yaml: %v", err)
	}
	manifest := string(raw)

	for _, path := range []string{"/metrics", "/healthz", "/livez", "/readyz"} {
		if !strings.Contains(manifest, "location = "+path) {
			t.Errorf("contrib/k8s/ingress.yaml does not deny %s; the reference manifest would expose it publicly", path)
		}
	}

	// The Helm chart must be safe by default too.
	rawValues, err := os.ReadFile(filepath.Join(root, "contrib/k8s/helm/values.yaml"))
	if err != nil {
		t.Fatalf("read values.yaml: %v", err)
	}
	if !strings.Contains(string(rawValues), "denyInternalEndpoints: true") {
		t.Error("helm values.yaml must default ingress.denyInternalEndpoints to true")
	}

	rawTpl, err := os.ReadFile(filepath.Join(root, "contrib/k8s/helm/templates/ingress.yaml"))
	if err != nil {
		t.Fatalf("read helm ingress template: %v", err)
	}
	if !strings.Contains(string(rawTpl), "denyInternalEndpoints") {
		t.Error("helm ingress template ignores ingress.denyInternalEndpoints")
	}

	// The documented contract this guard enforces must stay in place.
	rawDocs, err := os.ReadFile(filepath.Join(root, "docs/metrics.md"))
	if err != nil {
		t.Fatalf("read docs/metrics.md: %v", err)
	}
	if !strings.Contains(string(rawDocs), "do not expose it directly to the public internet") {
		t.Error("docs/metrics.md no longer states the internal-only contract this test enforces")
	}
}
