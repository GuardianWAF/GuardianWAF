package layerregistry

// Regression (round 2026-09-24-r22-wire-regression): the r20
// suspicious_patterns wire must work through the FULL config load path —
// yaml -> LoadFile (populate + overlay) -> buildClientSide -> the layer's
// Magecart scanner enforcing the operator-configured pattern.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestSuspiciousPatternsFullConfigPath(t *testing.T) {
	yamlCfg := `
waf:
  client_side:
    enabled: true
    mode: block
    magecart_detection:
      enabled: true
      detect_suspicious_domains: true
      suspicious_patterns:
        - evil-exfil-collector
`
	path := filepath.Join(t.TempDir(), "gwaf.yaml")
	if err := os.WriteFile(path, []byte(yamlCfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	layer, err := buildClientSide(cfg)
	if err != nil {
		t.Fatalf("buildClientSide: %v", err)
	}

	ctx := &engine.RequestContext{Path: "/checkout"}
	if res := layer.Process(ctx); res.Action == engine.ActionBlock {
		t.Fatalf("request unexpectedly blocked at request time")
	}
	hook := ctx.ClientsideBodyXform
	if hook == nil {
		t.Fatalf("clientside response hook not registered from yaml config")
	}
	out, modified := hook([]byte(`<script src="https://cdn.example/evil-exfil-collector.js"></script>`), "text/html")
	if !modified || !strings.Contains(string(out), "Blocked by Client-Side Protection") {
		t.Fatalf("operator-configured pattern not enforced through the full config path: modified=%v out=%q", modified, string(out))
	}
}
