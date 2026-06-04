package layerregistry

import (
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// TestBuildLayer_CRSFailsClosedOnBadRulePath ensures an enabled CRS layer whose
// ruleset cannot be loaded surfaces an error to the caller instead of returning
// a silently-empty (and therefore ineffective) layer.
func TestBuildLayer_CRSFailsClosedOnBadRulePath(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.WAF.CRS.Enabled = true
	cfg.WAF.CRS.RulePath = "/nonexistent/path/to/crs/rules-xyz"

	layer, ok, err := BuildLayer("crs", cfg)
	if err == nil {
		t.Fatalf("expected error building CRS with an unloadable rule path; got layer=%v ok=%v", layer, ok)
	}
	if !strings.Contains(err.Error(), "CRS rules") {
		t.Fatalf("expected a CRS rule-loading error, got: %v", err)
	}
}
