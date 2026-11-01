package detection

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestDecodedViewsAreScanned(t *testing.T) {
	layer := NewLayer(defaultConfig())
	ctx := &engine.RequestContext{
		Method:      "GET",
		Path:        "/search",
		QueryParams: map[string][]string{"q": {"JyBPUiAxPTEgLS0="}},
		DecodedViews: []engine.DecodedView{
			{Source: "base64:query", Raw: "' OR 1=1 --", Normalized: "' OR 1=1 --"},
		},
	}
	res := layer.Process(ctx)
	if res.Score < 50 {
		t.Fatalf("decoded SQLi scored %d, want a block-level score", res.Score)
	}
	for _, f := range res.Findings {
		if f.Location != "base64:query" {
			t.Errorf("finding location = %q, want base64:query", f.Location)
		}
	}
}

func TestDecodedViewsSameRuleCountsOnce(t *testing.T) {
	layer := NewLayer(defaultConfig())
	view := engine.DecodedView{Source: "base64:query", Raw: "<script>alert(1)</script>", Normalized: "<script>alert(1)</script>"}
	one := layer.Process(&engine.RequestContext{DecodedViews: []engine.DecodedView{view}})
	two := layer.Process(&engine.RequestContext{DecodedViews: []engine.DecodedView{view, view}})
	if one.Score == 0 || one.Score != two.Score {
		t.Errorf("score with one view %d, with the same view twice %d; want equal and non-zero", one.Score, two.Score)
	}
}

func TestDecodedViewsRespectExclusions(t *testing.T) {
	cfg := defaultConfig()
	cfg.Exclusions = []Exclusion{{PathPrefix: "/editor", Detectors: []string{"xss"}}}
	layer := NewLayer(cfg)
	ctx := &engine.RequestContext{
		Path:         "/editor/save",
		DecodedViews: []engine.DecodedView{{Source: "base64:body", Raw: "<script>alert(1)</script>", Normalized: "<script>alert(1)</script>"}},
	}
	for _, f := range layer.Process(ctx).Findings {
		if f.DetectorName == "xss" {
			t.Fatalf("excluded xss detector still reported %q", f.Description)
		}
	}
}

func TestDecodedViewsIgnoreStructuralDetectors(t *testing.T) {
	layer := NewLayer(defaultConfig())
	ctx := &engine.RequestContext{
		DecodedViews: []engine.DecodedView{{Source: "base64:query", Raw: "https://evil.example/", Normalized: "https://evil.example/"}},
	}
	for _, f := range layer.Process(ctx).Findings {
		if f.DetectorName == "openredirect" || f.DetectorName == "smuggling" || f.DetectorName == "graphql" {
			t.Errorf("structural detector %q ran on a decoded view", f.DetectorName)
		}
	}
}
