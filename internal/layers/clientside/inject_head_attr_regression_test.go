package clientside

import (
	"strings"
	"testing"
)

// Regression (F176): the default injection point matched only a bare
// "<head>", so a head carrying attributes fell through to the prepend
// fallback, which placed the agent before <!DOCTYPE html> (quirks mode).
func TestInjectAgent_HeadWithAttributesAndDoctype(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AgentInjection.Enabled = true
	layer := NewLayer(cfg)
	const script = `<script ` + agentMarker + `>`
	cases := []struct{ in, wantPrefix string }{
		{`<!DOCTYPE html><html lang="en"><head prefix="og: x"><title>t</title></head></html>`, `<!DOCTYPE html><html lang="en"><head prefix="og: x">` + script},
		{"<!DOCTYPE html><html><HEAD\n><title>t</title></HEAD></html>", "<!DOCTYPE html><html><HEAD\n>" + script},
		{`<!doctype html><header>h</header><head><title>t</title></head>`, `<!doctype html><header>h</header><head>` + script},
		{"\n<!DOCTYPE html>\n<p>no head</p>", "\n<!DOCTYPE html>" + script},
	}
	for _, c := range cases {
		out := string(layer.InjectAgent([]byte(c.in)))
		if !strings.HasPrefix(out, c.wantPrefix) {
			t.Errorf("InjectAgent(%q)\n got  %q\n want prefix %q", c.in, out[:min(len(out), 120)], c.wantPrefix)
		}
	}
}
