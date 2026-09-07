package clientside

import (
	"strings"
	"testing"
)

// Regression tests: InjectAgent's already-injected guard must check for the
// agent's own marker attribute (data-guardian="security-agent" — what
// generateAgentScript actually emits). The guard previously looked for
// AgentInjection.ScriptURL, which the generated inline agent script never
// references, so it was inert: repeated transforms of the same body stacked
// duplicate agent scripts (doubled telemetry, doubled fetch/XHR wrapping).

func TestInjectAgentIsIdempotent(t *testing.T) {
	l := NewLayer(&Config{
		Enabled: true,
		AgentInjection: AgentConfig{
			Enabled:        true,
			InjectInHTML:   true,
			InjectPosition: "head",
			ScriptURL:      "/_guardian/agent.js", // the marker the old guard wrongly checked
		},
	})

	body := []byte("<!DOCTYPE html><html><head><title>t</title></head><body>hello</body></html>")

	once := l.InjectAgent(body)
	if got := strings.Count(string(once), agentMarker); got != 1 {
		t.Fatalf("FAIL: first injection produced %d agent markers (want 1): %s", got, string(once))
	}

	twice := l.InjectAgent(once)
	if got := strings.Count(string(twice), agentMarker); got != 1 {
		t.Fatalf("FAIL: repeated transform stacked %d agent markers (want exactly 1): %s", got, string(twice))
	}
}

// A body that already references the configured ScriptURL (an external agent
// load) is considered protected — the inline agent must NOT be stacked on
// top of it.
func TestInjectAgentSkipsWhenScriptURLReferenced(t *testing.T) {
	l := NewLayer(&Config{
		Enabled: true,
		AgentInjection: AgentConfig{
			Enabled:        true,
			InjectInHTML:   true,
			InjectPosition: "head",
			ScriptURL:      "/_guardian/agent.js",
		},
	})

	// The body references the script URL — already protected externally.
	body := []byte("<!DOCTYPE html><html><head><script src=\"/_guardian/agent.js\"></script></head><body>hi</body></html>")

	out := l.InjectAgent(body)
	if string(out) != string(body) {
		t.Fatalf("FAIL: externally-protected body was modified: %s", string(out))
	}
	if got := strings.Count(string(out), agentMarker); got != 0 {
		t.Fatalf("FAIL: inline agent stacked on an externally-protected body (markers: %d)", got)
	}
}

// The emitted agent script must carry the marker the dedup guard checks for
// — emitter and guard share the agentMarker constant.
func TestGenerateAgentScriptCarriesMarker(t *testing.T) {
	l := NewLayer(&Config{
		Enabled: true,
		AgentInjection: AgentConfig{
			Enabled:      true,
			InjectInHTML: true,
		},
	})

	script := l.generateAgentScript()
	if !strings.Contains(script, agentMarker) {
		t.Fatal("FAIL: generated agent script does not carry the dedup marker")
	}
}
