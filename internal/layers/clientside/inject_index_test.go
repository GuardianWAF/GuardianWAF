package clientside

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Regression tests for InjectAgent tag indexing: tag positions must be byte
// offsets valid in the ORIGINAL body. The implementation used to search a
// strings.ToLower copy and splice the original body at those offsets — but
// ToLower is not length-preserving (İ U+0130: 2→1 bytes; ẞ U+1E9E: 3→2
// bytes), so the script was spliced at a shifted offset, corrupting the HTML
// and (when the shift landed mid-rune) producing invalid UTF-8.

func newInjectTestLayer(t *testing.T, position string) *Layer {
	t.Helper()
	cfg := DefaultConfig()
	cfg.AgentInjection.Enabled = true
	cfg.AgentInjection.InjectPosition = position
	cfg.AgentInjection.MonitorDOM = true
	cfg.AgentInjection.MonitorNetwork = false
	cfg.AgentInjection.MonitorForms = false
	return NewLayer(cfg)
}

func TestInjectAgentHeadIndexValidWithMultiByteContent(t *testing.T) {
	layer := newInjectTestLayer(t, "head")
	body := "<!DOCTYPE html><html><head><title>Café — İmportant ẞeitreff</title></head><body>Hello</body></html>"

	out := string(layer.InjectAgent([]byte(body)))
	script := layer.generateAgentScript()

	headClose := strings.Index(out, "</head>")
	if headClose < 0 {
		t.Fatal("</head> missing from output")
	}
	if strings.Count(out, "</head>") != 1 {
		t.Fatalf("FAIL: </head> tag duplicated in output: %d occurrences", strings.Count(out, "</head>"))
	}
	if !strings.HasSuffix(out[:headClose], script) {
		t.Fatalf("FAIL: agent script spliced at wrong byte offset (must sit immediately before </head>) — output around injection: %q", out[max(0, headClose-40):min(headClose+9, len(out))])
	}
	if !utf8.ValidString(out) {
		t.Fatal("FAIL: injection split a multi-byte rune — output is not valid UTF-8")
	}
	if !strings.Contains(out, "ẞeitreff") || !strings.Contains(out, "İmportant") {
		t.Fatalf("FAIL: original content corrupted around injection point: %q", out[:min(len(out), 200)])
	}
}

// The shift error must not split a multi-byte rune when the shrinking
// character sits directly adjacent to the injection tag.
func TestInjectAgentHeadIndexDoesNotSplitRune(t *testing.T) {
	layer := newInjectTestLayer(t, "head")
	body := "<html><head><title>t</title>İ</head><body>x</body></html>"

	out := string(layer.InjectAgent([]byte(body)))
	if !utf8.ValidString(out) {
		t.Fatalf("FAIL: injection split the multi-byte rune İ — output is not valid UTF-8: %q", out)
	}
	script := layer.generateAgentScript()
	headClose := strings.Index(out, "</head>")
	if !strings.HasSuffix(out[:headClose], script) {
		t.Fatalf("FAIL: agent script spliced at wrong byte offset before </head>")
	}
}

func TestInjectAgentBodyEndIndexValidWithMultiByteContent(t *testing.T) {
	layer := newInjectTestLayer(t, "body-end")
	body := "<html><head></head><body>İ</body></html>"

	out := string(layer.InjectAgent([]byte(body)))
	if !utf8.ValidString(out) {
		t.Fatalf("FAIL: injection split the multi-byte rune İ — output is not valid UTF-8: %q", out)
	}
	script := layer.generateAgentScript()
	bodyClose := strings.Index(out, "</body>")
	if bodyClose < 0 {
		t.Fatal("</body> missing from output")
	}
	if !strings.HasSuffix(out[:bodyClose], script) {
		t.Fatalf("FAIL: agent script spliced at wrong byte offset (must sit immediately before </body>)")
	}
	if !strings.Contains(out, "İ") {
		t.Fatalf("FAIL: original content corrupted around injection point: %q", out)
	}
}

// Control: pure-ASCII bodies must keep injecting exactly before the tag.
func TestInjectAgentASCIIAdjacency(t *testing.T) {
	layer := newInjectTestLayer(t, "head")
	body := "<html><head><title>Test</title></head><body>Hello</body></html>"

	out := string(layer.InjectAgent([]byte(body)))
	script := layer.generateAgentScript()

	headClose := strings.Index(out, "</head>")
	if headClose < 0 {
		t.Fatal("</head> missing from output")
	}
	if !strings.HasSuffix(out[:headClose], script) {
		t.Fatal("FAIL: ASCII injection adjacency broke")
	}
	if !utf8.ValidString(out) {
		t.Fatal("FAIL: output is not valid UTF-8")
	}
}
