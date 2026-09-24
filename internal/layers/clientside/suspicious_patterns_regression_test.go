package clientside

// Regression (round 2026-09-24-r20-suspicious-patterns-knob): the
// magecart_detection.suspicious_patterns operator knob was dead end-to-end
// — SuspiciousPatterns existed only on the layer Config; CompilePatterns
// never read it, the global config type had no field, the populate layer
// didn't wire it, and the registry didn't map it, so operator-configured
// custom Magecart patterns were silently ignored. Post-fix the knob is
// wired end-to-end (config type + nodeStringSlice populate + registry
// mapping + CompilePatterns appending Compile'd patterns — invalid entries
// skipped, never a startup panic).

import (
	"testing"
)

func TestSuspiciousPatternsKnobWired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = "block"
	cfg.MagecartDetection.SuspiciousPatterns = []string{"evil-exfil-collector"}
	layer := NewLayer(cfg)

	// Control: a built-in skimming-pattern hit blocks in block mode.
	ctlSrc := []byte(`<script src="https://skim.evil.example/x.js"></script>`)
	ctlBody, ctlMod := layer.processResponse(ctlSrc, "application/javascript", "/")
	if !ctlMod || string(ctlBody) == string(ctlSrc) {
		t.Fatalf("control: built-in skimming detection did not block")
	}

	// The fixed defect: a body matching ONLY the operator-configured pattern.
	defSrc := []byte(`<script src="https://cdn.example/evil-exfil-collector.js"></script>`)
	defBody, defMod := layer.processResponse(defSrc, "application/javascript", "/")
	if !defMod || string(defBody) != "<!-- Blocked by Client-Side Protection -->" {
		t.Fatalf("operator-configured suspicious pattern was ignored (silent knob): modified=%v body=%q", defMod, string(defBody))
	}
}
