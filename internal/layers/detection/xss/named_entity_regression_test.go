package xss

// Regression (bug-hunt round 2026-09-18-r13, extending the asymmetry-sweep
// family from the round-9/25 sweep note): decodeCommonEncodings decoded
// \xHH, \uHHHH, %HH, &#DD; and &#xHH; — but NO named HTML entities. &lt;
// and &gt; are the most common HTML encoding family (html.EscapeString
// emits exactly them; XML bodies carry them natively), and every HTML
// decoder treats &lt; identically to the handled &#60;. Because Detect
// decodes-then-scans (the decoded form becomes analysisStr), a payload
// encoded entirely as named entities produced ZERO findings while its
// numeric-entity twin was classified and blocked:
//
//	&#60;script&#62;alert(1)&#60;/script&#62;   → 95 script-block finding
//	&lt;script&gt;alert(1)&lt;/script&gt;       → 0 findings
//
// The gap also hid event handlers when the attribute used HTML-legal
// whitespace around `=` (which defeats the standalone on[a-z]+= substring
// check): &lt;img src=x onerror =alert(1)&gt; → 0 findings, while
// &#60;img src=x onerror =alert(1)&#62; → 85 dangerous-tag finding.
//
// Fix: decodeCommonEncodings also decodes the named entities &lt; &gt;
// &quot; &apos; &amp (case-insensitive per the HTML5 &LT;/&GT;/&QUOT;
// aliases, semicolon optional), mirroring what browsers and backend
// html-unescape steps do. Single-pass semantics are preserved: &amp;lt;
// decodes to &lt; (not <), exactly as a browser would.

import (
	"strings"
	"testing"
)

// TestDetect_NamedEntityScriptBlockDetected is the defect case: the
// named-entity form of a script block must classify like its numeric twin.
func TestDetect_NamedEntityScriptBlockDetected(t *testing.T) {
	findings := Detect(`&lt;script&gt;alert(1)&lt;/script&gt;`, "body")
	found := false
	for _, f := range findings {
		if f.Description == "Script block detected: <script>...</script>" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: named-entity script block produced %d findings, none with the script-block classification (%+v) — named HTML entities must decode like numeric ones", len(findings), findings)
	}
}

// TestDetect_NamedEntityImgOnerrorDetected: the img/onerror variant with
// HTML-legal whitespace around `=` must reach the tag scanner after decoding.
func TestDetect_NamedEntityImgOnerrorDetected(t *testing.T) {
	findings := Detect(`&lt;img src=x onerror =alert(1)&gt;`, "body")
	found := false
	for _, f := range findings {
		if strings.Contains(f.Description, "event handler") ||
			strings.Contains(f.Description, "Event handler") {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: named-entity img/onerror payload produced %d findings, none with an event-handler classification (%+v)", len(findings), findings)
	}
}

// Control: the numeric-entity form keeps its classification — the fix must
// not lose the existing encoding family.
func TestDetect_NumericEntityScriptBlockStillDetected(t *testing.T) {
	findings := Detect(`&#60;script&#62;alert(1)&#60;/script&#62;`, "body")
	found := false
	for _, f := range findings {
		if f.Description == "Script block detected: <script>...</script>" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: harness control — numeric-entity script block must keep its classification, got %+v", findings)
	}
}

// Control: plain ampersands and benign text stay quiet.
func TestDetect_PlainAmpersandBenign(t *testing.T) {
	findings := Detect("fish & chips &amp; more", "body")
	if len(findings) != 0 {
		t.Fatalf("FAIL: harness control — benign ampersand text must produce no findings, got %+v", findings)
	}
}
