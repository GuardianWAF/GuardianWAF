package xxe

import (
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: Process scanned query parameters ONLY through
// ctx.NormalizedQuery, which is populated exclusively by the sanitizer
// layer (sanitizer.go) — and the sanitizer returns early when disabled
// (per-layer toggle or tenant override), leaving the engine's empty map in
// place. With the sanitizer not running, the documented query scanning
// silently no-oped: zero findings for any query-parameter XXE payload,
// while the same detector's body path guarded itself by also scanning the
// raw BodyString. The body's own convention (scan the normalized form,
// plus the raw form when it differs) is applied to queries here.

func TestProcessScansRawQueryParams(t *testing.T) {
	d := NewDetector(true, 1)
	payload := `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`

	// Sanitizer never ran: NormalizedQuery is the engine-initialized empty
	// map; only the raw QueryParams carry the payload.
	ctx := &engine.RequestContext{
		ContentType: "application/xml",
		QueryParams: map[string][]string{"xml": {payload}},
	}
	res := d.Process(ctx)
	if len(res.Findings) == 0 {
		t.Fatalf("FAIL: zero findings for a query-parameter XXE payload when the sanitizer has not populated NormalizedQuery — the query scan silently no-ops")
	}
	foundProtocol := false
	for _, f := range res.Findings {
		if strings.Contains(f.Description, "file://") {
			foundProtocol = true
		}
	}
	if !foundProtocol {
		t.Fatalf("FAIL: file:// protocol finding missing from %d findings", len(res.Findings))
	}
}

// Control: when the sanitizer HAS run and normalization left the payload
// unchanged, the identical form must be scanned exactly once — no
// duplicate counting across the raw and normalized forms.
func TestProcessQueryFormsScannedOnce(t *testing.T) {
	d := NewDetector(true, 1)
	payload := `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`

	ctx := &engine.RequestContext{
		ContentType:     "application/xml",
		QueryParams:     map[string][]string{"xml": {payload}},
		NormalizedQuery: map[string][]string{"xml": {payload}},
	}
	res := d.Process(ctx)
	protocolFindings := 0
	for _, f := range res.Findings {
		if strings.Contains(f.Description, "file://") {
			protocolFindings++
		}
	}
	if protocolFindings != 1 {
		t.Fatalf("FAIL: got %d file:// findings for an identical raw+normalized form, want exactly 1", protocolFindings)
	}

	// Benign query content stays clean.
	benign := &engine.RequestContext{
		ContentType:     "application/xml",
		QueryParams:     map[string][]string{"q": {"hello world"}},
		NormalizedQuery: map[string][]string{"q": {"hello world"}},
	}
	if res := d.Process(benign); len(res.Findings) != 0 {
		t.Fatalf("FAIL: benign query produced %d findings, want 0", len(res.Findings))
	}
}
