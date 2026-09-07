package sanitizer

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/detection/smuggling"
)

// Regression tests: the sanitizer must NOT mutate ctx.Headers when
// strip_hop_by_hop is enabled. The previous StripHopByHopHeaders(ctx) call
// deleted Transfer-Encoding/Connection/TE from the shared header map at
// pipeline order 300, blinding the order-400 smuggling detector (it reads
// ctx.Headers["Transfer-Encoding"] for four of its five vectors). The reverse
// proxy forwards the original *http.Request — it never reads ctx.Headers — so
// the mutation never affected forwarding and only destroyed detection.

func hophopCtx() *engine.RequestContext {
	return &engine.RequestContext{
		Method: "POST",
		Path:   "/submit",
		Headers: map[string][]string{
			"Content-Length":    {"5"},
			"Connection":        {"keep-alive"},
			"Transfer-Encoding": {"chunked"},
			"Host":              {"example.com"},
			"User-Agent":        {"scan-tool"},
		},
		BodyString: "hello",
	}
}

func TestStripHopByHopDoesNotBlindSmugglingDetector(t *testing.T) {
	ctx := hophopCtx()

	san := NewLayer(&Config{StripHopByHop: true})
	san.Process(ctx)

	detector := smuggling.NewDetector(true, 1.0)
	result := detector.Process(ctx)

	found := false
	for _, f := range result.Findings {
		if f.Category == "http-request-smuggling" {
			found = true
		}
	}
	if !found || result.Score == 0 {
		t.Fatalf("FAIL: hop-by-hop stripping blinded the smuggling detector: a CL+TE request produced no smuggling findings (categories=%v score=%d)", result.Findings, result.Score)
	}
}

func TestStripHopByHopPreservesTEHeader(t *testing.T) {
	ctx := hophopCtx()

	san := NewLayer(&Config{StripHopByHop: true})
	san.Process(ctx)

	if _, ok := ctx.Headers["Transfer-Encoding"]; !ok {
		t.Fatalf("FAIL: Transfer-Encoding was deleted from ctx.Headers — the shared detector view must not be mutated (forwarding uses the original *http.Request)")
	}
	if _, ok := ctx.Headers["Connection"]; !ok {
		t.Fatalf("FAIL: Connection was deleted from ctx.Headers")
	}
}
