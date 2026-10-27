package apivalidation

import (
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

const typeMismatchScoreSpec = `{"openapi":"3.0.0","info":{"title":"type-score-regression","version":"1"},"paths":{"/typed":{"post":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"integer"}}}},"responses":{"200":{"description":"ok"}}}},"/bounded":{"post":{"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"string","maxLength":1}}}},"responses":{"200":{"description":"ok"}}}}}}`

func newTypeMismatchScoreLayer(t *testing.T, block bool) *Layer {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ValidateRequest = true
	cfg.StrictMode = false
	cfg.BlockOnViolation = block
	layer := NewLayer(cfg)
	if err := layer.LoadSchema(SchemaSource{
		Type:    "openapi",
		Name:    "type-score-regression",
		Content: typeMismatchScoreSpec,
	}); err != nil {
		t.Fatalf("LoadSchema: %v", err)
	}
	return layer
}

func processTypeMismatchScoreJSON(layer *Layer, path, body string) engine.LayerResult {
	return layer.Process(&engine.RequestContext{
		Method:  "POST",
		Path:    path,
		Body:    []byte(body),
		Headers: map[string][]string{"Content-Type": {"application/json"}},
	})
}

func TestTypeMismatchScoreBlocksRequest(t *testing.T) {
	layer := newTypeMismatchScoreLayer(t, true)

	valid := processTypeMismatchScoreJSON(layer, "/typed", `42`)
	if valid.Action != engine.ActionPass || valid.Score != 0 || len(valid.Findings) != 0 {
		t.Fatalf("valid integer body: action=%s score=%d findings=%v", valid.Action, valid.Score, valid.Findings)
	}

	bounded := processTypeMismatchScoreJSON(layer, "/bounded", `"too-long"`)
	if bounded.Action != engine.ActionBlock || bounded.Score <= 0 {
		t.Fatalf("maxLength scoring control: action=%s score=%d findings=%v", bounded.Action, bounded.Score, bounded.Findings)
	}

	mismatch := processTypeMismatchScoreJSON(layer, "/typed", `"wrong-type"`)
	if mismatch.Action != engine.ActionBlock || mismatch.Score != 10 || len(mismatch.Findings) != 1 {
		t.Fatalf("type mismatch: action=%s score=%d findings=%v", mismatch.Action, mismatch.Score, mismatch.Findings)
	}
	if !strings.Contains(mismatch.Findings[0].Description, "expected integer, got string") {
		t.Fatalf("unexpected mismatch finding: %q", mismatch.Findings[0].Description)
	}
}

func TestTypeMismatchScoreLogsWhenBlockingDisabled(t *testing.T) {
	layer := newTypeMismatchScoreLayer(t, false)
	mismatch := processTypeMismatchScoreJSON(layer, "/typed", `"wrong-type"`)
	if mismatch.Action != engine.ActionLog || mismatch.Score != 10 || len(mismatch.Findings) != 1 {
		t.Fatalf("non-blocking type mismatch: action=%s score=%d findings=%v", mismatch.Action, mismatch.Score, mismatch.Findings)
	}
}
