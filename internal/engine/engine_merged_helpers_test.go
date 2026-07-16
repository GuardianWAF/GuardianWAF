package engine

import "github.com/guardianwaf/guardianwaf/internal/tracing"

// responseHookLayer is a test helper used by tests merged from engine_gap_test.go
type responseHookLayer struct{ name string }

func (l *responseHookLayer) Name() string { return l.name }
func (l *responseHookLayer) Order() int   { return 0 }
func (l *responseHookLayer) Process(ctx *RequestContext) LayerResult {
	ctx.ResponseMaskFn = func(body string) string {
		return "masked:" + body
	}
	ctx.ClientsideBodyXform = func(body []byte, contentType string) ([]byte, bool) {
		if contentType == "text/plain; charset=utf-8" {
			return append([]byte("xform:"), body...), true
		}
		return body, false
	}
	return LayerResult{Action: ActionPass}
}

// Ensure tracing import is used
var _ = (*tracing.Span)(nil)
