package apivalidation

import (
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

const scalarParameterDeserializationSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "scalar parameter regression", "version": "1"},
  "paths": {
    "/items/{id}": {
      "get": {
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "integer", "minimum": 1}},
          {"name": "limit", "in": "query", "required": true, "schema": {"type": "integer", "minimum": 1}},
          {"name": "enabled", "in": "query", "required": true, "schema": {"type": "boolean"}},
          {"name": "X-Ratio", "in": "header", "required": true, "schema": {"type": "number", "minimum": 0.5}},
          {"name": "secure", "in": "cookie", "required": true, "schema": {"type": "boolean"}}
        ],
        "responses": {"200": {"description": "ok"}}
      }
    },
    "/control": {
      "get": {
        "parameters": [
          {"name": "q", "in": "query", "required": true, "schema": {"type": "string", "minLength": 2}}
        ],
        "responses": {"200": {"description": "ok"}}
      }
    }
  }
}`

func newScalarParameterLayer(t *testing.T) *Layer {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ValidateRequest = true
	cfg.BlockOnViolation = true
	layer := NewLayer(cfg)
	if err := layer.LoadSchema(SchemaSource{
		Content: scalarParameterDeserializationSpec,
		Type:    "openapi",
		Name:    "scalar-parameter-regression",
	}); err != nil {
		t.Fatalf("load scalar parameter spec: %v", err)
	}
	return layer
}

func validScalarParameterContext() *engine.RequestContext {
	return &engine.RequestContext{
		Method: "GET",
		Path:   "/items/42",
		Headers: map[string][]string{
			"X-Ratio": {"1.5"},
		},
		QueryParams: map[string][]string{
			"limit":   {"10"},
			"enabled": {"true"},
		},
		Cookies: map[string][]string{
			"secure": {"false"},
		},
	}
}

func TestOpenAPIParameterScalarsDeserializeBeforeValidation(t *testing.T) {
	result := newScalarParameterLayer(t).Process(validScalarParameterContext())
	if result.Action != engine.ActionPass || len(result.Findings) != 0 {
		t.Fatalf("valid serialized scalar parameters rejected: action=%s findings=%v", result.Action, result.Findings)
	}
}

func TestOpenAPIParameterStringControlUnchanged(t *testing.T) {
	result := newScalarParameterLayer(t).Process(&engine.RequestContext{
		Method:      "GET",
		Path:        "/control",
		Headers:     map[string][]string{},
		QueryParams: map[string][]string{"q": {"ok"}},
		Cookies:     map[string][]string{},
	})
	if result.Action != engine.ActionPass || len(result.Findings) != 0 {
		t.Fatalf("valid string control rejected: action=%s findings=%v", result.Action, result.Findings)
	}
}

func TestOpenAPIParameterScalarInvalidFormsStillFail(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*engine.RequestContext)
		wantField string
	}{
		{
			name: "integer lexical form",
			mutate: func(ctx *engine.RequestContext) {
				ctx.QueryParams["limit"] = []string{"not-an-integer"}
			},
			wantField: "limit",
		},
		{
			name: "integer constraint",
			mutate: func(ctx *engine.RequestContext) {
				ctx.QueryParams["limit"] = []string{"0"}
			},
			wantField: "limit",
		},
		{
			name: "non-whole integer",
			mutate: func(ctx *engine.RequestContext) {
				ctx.QueryParams["limit"] = []string{"1.5"}
			},
			wantField: "limit",
		},
		{
			name: "boolean lexical form",
			mutate: func(ctx *engine.RequestContext) {
				ctx.QueryParams["enabled"] = []string{"yes"}
			},
			wantField: "enabled",
		},
		{
			name: "number constraint",
			mutate: func(ctx *engine.RequestContext) {
				ctx.Headers["X-Ratio"] = []string{"0.25"}
			},
			wantField: "X-Ratio",
		},
		{
			name: "path integer constraint",
			mutate: func(ctx *engine.RequestContext) {
				ctx.Path = "/items/0"
			},
			wantField: "id",
		},
		{
			name: "cookie boolean lexical form",
			mutate: func(ctx *engine.RequestContext) {
				ctx.Cookies["secure"] = []string{"on"}
			},
			wantField: "secure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := validScalarParameterContext()
			tt.mutate(ctx)
			result := newScalarParameterLayer(t).Process(ctx)
			if result.Action != engine.ActionBlock || len(result.Findings) == 0 {
				t.Fatalf("invalid scalar parameter passed: action=%s findings=%v", result.Action, result.Findings)
			}
			var descriptions []string
			for _, finding := range result.Findings {
				descriptions = append(descriptions, finding.Description)
			}
			if !strings.Contains(strings.Join(descriptions, " "), tt.wantField) {
				t.Fatalf("findings %q do not identify %q", descriptions, tt.wantField)
			}
		})
	}
}
