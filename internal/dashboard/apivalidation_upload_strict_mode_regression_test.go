package dashboard

// Regression (hunt round 2026-09-28-apival-upload-strictmode): the schema
// upload endpoint accepted a per-schema `strict_mode` and silently discarded it.
//
// Defect: POST /api/apivalidation/schemas parsed `strict_mode` from the
// operator's JSON body into APISchemaInfo.StrictMode
// (apivalidation_handlers.go:85 and :104), and both the list and detail
// endpoints echoed a "strict_mode" field back (`:62` and `:147`) — presenting
// it as a real per-schema setting on the read side.
//
// The write side dropped it: apiValidationAdapter.LoadSchema built
// apivalidation.SchemaSource{Type, Content, Name} only. SchemaSource has no
// StrictMode field at all (apivalidation/schema.go:57-63), and every
// enforcement decision in the layer reads the GLOBAL l.config.StrictMode
// (layer.go:548 NewSchemaValidator(l.config.StrictMode); also :488, :511,
// :531). So an operator who uploaded with strict_mode: true received
// NON-strict validation — an undeclared property passed — while the API
// advertised the knob as honoured.
//
// The read-back could never report true either: compiledSpecToInfo
// (`:328-335`) never populates StrictMode, so the echoed value was the Go
// zero value regardless of what was uploaded.
//
// Fix: the upload rejects a per-schema strict_mode explicitly (HTTP 400,
// naming the global setting), rather than accepting a security-relevant
// parameter that does nothing. This is the silent-knob family: the buildDLP
// round, r20 suspicious_patterns, the siem ExtraFields fix, and the
// 2026-10-02 buildResponse x_content_type_options fix — every one of which
// was an accepted-but-dropped knob.
//
// The invariant, not one resolution: an accepted parameter must either reach
// its consumer or be explicitly refused. These tests accept BOTH valid
// outcomes so a future change that genuinely implements per-schema strict
// mode does not break them.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/apivalidation"
)

// uploadStrictModeSpec declares exactly one property, so an undeclared one is
// the strict-mode violation probe.
const uploadStrictModeSpec = `{
	"openapi": "3.0.0",
	"info": {"title": "orders-api", "version": "1"},
	"paths": {
		"/orders": {
			"post": {
				"requestBody": {
					"content": {
						"application/json": {
							"schema": {
								"type": "object",
								"properties": {"id": {"type": "integer"}}
							}
						}
					}
				}
			}
		}
	}
}`

// postUploadSchema drives the real handler and returns the recorder.
func postUploadSchema(t *testing.T, d *Dashboard, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := NewAPIValidationHandler(d)
	req := httptest.NewRequest(http.MethodPost, "/api/apivalidation/schemas", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.handleUploadSchema(rec, req)
	return rec
}

// undeclaredPropOrderCtx is a POST /orders whose body carries a property the
// schema does not declare.
func undeclaredPropOrderCtx() *engine.RequestContext {
	body := `{"id":7,"undeclared_field":"surprise"}`
	return &engine.RequestContext{
		Method:      http.MethodPost,
		Path:        "/orders",
		Body:        []byte(body),
		BodyString:  body,
		ContentType: "application/json",
		Headers:     map[string][]string{"Content-Type": {"application/json"}},
	}
}

// jsonStringLit renders s as a JSON string literal. encoding/json, not a
// hand-rolled escaper: JSON forbids raw control characters (tab included)
// inside strings, and the spec above is tab-indented.
func jsonStringLit(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal spec literal: %v", err)
	}
	return string(b)
}

// The defect: per-schema strict_mode must not be silently accepted and
// discarded. Either it is enforced, or the upload is explicitly refused.
func TestAPISchemaUploadStrictModeNotSilentlyDropped(t *testing.T) {
	// Global strict_mode OFF: the operator's per-schema request is the only
	// source of strictness they asked for.
	layer := apivalidation.NewLayer(&apivalidation.Config{
		Enabled:          true,
		ValidateRequest:  true,
		BlockOnViolation: true,
		StrictMode:       false,
	})
	d := &Dashboard{apiValidationOverride: &apiValidationAdapter{layer: layer}}

	body := `{"name":"orders","format":"openapi","content":` +
		jsonStringLit(t, uploadStrictModeSpec) + `,"strict_mode":true}`
	rec := postUploadSchema(t, d, body)

	switch {
	case rec.Code == http.StatusOK:
		// Honoured: strict validation must actually apply to this schema.
		if res := layer.Process(undeclaredPropOrderCtx()); len(res.Findings) == 0 {
			t.Fatalf("per-schema strict_mode was accepted and then silently dropped: the " +
				"undeclared property 'undeclared_field' passed. LoadSchema builds " +
				"SchemaSource{Type, Content, Name} and that type has no StrictMode field; " +
				"every enforcement decision reads the GLOBAL l.config.StrictMode, so the " +
				"operator's per-schema strict_mode had no effect while the list/detail " +
				"read-backs advertised the field")
		}
	case rec.Code == http.StatusBadRequest:
		// Refused: the operator is told the setting is global, not per-schema.
		if msg := rec.Body.String(); !strings.Contains(msg, "strict_mode") {
			t.Fatalf("upload refused with HTTP 400 but the message does not mention "+
				"strict_mode, so the operator cannot tell which field was rejected: %s", msg)
		}
	default:
		t.Fatalf("upload with strict_mode:true returned HTTP %d (%s) — the parameter must "+
			"either be enforced or explicitly refused with 4xx", rec.Code, rec.Body.String())
	}
}

// The read-back must never claim a per-schema strict mode that does not exist.
func TestAPISchemaListDoesNotAdvertisePerSchemaStrictMode(t *testing.T) {
	layer := apivalidation.NewLayer(&apivalidation.Config{Enabled: true, ValidateRequest: true})
	adapter := &apiValidationAdapter{layer: layer}

	spec := &APISchemaInfo{Name: "orders", Format: "openapi", Content: uploadStrictModeSpec}
	if err := adapter.LoadSchema(spec); err != nil {
		t.Fatalf("seed load: %v", err)
	}

	got := adapter.GetSchema("orders")
	if got == nil {
		t.Fatal("uploaded schema must be discoverable by name")
	}
	// compiledSpecToInfo does not populate StrictMode; this pins that a
	// compiled spec never carries one, so the dashboard cannot advertise a
	// per-schema strict mode it does not enforce.
	if got.StrictMode {
		t.Fatal("a compiled spec reported StrictMode=true, but the layer has no " +
			"per-schema strict-mode state — such a value could never be enforced")
	}
}

// Control (must hold before and after the fix): the GLOBAL strict_mode still
// rejects an undeclared property. A failure here means the harness never
// reached real schema enforcement and the defect case above proves nothing.
func TestAPISchemaUploadControlGlobalStrictModeStillEnforced(t *testing.T) {
	layer := apivalidation.NewLayer(&apivalidation.Config{
		Enabled:          true,
		ValidateRequest:  true,
		BlockOnViolation: true,
		StrictMode:       true, // global this time
	})
	d := &Dashboard{apiValidationOverride: &apiValidationAdapter{layer: layer}}

	body := `{"name":"orders","format":"openapi","content":` + jsonStringLit(t, uploadStrictModeSpec) + `}`
	rec := postUploadSchema(t, d, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("control setup: ordinary upload rejected with HTTP %d (%s)", rec.Code, rec.Body.String())
	}

	if res := layer.Process(undeclaredPropOrderCtx()); len(res.Findings) == 0 {
		t.Fatal("control harness broken: with GLOBAL strict_mode:true the undeclared " +
			"property must be rejected, but no findings were produced")
	}
}

// Control (must hold before and after the fix): an upload WITHOUT the knob is
// unaffected — the neighbour fields still load and enforce.
func TestAPISchemaUploadWithoutStrictModeStillWorks(t *testing.T) {
	layer := apivalidation.NewLayer(&apivalidation.Config{
		Enabled:          true,
		ValidateRequest:  true,
		BlockOnViolation: true,
	})
	d := &Dashboard{apiValidationOverride: &apiValidationAdapter{layer: layer}}

	body := `{"name":"orders","format":"openapi","content":` + jsonStringLit(t, uploadStrictModeSpec) + `}`
	rec := postUploadSchema(t, d, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("ordinary upload rejected with HTTP %d (%s)", rec.Code, rec.Body.String())
	}

	got := (&apiValidationAdapter{layer: layer}).GetSchema("orders")
	if got == nil {
		t.Fatal("uploaded schema must be discoverable by name")
	}
	if got.Format != "openapi" {
		t.Fatalf("format = %q, want openapi — the neighbouring knob must round-trip", got.Format)
	}
	// The declared property still validates.
	ok := &engine.RequestContext{
		Method:      http.MethodPost,
		Path:        "/orders",
		Body:        []byte(`{"id":7}`),
		BodyString:  `{"id":7}`,
		ContentType: "application/json",
		Headers:     map[string][]string{"Content-Type": {"application/json"}},
	}
	if res := layer.Process(ok); len(res.Findings) != 0 {
		t.Fatalf("a conforming body produced %d finding(s): %v", len(res.Findings), res.Findings)
	}
}
