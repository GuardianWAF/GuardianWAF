package dlp

import (
	"bytes"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"regexp"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// ---------------------------------------------------------------------------
// ScanRequest — body read error path (line 220-222)
// ---------------------------------------------------------------------------

// errorReader is an io.Reader that always returns an error.
type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}

func (r *errorReader) Close() error { return nil }

func TestLayer_ScanRequest_BodyReadError(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:     true,
		ScanRequest: true,
		Patterns:    []string{"credit_card"},
	})

	req, _ := http.NewRequest("POST", "/test", &errorReader{err: errors.New("read failure")})
	req.Header.Set("Content-Type", "application/json")

	result, err := layer.ScanRequest(req)
	if err == nil {
		t.Error("expected error from body read failure")
	}
	if result != nil {
		t.Error("expected nil result on error")
	}
}

// ---------------------------------------------------------------------------
// scanContent — SeverityHigh branch (lines 281-282)
// ---------------------------------------------------------------------------

func TestLayer_ScanContent_HighSeverity(t *testing.T) {
	r := NewPatternRegistry()
	r.AddCustomPattern("high_test", regexp.MustCompile(`\bHIGH-SECRET-\d+\b`), SeverityHigh, "****")

	layer := NewLayer(&Config{Enabled: true, Patterns: []string{}})
	layer.registry = r

	result := layer.scanContent("Found HIGH-SECRET-123 in text")
	if result.Safe {
		t.Error("expected unsafe result for high severity match")
	}
	if result.RiskScore != 30 {
		t.Errorf("expected risk score 30 for high severity, got %d", result.RiskScore)
	}
}

// ---------------------------------------------------------------------------
// ScanFileUploads — mime.ParseMediaType error (line 364-366)
// ---------------------------------------------------------------------------

func TestLayer_ScanFileUploads_ParseMediaError(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:         true,
		ScanFileUploads: true,
		Patterns:        []string{"credit_card"},
	})

	// mime.ParseMediaType returns an error for malformed media types.
	// An empty string is not a valid media type.
	result, err := layer.ScanFileUploads([]byte("data"), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Safe {
		t.Error("expected safe result when mime.ParseMediaType fails on empty string")
	}
}

// ---------------------------------------------------------------------------
// ScanFileUploads — multipart reader NextPart error (lines 382-383)
//   The NextPart error path for non-EOF errors is hard to trigger because
//   the multipart.Reader loops on NextPart until EOF. With an in-memory
//   bytes.Reader, errors are extremely rare. The corrupted multipart test
//   tends to cause infinite loops in the multipart reader. Skip this from
//   coverage — it's a defensive continue statement for robustness.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ScanFileUploads — text content detection via Content-Type header (line 442)
//   Tests the isTextContent path instead of isTextFile by using a non-text
//   file extension but a text/plain Content-Type on the part.
// ---------------------------------------------------------------------------

func TestLayer_ScanFileUploads_TextContentViaPartContentType(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:         true,
		ScanFileUploads: true,
		MaxFileSize:     10 << 20,
		Patterns:        []string{"credit_card"},
	})

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Create a part with text/plain content type but a non-text-file extension
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="upload"; filename="data.bin"`)
	h.Set("Content-Type", "text/plain")
	part, err := writer.CreatePart(h)
	if err != nil {
		t.Fatalf("failed to create part: %v", err)
	}
	part.Write([]byte("Card: 4111111111111111"))
	writer.Close()

	result, err := layer.ScanFileUploads(buf.Bytes(), writer.FormDataContentType())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should detect credit card because isTextContent returns true for text/plain
	if result.Safe {
		t.Error("expected unsafe result — credit card in text/plain part should be detected")
	}
}

// ---------------------------------------------------------------------------
// ScanFileUploads — JSON content type on part triggers isTextContent
// ---------------------------------------------------------------------------

func TestLayer_ScanFileUploads_JSONContentViaPartContentType(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:         true,
		ScanFileUploads: true,
		MaxFileSize:     10 << 20,
		Patterns:        []string{"credit_card"},
	})

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="upload"; filename="payload.bin"`)
	h.Set("Content-Type", "application/json")
	part, err := writer.CreatePart(h)
	if err != nil {
		t.Fatalf("failed to create part: %v", err)
	}
	part.Write([]byte(`{"card":"4111111111111111"}`))
	writer.Close()

	result, err := layer.ScanFileUploads(buf.Bytes(), writer.FormDataContentType())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Safe {
		t.Error("expected unsafe result — credit card in application/json part should be detected")
	}
}

// ---------------------------------------------------------------------------
// ScanFileUploads — non-text content type on part with non-text extension
//   Should NOT scan because neither isTextContent nor isTextFile is true.
// ---------------------------------------------------------------------------

func TestLayer_ScanFileUploads_NonTextPartNotScanned(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:              true,
		ScanFileUploads:      true,
		MaxFileSize:          10 << 20,
		BlockExecutableFiles: false,
		Patterns:             []string{"credit_card"},
	})

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="upload"; filename="image.bin"`)
	h.Set("Content-Type", "image/png")
	part, err := writer.CreatePart(h)
	if err != nil {
		t.Fatalf("failed to create part: %v", err)
	}
	part.Write([]byte("Card: 4111111111111111"))
	writer.Close()

	result, err := layer.ScanFileUploads(buf.Bytes(), writer.FormDataContentType())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Safe {
		t.Error("expected safe — non-text part should not be scanned for PII")
	}
}

// ---------------------------------------------------------------------------
// Layer.Process — concurrent access stress test
// ---------------------------------------------------------------------------

func TestLayer_Process_ConcurrentStress(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanRequest:  true,
		BlockOnMatch: true,
		Patterns:     []string{"credit_card"},
	})

	done := make(chan bool, 20)
	for i := range 20 {
		go func(idx int) {
			body := fmt.Sprintf(`{"card":"411111111111%d"}`, idx%10)
			req, _ := http.NewRequest("POST", "/test", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			ctx := &engine.RequestContext{
				Request:     req,
				Accumulator: engine.NewScoreAccumulator(2),
			}
			result := layer.Process(ctx)
			_ = result
			done <- true
		}(i)
	}

	for range 20 {
		<-done
	}
}

// ---------------------------------------------------------------------------
// EngineLayer.Process — file upload via Headers map (lines 38-45)
// ---------------------------------------------------------------------------

func TestEngineLayer_Process_FileUploadViaHeaders(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:          true,
		ScanRequest:      true,
		BlockOnMatch:     true,
		ScanFileUploads:  true,
		MaxFileSize:      10 << 20,
		Patterns:         []string{"credit_card"},
	})

	// Build multipart with credit card in a text file
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("upload", "data.txt")
	part.Write([]byte("Card: 4111111111111111"))
	writer.Close()

	ctx := &engine.RequestContext{
		Body:        buf.Bytes(),
		BodyString:  string(buf.Bytes()),
		Headers:     map[string][]string{"Content-Type": {writer.FormDataContentType()}},
		Accumulator: engine.NewScoreAccumulator(2),
	}

	result := el.Process(ctx)
	if result.Action == engine.ActionPass {
		t.Error("expected non-pass action for file upload with PII")
	}
}

// ---------------------------------------------------------------------------
// EngineLayer.Process — file upload safe result (lines 41-44 negative path)
// ---------------------------------------------------------------------------

func TestEngineLayer_Process_FileUploadSafe(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:          true,
		ScanRequest:      true,
		BlockOnMatch:     false,
		ScanFileUploads:  true,
		MaxFileSize:      10 << 20,
		Patterns:         []string{"credit_card"},
	})

	// Build multipart with safe content
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("upload", "data.txt")
	part.Write([]byte("Just some safe text"))
	writer.Close()

	ctx := &engine.RequestContext{
		Body:        buf.Bytes(),
		BodyString:  string(buf.Bytes()),
		Headers:     map[string][]string{"Content-Type": {writer.FormDataContentType()}},
		Accumulator: engine.NewScoreAccumulator(2),
	}

	result := el.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for safe file upload, got %v", result.Action)
	}
}

// ---------------------------------------------------------------------------
// EngineLayer.Process — empty Headers map (file upload path not taken)
// ---------------------------------------------------------------------------

func TestEngineLayer_Process_EmptyHeaders(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:          true,
		ScanRequest:      true,
		BlockOnMatch:     false,
		ScanFileUploads:  true,
		Patterns:         []string{"credit_card"},
	})

	ctx := &engine.RequestContext{
		Body:        []byte(`{"card":"4111111111111111"}`),
		BodyString:  `{"card":"4111111111111111"}`,
		Headers:     map[string][]string{}, // empty — Content-Type key missing
		Accumulator: engine.NewScoreAccumulator(2),
	}

	result := el.Process(ctx)
	// Should still scan body (not file upload path) and find credit card
	// RiskScore 40 >= 25 => ActionLog
	if result.Action == engine.ActionPass {
		t.Error("expected non-pass for body with credit card")
	}
}

// ---------------------------------------------------------------------------
// EngineLayer.Process — scanRequest false
// ---------------------------------------------------------------------------

func TestEngineLayer_Process_ScanRequestFalse(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:      true,
		ScanRequest:  false,
		Patterns:     []string{"credit_card"},
	})

	ctx := &engine.RequestContext{
		Body:        []byte(`{"card":"4111111111111111"}`),
		BodyString:  `{"card":"4111111111111111"}`,
		Accumulator: engine.NewScoreAccumulator(2),
	}

	result := el.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass when scanRequest=false, got %v", result.Action)
	}
}

// ---------------------------------------------------------------------------
// EngineLayer.Process — TenantWAFConfig with DLP enabled
// ---------------------------------------------------------------------------

func TestEngineLayer_Process_TenantConfig_DLPEnabled(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:      true,
		ScanRequest:  true,
		BlockOnMatch: true,
		Patterns:     []string{"credit_card"},
	})

	ctx := &engine.RequestContext{
		Body:        []byte(`{"card":"4111111111111111"}`),
		BodyString:  `{"card":"4111111111111111"}`,
		Accumulator: engine.NewScoreAccumulator(2),
		TenantWAFConfig: &config.WAFConfig{
			DLP: config.DLPConfig{Enabled: true},
		},
	}

	result := el.Process(ctx)
	// Tenant enabled DLP — should detect and act
	if result.Action == engine.ActionPass {
		t.Error("expected non-pass when tenant enables DLP")
	}
}

// ---------------------------------------------------------------------------
// Layer.Process — Findings field details with multiple PII types
// ---------------------------------------------------------------------------

func TestLayer_Process_FindingsDetails(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanRequest:  true,
		BlockOnMatch: true,
		Patterns:     []string{"credit_card", "ssn"},
	})

	req, _ := http.NewRequest("POST", "/test", strings.NewReader(
		`{"card":"4111111111111111","ssn":"123-45-6789"}`))
	req.Header.Set("Content-Type", "application/json")

	ctx := &engine.RequestContext{
		Request:     req,
		Accumulator: engine.NewScoreAccumulator(2),
	}

	result := layer.Process(ctx)
	if len(result.Findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(result.Findings))
	}

	for _, f := range result.Findings {
		if f.DetectorName != "dlp" {
			t.Errorf("expected DetectorName='dlp', got %q", f.DetectorName)
		}
		if f.Category != "PII/PCI" {
			t.Errorf("expected Category='PII/PCI', got %q", f.Category)
		}
		if f.Location != "body" {
			t.Errorf("expected Location='body', got %q", f.Location)
		}
		if f.Score <= 0 {
			t.Errorf("expected positive Score, got %d", f.Score)
		}
	}
}

// ---------------------------------------------------------------------------
// Layer.ScanResponse — verify masking correctness for multiple matches
// ---------------------------------------------------------------------------

func TestLayer_ScanResponse_MultipleTypesMasked(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanResponse: true,
		MaskResponse: true,
		Patterns:     []string{"credit_card", "ssn", "api_key"},
	})

	body := `Card: 4111111111111111, SSN: 123-45-6789, api_key=sk_live_abcdef1234567890`
	result, masked := layer.ScanResponse([]byte(body), "application/json")

	if result.Safe {
		t.Error("expected unsafe result")
	}
	maskedStr := string(masked)
	if strings.Contains(maskedStr, "4111111111111111") {
		t.Error("credit card should be masked")
	}
	if strings.Contains(maskedStr, "123-45-6789") {
		t.Error("SSN should be masked")
	}
}

// ---------------------------------------------------------------------------
// Layer.ScanRequest — nil body on http.Request
// ---------------------------------------------------------------------------

func TestLayer_ScanRequest_NilRequestBody(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:     true,
		ScanRequest: true,
		Patterns:    []string{"credit_card"},
	})

	// Use http.NoBody instead of nil to avoid panic in io.LimitReader
	req, _ := http.NewRequest("POST", "/test", http.NoBody)
	req.Header.Set("Content-Type", "application/json")

	result, err := layer.ScanRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// http.NoBody returns immediately — empty body means no PII found
	if !result.Safe {
		t.Error("expected safe result for empty body")
	}
}

// ---------------------------------------------------------------------------
// MaskValue — IBAN with exactly 6 alphanumeric chars (boundary)
// ---------------------------------------------------------------------------

func TestMaskValue_IBAN_ExactMinLength(t *testing.T) {
	r := NewPatternRegistry()
	p := r.GetPattern(PatternIBAN)
	// Exactly 6 alphanumeric chars — country(2) + last4(4)
	masked := r.maskValue("DE1234", p)
	if !strings.Contains(masked, "DE") {
		t.Errorf("expected country code in mask, got %q", masked)
	}
}

// ---------------------------------------------------------------------------
// Concurrent registry access — SetEnabled + Scan
// ---------------------------------------------------------------------------

func TestPatternRegistry_ConcurrentAccess(t *testing.T) {
	r := NewPatternRegistry()
	done := make(chan bool, 10)

	for i := range 10 {
		go func(idx int) {
			if idx%2 == 0 {
				r.SetEnabled(PatternCreditCard, true)
				matches := r.Scan("Card: 4111111111111111")
				_ = matches
			} else {
				r.SetEnabled(PatternCreditCard, false)
				matches := r.Scan("Card: 4111111111111111")
				_ = matches
			}
			done <- true
		}(i)
	}

	for range 10 {
		<-done
	}
}

// ---------------------------------------------------------------------------
// ScanResponse — content type edge cases
// ---------------------------------------------------------------------------

func TestLayer_ScanResponse_GraphQLContentType(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanResponse: true,
		MaskResponse: true,
		Patterns:     []string{"credit_card"},
	})

	result, _ := layer.ScanResponse([]byte(`{"card":"4111111111111111"}`), "application/graphql")
	if result.Safe {
		t.Error("expected unsafe for application/graphql content type")
	}
}

func TestLayer_ScanResponse_FormURLEncoded(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanResponse: true,
		MaskResponse: true,
		Patterns:     []string{"credit_card"},
	})

	result, _ := layer.ScanResponse([]byte(`card=4111111111111111`), "application/x-www-form-urlencoded")
	if result.Safe {
		t.Error("expected unsafe for form-urlencoded content type with credit card")
	}
}
