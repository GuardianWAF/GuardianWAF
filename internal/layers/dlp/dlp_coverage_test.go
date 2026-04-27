package dlp

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// ---------------------------------------------------------------------------
// DefaultConfig
// ---------------------------------------------------------------------------

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("expected config, got nil")
	}
	if cfg.Enabled {
		t.Error("expected Enabled=false by default")
	}
	if !cfg.ScanRequest {
		t.Error("expected ScanRequest=true by default")
	}
	if !cfg.ScanResponse {
		t.Error("expected ScanResponse=true by default")
	}
	if cfg.BlockOnMatch {
		t.Error("expected BlockOnMatch=false by default")
	}
	if !cfg.MaskResponse {
		t.Error("expected MaskResponse=true by default")
	}
	if cfg.MaxBodySize != 1024*1024 {
		t.Errorf("expected MaxBodySize=1048576, got %d", cfg.MaxBodySize)
	}
	if cfg.MaxFileSize != 10<<20 {
		t.Errorf("expected MaxFileSize=%d, got %d", 10<<20, cfg.MaxFileSize)
	}
	if !cfg.ScanFileUploads {
		t.Error("expected ScanFileUploads=true by default")
	}
	if !cfg.BlockExecutableFiles {
		t.Error("expected BlockExecutableFiles=true by default")
	}
	if cfg.BlockArchiveFiles {
		t.Error("expected BlockArchiveFiles=false by default")
	}
	if !cfg.BlockDangerousWebExtensions {
		t.Error("expected BlockDangerousWebExtensions=true by default")
	}
	if len(cfg.Patterns) == 0 {
		t.Error("expected default patterns")
	}
}

// ---------------------------------------------------------------------------
// NewLayer with nil config (uses defaults)
// ---------------------------------------------------------------------------

func TestNewLayer_NilConfig(t *testing.T) {
	layer := NewLayer(nil)
	if layer == nil {
		t.Fatal("expected layer with nil config, got nil")
	}
	cfg := layer.snapshotConfig()
	if cfg.Enabled {
		t.Error("expected Enabled=false from default config")
	}
	if cfg.MaxBodySize != 1024*1024 {
		t.Errorf("expected default MaxBodySize, got %d", cfg.MaxBodySize)
	}
}

// ---------------------------------------------------------------------------
// NewLayer with zero MaxBodySize
// ---------------------------------------------------------------------------

func TestNewLayer_ZeroMaxBodySize(t *testing.T) {
	cfg := &Config{Enabled: true, MaxBodySize: 0}
	layer := NewLayer(cfg)
	if cfg.MaxBodySize != 1024*1024 {
		t.Errorf("expected MaxBodySize to be set to 1MB default, got %d", cfg.MaxBodySize)
	}
	_ = layer
}

// ---------------------------------------------------------------------------
// configurePatterns — all named patterns
// ---------------------------------------------------------------------------

func TestConfigurePatterns_AllNamed(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled: true,
		Patterns: []string{
			"credit_card", "ssn", "iban", "email", "phone",
			"api_key", "private_key", "passport", "tax_id",
		},
	})
	r := layer.GetRegistry()
	for _, pt := range []PatternType{
		PatternCreditCard, PatternSSN, PatternIBAN, PatternEmail,
		PatternPhone, PatternAPIKey, PatternPrivateKey, PatternPassport, PatternTaxID,
	} {
		p := r.GetPattern(pt)
		if p == nil {
			t.Errorf("expected pattern %s to exist", pt)
			continue
		}
		if !p.Enabled {
			t.Errorf("expected pattern %s to be enabled", pt)
		}
	}
}

func TestConfigurePatterns_UnknownName_Ignored(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:  true,
		Patterns: []string{"nonexistent_pattern"},
	})
	r := layer.GetRegistry()
	for _, pt := range []PatternType{
		PatternCreditCard, PatternSSN, PatternIBAN, PatternEmail,
		PatternPhone, PatternAPIKey, PatternPrivateKey, PatternPassport, PatternTaxID,
	} {
		p := r.GetPattern(pt)
		if p != nil && p.Enabled {
			t.Errorf("expected pattern %s to be disabled with unknown config", pt)
		}
	}
}

func TestConfigurePatterns_EmptyList(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, Patterns: []string{}})
	r := layer.GetRegistry()
	cc := r.GetPattern(PatternCreditCard)
	if cc != nil && cc.Enabled {
		t.Error("expected credit card to be disabled when Patterns is empty")
	}
}

// ---------------------------------------------------------------------------
// EnablePattern / DisablePattern
// ---------------------------------------------------------------------------

func TestLayer_EnableDisablePattern(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, Patterns: []string{}})

	r := layer.GetRegistry()
	if r.GetPattern(PatternCreditCard).Enabled {
		t.Error("expected credit card disabled initially")
	}

	layer.EnablePattern(PatternCreditCard)
	if !r.GetPattern(PatternCreditCard).Enabled {
		t.Error("expected credit card enabled after EnablePattern")
	}

	layer.DisablePattern(PatternCreditCard)
	if r.GetPattern(PatternCreditCard).Enabled {
		t.Error("expected credit card disabled after DisablePattern")
	}
}

// ---------------------------------------------------------------------------
// Layer.AddCustomPattern
// ---------------------------------------------------------------------------

func TestLayer_AddCustomPattern(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, Patterns: []string{"credit_card"}})
	layer.AddCustomPattern("test_custom", &Pattern{
		Type:       PatternCustom,
		Name:       "test_custom",
		Regex:      regexp.MustCompile(`\bTEST-\d{4}\b`),
		Severity:   SeverityLow,
		MaskFormat: "TEST-****",
		Enabled:    true,
	})

	input := "Found TEST-1234 in text"
	matches := layer.GetRegistry().Scan(input)
	found := false
	for _, m := range matches {
		if m.Type == PatternCustom {
			found = true
		}
	}
	if !found {
		t.Error("expected custom pattern match")
	}
}

// ---------------------------------------------------------------------------
// snapshotConfig
// ---------------------------------------------------------------------------

func TestSnapshotConfig(t *testing.T) {
	cfg := &Config{Enabled: true, MaxBodySize: 2048}
	layer := NewLayer(cfg)
	snap := layer.snapshotConfig()
	if !snap.Enabled {
		t.Error("expected Enabled=true in snapshot")
	}
	if snap.MaxBodySize != 2048 {
		t.Errorf("expected MaxBodySize=2048 in snapshot, got %d", snap.MaxBodySize)
	}
}

// ---------------------------------------------------------------------------
// Process — Layer.Process (engine.Layer interface)
// ---------------------------------------------------------------------------

func TestLayerProcess_Disabled(t *testing.T) {
	layer := NewLayer(&Config{Enabled: false})
	ctx := &engine.RequestContext{
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass when disabled, got %v", result.Action)
	}
}

func TestLayerProcess_TenantDisabled(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, ScanRequest: true, Patterns: []string{"credit_card"}})
	ctx := &engine.RequestContext{
		TenantWAFConfig: &config.WAFConfig{
			DLP: config.DLPConfig{Enabled: false},
		},
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass when tenant disabled, got %v", result.Action)
	}
}

func TestLayerProcess_ScanRequest_NoPII(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:     true,
		ScanRequest: true,
		Patterns:    []string{"credit_card"},
	})
	body := `{"message": "hello world"}`
	req := httptestRequest("POST", "/api", body, "application/json")
	ctx := &engine.RequestContext{
		Request:     req,
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass with no PII, got %v", result.Action)
	}
}

func TestLayerProcess_ScanRequest_WithPII_BlockOnMatch(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanRequest:  true,
		BlockOnMatch: true,
		Patterns:     []string{"credit_card"},
	})
	body := `{"card": "4111111111111111"}`
	req := httptestRequest("POST", "/api", body, "application/json")
	ctx := &engine.RequestContext{
		Request:     req,
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected ActionBlock with PII and BlockOnMatch, got %v", result.Action)
	}
	if result.Score <= 0 {
		t.Errorf("expected positive score, got %d", result.Score)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings")
	}
}

func TestLayerProcess_ScanRequest_WithPII_NoBlock(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanRequest:  true,
		BlockOnMatch: false,
		Patterns:     []string{"credit_card"},
	})
	body := `{"card": "4111111111111111"}`
	req := httptestRequest("POST", "/api", body, "application/json")
	ctx := &engine.RequestContext{
		Request:     req,
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass with PII and no BlockOnMatch, got %v", result.Action)
	}
	if result.Score <= 0 {
		t.Errorf("expected positive score, got %d", result.Score)
	}
}

func TestLayerProcess_ScanRequest_UnscannableContentType(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanRequest:  true,
		BlockOnMatch: true,
		Patterns:     []string{"credit_card"},
	})
	body := `binary data with 4111111111111111`
	req := httptestRequest("POST", "/api", body, "application/octet-stream")
	ctx := &engine.RequestContext{
		Request:     req,
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass for unscannable content type, got %v", result.Action)
	}
}

func TestLayerProcess_ScanRequestDisabled(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanRequest:  false,
		BlockOnMatch: true,
		Patterns:     []string{"credit_card"},
	})
	body := `{"card": "4111111111111111"}`
	req := httptestRequest("POST", "/api", body, "application/json")
	ctx := &engine.RequestContext{
		Request:     req,
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass when ScanRequest=false, got %v", result.Action)
	}
}

func TestLayerProcess_NilRequest(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanRequest:  true,
		BlockOnMatch: true,
		Patterns:     []string{"credit_card"},
	})
	ctx := &engine.RequestContext{
		Request:     nil,
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass with nil request, got %v", result.Action)
	}
}

// ---------------------------------------------------------------------------
// severityToEngine / severityScore
// ---------------------------------------------------------------------------

func TestSeverityToEngine(t *testing.T) {
	tests := []struct {
		input    Severity
		expected engine.Severity
	}{
		{SeverityCritical, engine.SeverityCritical},
		{SeverityHigh, engine.SeverityHigh},
		{SeverityMedium, engine.SeverityMedium},
		{SeverityLow, engine.SeverityLow},
		{Severity("unknown"), engine.SeverityLow},
	}
	for _, tt := range tests {
		got := severityToEngine(tt.input)
		if got != tt.expected {
			t.Errorf("severityToEngine(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestSeverityScore(t *testing.T) {
	tests := []struct {
		input    Severity
		expected int
	}{
		{SeverityCritical, 40},
		{SeverityHigh, 30},
		{SeverityMedium, 15},
		{SeverityLow, 5},
		{Severity("unknown"), 5},
	}
	for _, tt := range tests {
		got := severityScore(tt.input)
		if got != tt.expected {
			t.Errorf("severityScore(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// ScanRequest (via Layer)
// ---------------------------------------------------------------------------

func TestLayerScanRequest_Disabled(t *testing.T) {
	layer := NewLayer(&Config{Enabled: false})
	req := httptestRequest("POST", "/", `{"card":"4111111111111111"}`, "application/json")
	result, err := layer.ScanRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Safe {
		t.Error("expected Safe=true when layer disabled")
	}
}

func TestLayerScanRequest_ScanNotEnabled(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, ScanRequest: false})
	req := httptestRequest("POST", "/", `{"card":"4111111111111111"}`, "application/json")
	result, err := layer.ScanRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Safe {
		t.Error("expected Safe=true when ScanRequest=false")
	}
}

func TestLayerScanRequest_UnscannableContent(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:     true,
		ScanRequest: true,
		Patterns:    []string{"credit_card"},
	})
	req := httptestRequest("POST", "/", `{"card":"4111111111111111"}`, "image/png")
	result, err := layer.ScanRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Safe {
		t.Error("expected Safe=true for unscannable content type")
	}
}

func TestLayerScanRequest_WithCreditCard(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:     true,
		ScanRequest: true,
		Patterns:    []string{"credit_card"},
	})
	req := httptestRequest("POST", "/", `{"card":"4111111111111111"}`, "application/json")
	result, err := layer.ScanRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Safe {
		t.Error("expected Safe=false when credit card found")
	}
	if result.RiskScore <= 0 {
		t.Errorf("expected positive RiskScore, got %d", result.RiskScore)
	}
	if len(result.Matches) == 0 {
		t.Error("expected matches")
	}
}

func TestLayerScanRequest_BodyRestored(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:     true,
		ScanRequest: true,
		Patterns:    []string{"credit_card"},
	})
	body := `{"card":"4111111111111111"}`
	req := httptestRequest("POST", "/", body, "application/json")
	_, err := layer.ScanRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	readBody, _ := io.ReadAll(req.Body)
	if string(readBody) != body {
		t.Errorf("body not restored properly: got %q", string(readBody))
	}
}

func TestLayerScanRequest_EmptyBody(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:     true,
		ScanRequest: true,
		Patterns:    []string{"credit_card"},
	})
	req := httptestRequest("POST", "/", "", "application/json")
	result, err := layer.ScanRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Safe {
		t.Error("expected Safe=true for empty body")
	}
}

// ---------------------------------------------------------------------------
// ScanResponse
// ---------------------------------------------------------------------------

func TestLayerScanResponse_Disabled(t *testing.T) {
	layer := NewLayer(&Config{Enabled: false})
	result, body := layer.ScanResponse([]byte(`card: 4111111111111111`), "application/json")
	if !result.Safe {
		t.Error("expected Safe=true when disabled")
	}
	if string(body) != `card: 4111111111111111` {
		t.Error("body should be unchanged when disabled")
	}
}

func TestLayerScanResponse_ScanNotEnabled(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, ScanResponse: false})
	result, body := layer.ScanResponse([]byte(`card: 4111111111111111`), "application/json")
	if !result.Safe {
		t.Error("expected Safe=true when ScanResponse=false")
	}
	if string(body) != `card: 4111111111111111` {
		t.Error("body should be unchanged")
	}
}

func TestLayerScanResponse_UnscannableContent(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanResponse: true,
		Patterns:     []string{"credit_card"},
	})
	result, body := layer.ScanResponse([]byte(`card: 4111111111111111`), "image/png")
	if !result.Safe {
		t.Error("expected Safe=true for unscannable content type")
	}
	if string(body) != `card: 4111111111111111` {
		t.Error("body should be unchanged")
	}
}

func TestLayerScanResponse_BodyTooLarge(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanResponse: true,
		MaxBodySize:  10,
		Patterns:     []string{"credit_card"},
	})
	largeBody := strings.Repeat("card: 4111111111111111 ", 100)
	result, body := layer.ScanResponse([]byte(largeBody), "application/json")
	if !result.Safe {
		t.Error("expected Safe=true when body too large")
	}
	if string(body) != largeBody {
		t.Error("body should be unchanged when too large")
	}
}

func TestLayerScanResponse_WithPII_NoMask(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanResponse: true,
		MaskResponse: false,
		Patterns:     []string{"credit_card"},
	})
	origBody := `{"card":"4111111111111111"}`
	result, body := layer.ScanResponse([]byte(origBody), "application/json")
	if result.Safe {
		t.Error("expected Safe=false when credit card found")
	}
	if string(body) != origBody {
		t.Error("body should be unchanged when MaskResponse=false")
	}
}

func TestLayerScanResponse_WithPII_WithMask(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanResponse: true,
		MaskResponse: true,
		Patterns:     []string{"credit_card"},
	})
	origBody := `{"card":"4111111111111111"}`
	result, body := layer.ScanResponse([]byte(origBody), "application/json")
	if result.Safe {
		t.Error("expected Safe=false when credit card found")
	}
	if string(body) == origBody {
		t.Error("body should be masked when MaskResponse=true")
	}
	if strings.Contains(string(body), "4111111111111111") {
		t.Error("masked body should not contain original credit card number")
	}
}

func TestLayerScanResponse_NoPII(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:      true,
		ScanResponse: true,
		MaskResponse: true,
		Patterns:     []string{"credit_card"},
	})
	origBody := `{"message":"hello"}`
	result, body := layer.ScanResponse([]byte(origBody), "application/json")
	if !result.Safe {
		t.Error("expected Safe=true when no PII found")
	}
	if string(body) != origBody {
		t.Error("body should be unchanged when no matches")
	}
}

// ---------------------------------------------------------------------------
// scanContent — Low severity score
// ---------------------------------------------------------------------------

func TestLayerScanContent_LowSeverity(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:  true,
		Patterns: []string{},
	})
	layer.GetRegistry().AddCustomPattern("low_test", regexp.MustCompile(`\bLOW-\d{4}\b`), SeverityLow, "****")
	result := layer.scanContent("Found LOW-1234 here")
	if result.Safe {
		t.Error("expected Safe=false for custom low severity match")
	}
	if result.RiskScore != 5 {
		t.Errorf("expected RiskScore=5 for low severity, got %d", result.RiskScore)
	}
}

func TestLayerScanContent_EmptyInput(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, Patterns: []string{"credit_card"}})
	result := layer.scanContent("")
	if !result.Safe {
		t.Error("expected Safe=true for empty input")
	}
}

// ---------------------------------------------------------------------------
// maskContent — position out of range
// ---------------------------------------------------------------------------

func TestLayerMaskContent_PositionOutOfRange(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, Patterns: []string{"credit_card"}})
	content := "short"
	matches := []Match{
		{Position: 100, Length: 5, Masked: "XXXXX"},
	}
	masked := layer.maskContent(content, matches)
	if masked != "short" {
		t.Errorf("expected unchanged content for out-of-range match, got %q", masked)
	}
}

func TestLayerMaskContent_MultipleMatches(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:  true,
		Patterns: []string{"credit_card", "ssn"},
	})
	content := "Card: 4111111111111111 and SSN: 123-45-6789"
	result := layer.scanContent(content)
	if result.Safe {
		t.Fatal("expected PII to be detected")
	}
	masked := layer.maskContent(content, result.Matches)
	if strings.Contains(masked, "4111111111111111") {
		t.Error("credit card should be masked")
	}
	if strings.Contains(masked, "123-45-6789") {
		t.Error("SSN should be masked")
	}
}

// ---------------------------------------------------------------------------
// GetAllPatterns
// ---------------------------------------------------------------------------

func TestGetAllPatterns(t *testing.T) {
	r := NewPatternRegistry()
	all := r.GetAllPatterns()
	if len(all) == 0 {
		t.Error("expected some default patterns")
	}
	expectedCount := 9
	if len(all) != expectedCount {
		t.Errorf("expected %d patterns, got %d", expectedCount, len(all))
	}
}

// ---------------------------------------------------------------------------
// GetCustomPattern / RemoveCustomPattern
// ---------------------------------------------------------------------------

func TestGetCustomPattern(t *testing.T) {
	r := NewPatternRegistry()
	p := r.GetCustomPattern("my_custom")
	if p != nil {
		t.Error("expected nil for non-existent custom pattern")
	}

	r.AddCustomPattern("my_custom", regexp.MustCompile(`\bCUS-\d+\b`), SeverityMedium, "CUS-***")
	p = r.GetCustomPattern("my_custom")
	if p == nil {
		t.Fatal("expected custom pattern after adding")
	}
	if p.Name != "my_custom" {
		t.Errorf("expected name=my_custom, got %s", p.Name)
	}
	if p.Type != PatternCustom {
		t.Errorf("expected type=custom, got %s", p.Type)
	}
	if !p.Enabled {
		t.Error("expected custom pattern to be enabled")
	}
}

func TestRemoveCustomPattern(t *testing.T) {
	r := NewPatternRegistry()
	if r.RemoveCustomPattern("nonexistent") {
		t.Error("expected false when removing non-existent pattern")
	}

	r.AddCustomPattern("to_remove", regexp.MustCompile(`\bRM-\d+\b`), SeverityLow, "RM-***")
	if !r.RemoveCustomPattern("to_remove") {
		t.Error("expected true when removing existing pattern")
	}
	if r.GetCustomPattern("to_remove") != nil {
		t.Error("expected nil after removal")
	}
}

// ---------------------------------------------------------------------------
// Scan with custom patterns — disabled custom pattern
// ---------------------------------------------------------------------------

func TestScan_CustomPattern_Disabled(t *testing.T) {
	r := NewPatternRegistry()
	r.AddCustomPattern("disabled_custom", regexp.MustCompile(`\bDIS-\d+\b`), SeverityLow, "DIS-***")
	p := r.GetCustomPattern("disabled_custom")
	p.Enabled = false

	matches := r.Scan("Found DIS-1234 here")
	for _, m := range matches {
		if m.Masked == "DIS-***" {
			t.Error("disabled custom pattern should not match")
		}
	}
}

// ---------------------------------------------------------------------------
// Pattern matchers — edge cases for each type
// ---------------------------------------------------------------------------

func TestScan_Phone(t *testing.T) {
	r := NewPatternRegistry()
	r.SetEnabled(PatternPhone, true)

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"US phone with dashes", "Phone: 415-555-1234", 1},
		{"US phone with parens", "Phone: (415) 555-1234", 1},
		{"US phone with +1", "Phone: +1-415-555-1234", 1},
		{"No phone", "Just some text", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := r.Scan(tt.input)
			phoneMatches := 0
			for _, m := range matches {
				if m.Type == PatternPhone {
					phoneMatches++
				}
			}
			if phoneMatches != tt.expected {
				t.Errorf("expected %d phone matches, got %d", tt.expected, phoneMatches)
			}
		})
	}
}

func TestScan_TaxID(t *testing.T) {
	r := NewPatternRegistry()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"Valid EIN", "EIN: 12-3456789", 1},
		{"Another EIN", "Tax ID: 99-9999999", 1},
		{"Invalid - too short", "ID: 1-2345678", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := r.Scan(tt.input)
			taxMatches := 0
			for _, m := range matches {
				if m.Type == PatternTaxID {
					taxMatches++
				}
			}
			if taxMatches != tt.expected {
				t.Errorf("expected %d tax_id matches, got %d", tt.expected, taxMatches)
			}
		})
	}
}

func TestScan_Passport(t *testing.T) {
	r := NewPatternRegistry()
	r.SetEnabled(PatternPassport, true)

	matches := r.Scan("Passport: AB1234567")
	passportMatches := 0
	for _, m := range matches {
		if m.Type == PatternPassport {
			passportMatches++
		}
	}
	if passportMatches == 0 {
		t.Error("expected passport match")
	}
}

func TestScan_MultipleTypes(t *testing.T) {
	r := NewPatternRegistry()
	r.SetEnabled(PatternEmail, true)
	r.SetEnabled(PatternPhone, true)

	input := "Contact user@example.com at 415-555-1234. SSN: 123-45-6789"
	matches := r.Scan(input)

	types := map[PatternType]int{}
	for _, m := range matches {
		types[m.Type]++
	}

	if types[PatternSSN] == 0 {
		t.Error("expected SSN match")
	}
	if types[PatternEmail] == 0 {
		t.Error("expected email match")
	}
	if types[PatternPhone] == 0 {
		t.Error("expected phone match")
	}
}

// ---------------------------------------------------------------------------
// maskValue — all pattern type branches
// ---------------------------------------------------------------------------

func TestMaskValue_CreditCard_NoDigits(t *testing.T) {
	r := NewPatternRegistry()
	pattern := r.GetPattern(PatternCreditCard)
	masked := r.maskValue("abc", pattern)
	if masked == "" {
		t.Error("expected non-empty mask even for short input")
	}
}

func TestMaskValue_CreditCard_Exact4(t *testing.T) {
	r := NewPatternRegistry()
	pattern := r.GetPattern(PatternCreditCard)
	masked := r.maskValue("1234", pattern)
	if !strings.Contains(masked, "1234") {
		t.Errorf("expected last4=1234 in mask, got %q", masked)
	}
}

func TestMaskValue_SSN_NoDashes(t *testing.T) {
	r := NewPatternRegistry()
	pattern := r.GetPattern(PatternSSN)
	masked := r.maskValue("123456789", pattern)
	// Without dashes, Split won't produce 3 parts, format stays with placeholder
	if strings.Contains(masked, "${last4}") {
		t.Logf("SSN mask without dashes retains placeholder: %q", masked)
	}
}

func TestMaskValue_SSN_WithDashes(t *testing.T) {
	r := NewPatternRegistry()
	pattern := r.GetPattern(PatternSSN)
	masked := r.maskValue("123-45-6789", pattern)
	if !strings.HasSuffix(masked, "6789") {
		t.Errorf("expected mask to end with 6789, got %q", masked)
	}
}

func TestMaskValue_IBAN_Short(t *testing.T) {
	r := NewPatternRegistry()
	pattern := r.GetPattern(PatternIBAN)
	masked := r.maskValue("AB12", pattern)
	t.Logf("Short IBAN mask: %q", masked)
}

func TestMaskValue_IBAN_Valid(t *testing.T) {
	r := NewPatternRegistry()
	pattern := r.GetPattern(PatternIBAN)
	masked := r.maskValue("DE89370400440532013000", pattern)
	if !strings.HasPrefix(masked, "DE") {
		t.Errorf("expected mask to start with country code DE, got %q", masked)
	}
}

func TestMaskValue_Email(t *testing.T) {
	r := NewPatternRegistry()
	pattern := r.GetPattern(PatternEmail)

	tests := []struct {
		name  string
		input string
		check func(t *testing.T, masked string)
	}{
		{
			name:  "Normal email",
			input: "user@example.com",
			check: func(t *testing.T, masked string) {
				if !strings.Contains(masked, "@example.com") {
					t.Errorf("expected domain in mask, got %q", masked)
				}
			},
		},
		{
			name:  "Email with short user",
			input: "ab@c.com",
			check: func(t *testing.T, masked string) {
				if !strings.Contains(masked, "@c.com") {
					t.Errorf("expected domain in mask, got %q", masked)
				}
			},
		},
		{
			name:  "No at sign",
			input: "notanemail",
			check: func(t *testing.T, masked string) {
				// Without @, the format string stays with placeholders
				t.Logf("No-at email mask: %q", masked)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			masked := r.maskValue(tt.input, pattern)
			tt.check(t, masked)
		})
	}
}

func TestMaskValue_APIKey(t *testing.T) {
	r := NewPatternRegistry()
	pattern := r.GetPattern(PatternAPIKey)

	tests := []struct {
		name  string
		input string
		check func(t *testing.T, masked string)
	}{
		{
			name:  "Long enough",
			input: "sk_live_abcdef1234567890",
			check: func(t *testing.T, masked string) {
				if !strings.HasPrefix(masked, "sk_l") {
					t.Errorf("expected prefix 'sk_l' in mask, got %q", masked)
				}
			},
		},
		{
			name:  "Too short (< 8 chars)",
			input: "short",
			check: func(t *testing.T, masked string) {
				// Short value retains placeholders
				t.Logf("Short API key mask: %q", masked)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			masked := r.maskValue(tt.input, pattern)
			tt.check(t, masked)
		})
	}
}

func TestMaskValue_TaxID(t *testing.T) {
	r := NewPatternRegistry()
	pattern := r.GetPattern(PatternTaxID)
	masked := r.maskValue("12-3456789", pattern)
	if !strings.HasSuffix(masked, "6789") {
		t.Errorf("expected mask ending with 6789, got %q", masked)
	}
}

func TestMaskValue_TaxID_ShortSecondPart(t *testing.T) {
	r := NewPatternRegistry()
	pattern := r.GetPattern(PatternTaxID)
	masked := r.maskValue("12-345", pattern)
	t.Logf("TaxID mask with short second part: %q", masked)
}

func TestMaskValue_TaxID_NoDash(t *testing.T) {
	r := NewPatternRegistry()
	pattern := r.GetPattern(PatternTaxID)
	masked := r.maskValue("123456789", pattern)
	t.Logf("TaxID mask without dash: %q", masked)
}

func TestMaskValue_DefaultCase(t *testing.T) {
	r := NewPatternRegistry()
	customPattern := &Pattern{
		Type:       PatternCustom,
		Name:       "test",
		Regex:      regexp.MustCompile(`test`),
		Severity:   SeverityLow,
		MaskFormat: "",
		Enabled:    true,
	}
	masked := r.maskValue("sensitive", customPattern)
	if masked != "*********" {
		t.Errorf("expected all asterisks for default with empty mask, got %q", masked)
	}
}

func TestMaskValue_DefaultCase_WithMask(t *testing.T) {
	r := NewPatternRegistry()
	customPattern := &Pattern{
		Type:       PatternCustom,
		Name:       "test",
		Regex:      regexp.MustCompile(`test`),
		Severity:   SeverityLow,
		MaskFormat: "[REDACTED]",
		Enabled:    true,
	}
	masked := r.maskValue("sensitive", customPattern)
	if masked != "[REDACTED]" {
		t.Errorf("expected [REDACTED] for default with mask, got %q", masked)
	}
}

// ---------------------------------------------------------------------------
// Scan — empty text
// ---------------------------------------------------------------------------

func TestScan_EmptyText(t *testing.T) {
	r := NewPatternRegistry()
	matches := r.Scan("")
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty text, got %d", len(matches))
	}
}

// ---------------------------------------------------------------------------
// Scan — Match struct fields (Position, Length, Value cleared)
// ---------------------------------------------------------------------------

func TestScan_MatchFields(t *testing.T) {
	r := NewPatternRegistry()
	input := "SSN: 123-45-6789 here"
	matches := r.Scan(input)
	if len(matches) == 0 {
		t.Fatal("expected at least one match")
	}
	m := matches[0]
	if m.Value != "" {
		t.Error("expected Value to be cleared (empty string) for security")
	}
	if m.Position < 0 || m.Position >= len(input) {
		t.Errorf("expected valid position, got %d", m.Position)
	}
	if m.Length <= 0 {
		t.Errorf("expected positive length, got %d", m.Length)
	}
	if m.Masked == "" {
		t.Error("expected non-empty masked value")
	}
	if m.Position+m.Length > len(input) {
		t.Errorf("match range [%d:%d] exceeds input length %d", m.Position, m.Position+m.Length, len(input))
	}
}

// ---------------------------------------------------------------------------
// ScanFileUploads
// ---------------------------------------------------------------------------

func TestScanFileUploads_Disabled(t *testing.T) {
	layer := NewLayer(&Config{Enabled: false})
	result, err := layer.ScanFileUploads([]byte("any"), "multipart/form-data; boundary=----abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Safe {
		t.Error("expected Safe=true when disabled")
	}
}

func TestScanFileUploads_ScanNotEnabled(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, ScanFileUploads: false})
	result, err := layer.ScanFileUploads([]byte("any"), "multipart/form-data; boundary=----abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Safe {
		t.Error("expected Safe=true when ScanFileUploads=false")
	}
}

func TestScanFileUploads_InvalidContentType(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, ScanFileUploads: true})
	result, err := layer.ScanFileUploads([]byte("any"), "not-multipart")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Safe {
		t.Error("expected Safe=true for invalid content type")
	}
}

func TestScanFileUploads_NoBoundary(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true, ScanFileUploads: true})
	result, err := layer.ScanFileUploads([]byte("any"), "multipart/form-data")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Safe {
		t.Error("expected Safe=true when no boundary")
	}
}

func TestScanFileUploads_NoFileParts(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:         true,
		ScanFileUploads: true,
		Patterns:        []string{"credit_card"},
	})

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.WriteField("name", "value")
	writer.Close()

	result, err := layer.ScanFileUploads(buf.Bytes(), writer.FormDataContentType())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Safe {
		t.Error("expected Safe=true with no file parts")
	}
}

func TestScanFileUploads_ExecutableFile(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:              true,
		ScanFileUploads:      true,
		MaxFileSize:          10 << 20,
		BlockExecutableFiles: true,
		Patterns:             []string{"credit_card"},
	})

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("upload", "malware.exe")
	part.Write([]byte("binary content"))
	writer.Close()

	result, err := layer.ScanFileUploads(buf.Bytes(), writer.FormDataContentType())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Safe {
		t.Error("expected Safe=false for executable file upload")
	}
	found := false
	for _, m := range result.Matches {
		if m.Masked == "[EXECUTABLE_FILE_BLOCKED]" {
			found = true
		}
	}
	if !found {
		t.Error("expected EXECUTABLE_FILE_BLOCKED match")
	}
}

func TestScanFileUploads_ArchiveFile(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:           true,
		ScanFileUploads:   true,
		MaxFileSize:       10 << 20,
		BlockArchiveFiles: true,
		Patterns:          []string{"credit_card"},
	})

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("upload", "archive.zip")
	part.Write([]byte("zip content"))
	writer.Close()

	result, err := layer.ScanFileUploads(buf.Bytes(), writer.FormDataContentType())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Safe {
		t.Error("expected Safe=false for archive file upload")
	}
	found := false
	for _, m := range result.Matches {
		if m.Masked == "[ARCHIVE_FILE_BLOCKED]" {
			found = true
		}
	}
	if !found {
		t.Error("expected ARCHIVE_FILE_BLOCKED match")
	}
}

func TestScanFileUploads_DangerousWebFile(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:                     true,
		ScanFileUploads:             true,
		MaxFileSize:                 10 << 20,
		BlockDangerousWebExtensions: true,
		Patterns:                    []string{"credit_card"},
	})

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("upload", "shell.php")
	part.Write([]byte("<?php echo 'hello'; ?>"))
	writer.Close()

	result, err := layer.ScanFileUploads(buf.Bytes(), writer.FormDataContentType())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Safe {
		t.Error("expected Safe=false for dangerous web file upload")
	}
	found := false
	for _, m := range result.Matches {
		if m.Masked == "[DANGEROUS_WEB_FILE_BLOCKED]" {
			found = true
		}
	}
	if !found {
		t.Error("expected DANGEROUS_WEB_FILE_BLOCKED match")
	}
}

func TestScanFileUploads_DoubleExtension(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:                     true,
		ScanFileUploads:             true,
		MaxFileSize:                 10 << 20,
		BlockDangerousWebExtensions: true,
		Patterns:                    []string{"credit_card"},
	})

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("upload", "shell.php.jpg")
	part.Write([]byte("malicious content"))
	writer.Close()

	result, err := layer.ScanFileUploads(buf.Bytes(), writer.FormDataContentType())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Safe {
		t.Error("expected Safe=false for double extension dangerous file")
	}
}

func TestScanFileUploads_FileTooLarge(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:         true,
		ScanFileUploads: true,
		MaxFileSize:     10,
		Patterns:        []string{"credit_card"},
	})

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("upload", "data.txt")
	part.Write([]byte(strings.Repeat("x", 100)))
	writer.Close()

	result, err := layer.ScanFileUploads(buf.Bytes(), writer.FormDataContentType())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Safe {
		t.Error("expected Safe=false for oversized file")
	}
	found := false
	for _, m := range result.Matches {
		if m.Masked == "[FILE_TOO_LARGE]" {
			found = true
		}
	}
	if !found {
		t.Error("expected FILE_TOO_LARGE match")
	}
}

func TestScanFileUploads_TextFileWithPII(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:         true,
		ScanFileUploads: true,
		MaxFileSize:     10 << 20,
		Patterns:        []string{"credit_card"},
	})

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("upload", "data.txt")
	part.Write([]byte("Card: 4111111111111111"))
	writer.Close()

	result, err := layer.ScanFileUploads(buf.Bytes(), writer.FormDataContentType())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Safe {
		t.Error("expected Safe=false for text file with credit card")
	}
}

func TestScanFileUploads_TextFile_JSONWithPII(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:         true,
		ScanFileUploads: true,
		MaxFileSize:     10 << 20,
		Patterns:        []string{"credit_card"},
	})

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("upload", "data.json")
	part.Write([]byte(`{"card":"4111111111111111"}`))
	writer.Close()

	result, err := layer.ScanFileUploads(buf.Bytes(), writer.FormDataContentType())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Safe {
		t.Error("expected Safe=false for JSON file with credit card")
	}
}

func TestScanFileUploads_NonTextFile_NoScan(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:         true,
		ScanFileUploads: true,
		MaxFileSize:     10 << 20,
		Patterns:        []string{"credit_card"},
	})

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("upload", "image.png")
	part.Write([]byte("fake PNG with card 4111111111111111"))
	writer.Close()

	result, err := layer.ScanFileUploads(buf.Bytes(), writer.FormDataContentType())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Safe {
		t.Error("expected Safe=true for non-text file (no PII scan)")
	}
}

// ---------------------------------------------------------------------------
// isExecutableFile
// ---------------------------------------------------------------------------

func TestIsExecutableFile(t *testing.T) {
	tests := []struct {
		filename string
		expected bool
	}{
		{"program.exe", true},
		{"library.DLL", true},
		{"script.bat", true},
		{"script.cmd", true},
		{"shell.sh", true},
		{"binary.bin", true},
		{"setup.msi", true},
		{"app.apk", true},
		{"mac.app", true},
		{"disk.dmg", true},
		{"package.pkg", true},
		{"debian.deb", true},
		{"redhat.rpm", true},
		{"document.pdf", false},
		{"image.png", false},
		{"text.txt", false},
		{"data.json", false},
	}
	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := isExecutableFile(tt.filename)
			if got != tt.expected {
				t.Errorf("isExecutableFile(%q) = %v, want %v", tt.filename, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isArchiveFile
// ---------------------------------------------------------------------------

func TestIsArchiveFile(t *testing.T) {
	tests := []struct {
		filename string
		expected bool
	}{
		{"archive.zip", true},
		{"backup.tar", true},
		{"data.gz", true},
		{"compressed.rar", true},
		{"seven.7z", true},
		{"file.bz2", true},
		{"file.xz", true},
		{"combined.tar.gz", true},
		{"bundle.tgz", true},
		{"archive.tar.bz2", true},
		{"document.pdf", false},
		{"image.png", false},
	}
	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := isArchiveFile(tt.filename)
			if got != tt.expected {
				t.Errorf("isArchiveFile(%q) = %v, want %v", tt.filename, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isDangerousWebFile
// ---------------------------------------------------------------------------

func TestIsDangerousWebFile(t *testing.T) {
	tests := []struct {
		filename string
		expected bool
	}{
		// Direct extensions
		{"index.php", true},
		{"index.php5", true},
		{"index.phtml", true},
		{"page.asp", true},
		{"page.aspx", true},
		{"page.ascx", true},
		{"page.ashx", true},
		{"page.asmx", true},
		{"page.asa", true},
		{"page.jsp", true},
		{"page.jspx", true},
		{"page.jsw", true},
		{"page.jspa", true},
		{"page.jspm", true},
		{"script.cgi", true},
		{"script.pl", true},
		{"script.py", true},
		{"script.rb", true},
		{"page.cfm", true},
		{"page.cfc", true},
		{"service.wsdl", true},
		{"transform.xslt", true},
		// Double extensions
		{"shell.php.jpg", true},
		{"shell.jsp.png", true},
		{"shell.asp.gif", true},
		// Safe files
		{"index.html", false},
		{"image.jpg", false},
		{"document.pdf", false},
		{"script.js", false},
		{"style.css", false},
		{"data.json", false},
		{"photo.png", false},
		{"single.dot.only.txt", false},
	}
	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := isDangerousWebFile(tt.filename)
			if got != tt.expected {
				t.Errorf("isDangerousWebFile(%q) = %v, want %v", tt.filename, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isTextContent
// ---------------------------------------------------------------------------

func TestIsTextContent(t *testing.T) {
	tests := []struct {
		contentType string
		expected    bool
	}{
		{"text/plain", true},
		{"text/html", true},
		{"application/json", true},
		{"application/xml", true},
		{"application/javascript", true},
		{"application/octet-stream", false},
		{"image/png", false},
		{"video/mp4", false},
	}
	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			got := isTextContent(tt.contentType)
			if got != tt.expected {
				t.Errorf("isTextContent(%q) = %v, want %v", tt.contentType, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isTextFile
// ---------------------------------------------------------------------------

func TestIsTextFile(t *testing.T) {
	tests := []struct {
		filename string
		expected bool
	}{
		{"readme.txt", true},
		{"data.json", true},
		{"config.xml", true},
		{"export.csv", true},
		{"debug.log", true},
		{"docs.md", true},
		{"config.yaml", true},
		{"config.yml", true},
		{"app.properties", true},
		{"app.conf", true},
		{"app.ini", true},
		{"index.html", true},
		{"index.htm", true},
		{"script.js", true},
		{"style.css", true},
		{"image.png", false},
		{"binary.exe", false},
		{"archive.zip", false},
	}
	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := isTextFile(tt.filename)
			if got != tt.expected {
				t.Errorf("isTextFile(%q) = %v, want %v", tt.filename, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EngineLayer
// ---------------------------------------------------------------------------

func TestNewEngineLayer(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:     true,
		ScanRequest: true,
		Patterns:    []string{"credit_card"},
	})
	if el == nil {
		t.Fatal("expected EngineLayer, got nil")
	}
}

func TestEngineLayer_Process_Disabled(t *testing.T) {
	el := NewEngineLayer(&Config{Enabled: false})
	ctx := &engine.RequestContext{
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := el.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass when disabled, got %v", result.Action)
	}
}

func TestEngineLayer_Process_TenantDisabled(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:     true,
		ScanRequest: true,
		Patterns:    []string{"credit_card"},
	})
	ctx := &engine.RequestContext{
		TenantWAFConfig: &config.WAFConfig{
			DLP: config.DLPConfig{Enabled: false},
		},
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := el.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass when tenant disabled, got %v", result.Action)
	}
}

func TestEngineLayer_Process_NoBody(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:     true,
		ScanRequest: true,
		Patterns:    []string{"credit_card"},
	})
	ctx := &engine.RequestContext{
		Body:        nil,
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := el.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass with no body, got %v", result.Action)
	}
}

func TestEngineLayer_Process_WithPII_BodyString(t *testing.T) {
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
	}
	result := el.Process(ctx)
	// Credit card = severityCritical = 40 points; >= 25 threshold => ActionLog
	if result.Action != engine.ActionLog && result.Action != engine.ActionBlock {
		t.Errorf("expected ActionLog or ActionBlock with PII, got %v", result.Action)
	}
}

func TestEngineLayer_Process_WithPII_BodyOnly(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:      true,
		ScanRequest:  true,
		BlockOnMatch: true,
		Patterns:     []string{"credit_card"},
	})
	ctx := &engine.RequestContext{
		Body:        []byte(`{"card":"4111111111111111"}`),
		BodyString:  "",
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := el.Process(ctx)
	if result.Action != engine.ActionLog && result.Action != engine.ActionBlock {
		t.Errorf("expected ActionLog or ActionBlock with PII, got %v", result.Action)
	}
}

func TestEngineLayer_Process_WithPII_NoBlock_LowRisk(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:      true,
		ScanRequest:  true,
		BlockOnMatch: false,
		Patterns:     []string{"credit_card"},
	})
	ctx := &engine.RequestContext{
		Body:        []byte(`safe content`),
		BodyString:  `safe content`,
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := el.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass for safe content, got %v", result.Action)
	}
}

func TestEngineLayer_Process_WithPII_BlockOnMatch_HighRisk(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:      true,
		ScanRequest:  true,
		BlockOnMatch: true,
		Patterns:     []string{"credit_card"},
	})
	ctx := &engine.RequestContext{
		Body:        []byte(`card: 4111111111111111`),
		BodyString:  `card: 4111111111111111`,
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := el.Process(ctx)
	// Credit card = severityCritical = 40, which is < 50 block threshold => ActionLog
	if result.Action != engine.ActionLog && result.Action != engine.ActionBlock {
		t.Errorf("expected ActionLog or ActionBlock for credit card, got %v", result.Action)
	}
}

func TestEngineLayer_Process_WithPII_BlockOnMatch_MediumRisk(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:      true,
		ScanRequest:  true,
		BlockOnMatch: true,
		Patterns:     []string{},
	})
	el.GetRegistry().AddCustomPattern("low_risk", regexp.MustCompile(`\bLOW-\d{4}\b`), SeverityLow, "****")
	ctx := &engine.RequestContext{
		Body:        []byte(`Found LOW-1234 here`),
		BodyString:  `Found LOW-1234 here`,
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := el.Process(ctx)
	// RiskScore 5 < 50, so block won't trigger even though BlockOnMatch=true
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass when risk < 50, got %v", result.Action)
	}
}

func TestEngineLayer_Process_WithPII_LogThreshold(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:      true,
		ScanRequest:  true,
		BlockOnMatch: false,
		Patterns:     []string{},
	})
	el.GetRegistry().AddCustomPattern("med_risk", regexp.MustCompile(`\bMED-\d{4}\b`), SeverityMedium, "****")
	ctx := &engine.RequestContext{
		Body:        []byte(`Found MED-1234 here`),
		BodyString:  `Found MED-1234 here`,
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := el.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass when risk < 25, got %v", result.Action)
	}
}

func TestEngineLayer_Process_FileUpload(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:          true,
		ScanRequest:      true,
		BlockOnMatch:     true,
		ScanFileUploads:  true,
		MaxFileSize:      10 << 20,
		Patterns:         []string{"credit_card"},
	})

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, _ := writer.CreateFormFile("upload", "data.txt")
	part.Write([]byte("Card: 4111111111111111"))
	writer.Close()

	contentType := writer.FormDataContentType()

	ctx := &engine.RequestContext{
		Body:        buf.Bytes(),
		BodyString:  "",
		Headers:     map[string][]string{"Content-Type": {contentType}},
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := el.Process(ctx)
	// Credit card = severityCritical = 40 points, < 50 block threshold => ActionLog
	if result.Action != engine.ActionLog && result.Action != engine.ActionBlock {
		t.Errorf("expected ActionLog or ActionBlock for file upload with PII, got %v", result.Action)
	}
}

// ---------------------------------------------------------------------------
// EngineLayer — convertSeverity, severityToScore, formatFindingDescription
// ---------------------------------------------------------------------------

func TestEngineLayer_ConvertSeverity(t *testing.T) {
	el := NewEngineLayer(&Config{Enabled: true})
	tests := []struct {
		input    Severity
		expected engine.Severity
	}{
		{SeverityCritical, engine.SeverityCritical},
		{SeverityHigh, engine.SeverityHigh},
		{SeverityMedium, engine.SeverityMedium},
		{SeverityLow, engine.SeverityLow},
		{Severity("unknown"), engine.SeverityInfo},
	}
	for _, tt := range tests {
		got := el.convertSeverity(tt.input)
		if got != tt.expected {
			t.Errorf("convertSeverity(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestEngineLayer_SeverityToScore(t *testing.T) {
	el := NewEngineLayer(&Config{Enabled: true})
	tests := []struct {
		input    Severity
		expected int
	}{
		{SeverityCritical, 40},
		{SeverityHigh, 30},
		{SeverityMedium, 15},
		{SeverityLow, 5},
		{Severity("unknown"), 10},
	}
	for _, tt := range tests {
		got := el.severityToScore(tt.input)
		if got != tt.expected {
			t.Errorf("severityToScore(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestEngineLayer_FormatFindingDescription(t *testing.T) {
	el := NewEngineLayer(&Config{Enabled: true})
	m := Match{
		Type:   PatternCreditCard,
		Masked: "****-****-****-1111",
	}
	desc := el.formatFindingDescription(m)
	if !strings.Contains(desc, "credit_card") {
		t.Errorf("expected description to contain type, got %q", desc)
	}
	if !strings.Contains(desc, "****-****-****-1111") {
		t.Errorf("expected description to contain masked value, got %q", desc)
	}
}

// ---------------------------------------------------------------------------
// EngineLayer.ScanHTTPRequest / ScanHTTPResponse
// ---------------------------------------------------------------------------

func TestEngineLayer_ScanHTTPRequest(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:     true,
		ScanRequest: true,
		Patterns:    []string{"credit_card"},
	})
	req := httptestRequest("POST", "/", `{"card":"4111111111111111"}`, "application/json")
	result, err := el.ScanHTTPRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Safe {
		t.Error("expected Safe=false for request with credit card")
	}
}

func TestEngineLayer_ScanHTTPResponse(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:      true,
		ScanResponse: true,
		MaskResponse: true,
		Patterns:     []string{"credit_card"},
	})
	result, body := el.ScanHTTPResponse([]byte(`card: 4111111111111111`), "application/json")
	if result.Safe {
		t.Error("expected Safe=false for response with credit card")
	}
	if strings.Contains(string(body), "4111111111111111") {
		t.Error("expected response body to be masked")
	}
}

// ---------------------------------------------------------------------------
// EngineLayer handleScanResult — accumulated findings
// ---------------------------------------------------------------------------

func TestEngineLayer_HandleScanResult_AccumulatesFindings(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:      true,
		BlockOnMatch: true,
		Patterns:     []string{"credit_card"},
	})
	ctx := &engine.RequestContext{
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := &ScanResult{
		Safe: false,
		Matches: []Match{
			{Type: PatternCreditCard, Severity: SeverityCritical, Masked: "****-****-****-1111"},
			{Type: PatternSSN, Severity: SeverityCritical, Masked: "***-**-6789"},
		},
		RiskScore: 80,
	}
	r := el.handleScanResult(ctx, result, "body")
	if r.Action != engine.ActionBlock {
		t.Errorf("expected ActionBlock, got %v", r.Action)
	}
}

func TestEngineLayer_HandleScanResult_Log(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:      true,
		BlockOnMatch: false,
		Patterns:     []string{},
	})

	ctx := &engine.RequestContext{
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := &ScanResult{
		Safe: false,
		Matches: []Match{
			{Type: PatternCustom, Severity: SeverityHigh, Masked: "****"},
		},
		RiskScore: 30,
	}
	r := el.handleScanResult(ctx, result, "body")
	if r.Action != engine.ActionLog {
		t.Errorf("expected ActionLog for risk >= 25, got %v", r.Action)
	}
}

func TestEngineLayer_HandleScanResult_Pass(t *testing.T) {
	el := NewEngineLayer(&Config{
		Enabled:      true,
		BlockOnMatch: false,
		Patterns:     []string{},
	})

	ctx := &engine.RequestContext{
		Accumulator: engine.NewScoreAccumulator(2),
	}
	result := &ScanResult{
		Safe: false,
		Matches: []Match{
			{Type: PatternCustom, Severity: SeverityLow, Masked: "****"},
		},
		RiskScore: 5,
	}
	r := el.handleScanResult(ctx, result, "body")
	if r.Action != engine.ActionPass {
		t.Errorf("expected ActionPass for risk < 25, got %v", r.Action)
	}
}

// ---------------------------------------------------------------------------
// extractDigits / extractAlphanumeric
// ---------------------------------------------------------------------------

func TestExtractDigits(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"4111-1111-1111-1111", "4111111111111111"},
		{"abc", ""},
		{"", ""},
		{"a1b2c3", "123"},
	}
	for _, tt := range tests {
		got := extractDigits(tt.input)
		if got != tt.expected {
			t.Errorf("extractDigits(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestExtractAlphanumeric(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"DE89 3704 0044 0532 0130 00", "DE89370400440532013000"},
		{"!@#$%", ""},
		{"", ""},
		{"AB-12_cd", "AB12cd"},
	}
	for _, tt := range tests {
		got := extractAlphanumeric(tt.input)
		if got != tt.expected {
			t.Errorf("extractAlphanumeric(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// isScannableContent — additional content types
// ---------------------------------------------------------------------------

func TestIsScannableContent_Additional(t *testing.T) {
	tests := []struct {
		contentType string
		expected    bool
	}{
		{"application/graphql", true},
		{"APPLICATION/JSON", true},
		{"text/xml; charset=utf-8", true},
		{"video/mp4", false},
		{"audio/mpeg", false},
	}
	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			got := isScannableContent(tt.contentType)
			if got != tt.expected {
				t.Errorf("isScannableContent(%q) = %v, want %v", tt.contentType, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Scan — various credit card formats
// ---------------------------------------------------------------------------

func TestScan_CreditCard_Formats(t *testing.T) {
	r := NewPatternRegistry()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"Visa no dashes", "4111111111111111", 1},
		{"Visa with dashes", "4111-1111-1111-1111", 1},
		{"Visa with spaces", "4111 1111 1111 1111", 1},
		{"MasterCard", "5500000000000004", 1},
		{"Amex", "378282246310005", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := r.Scan(tt.input)
			ccMatches := 0
			for _, m := range matches {
				if m.Type == PatternCreditCard {
					ccMatches++
				}
			}
			if ccMatches != tt.expected {
				t.Errorf("expected %d credit_card matches, got %d for %q", tt.expected, ccMatches, tt.input)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Scan — private key types
// ---------------------------------------------------------------------------

func TestScan_PrivateKey_Types(t *testing.T) {
	r := NewPatternRegistry()

	tests := []struct {
		name  string
		input string
	}{
		{
			"RSA",
			"-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
		},
		{
			"EC",
			"-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEI\n-----END EC PRIVATE KEY-----",
		},
		{
			"DSA",
			"-----BEGIN DSA PRIVATE KEY-----\nMIIBuwIBAAJ\n-----END DSA PRIVATE KEY-----",
		},
		{
			"OPENSSH",
			"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----",
		},
		{
			"Generic",
			"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkq\n-----END PRIVATE KEY-----",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := r.Scan(tt.input)
			found := false
			for _, m := range matches {
				if m.Type == PatternPrivateKey {
					found = true
				}
			}
			if !found {
				t.Errorf("expected private_key match for %s", tt.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Scan — API key formats
// ---------------------------------------------------------------------------

func TestScan_APIKey_Formats(t *testing.T) {
	r := NewPatternRegistry()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"api_key with colon", `api_key: "sk_live_abcdef1234567890"`, 1},
		{"apikey with equals", `apikey=ghp_abcdef1234567890abcdef`, 1},
		{"token with colon space", `token: sk_live_abcdef1234567890`, 1},
		{"api-key with dash", `api-key: "mysecretkey12345678"`, 1},
		{"no separator", `apikeywithoutseparator`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := r.Scan(tt.input)
			apiMatches := 0
			for _, m := range matches {
				if m.Type == PatternAPIKey {
					apiMatches++
				}
			}
			if apiMatches != tt.expected {
				t.Errorf("expected %d api_key matches, got %d for %q", tt.expected, apiMatches, tt.input)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Scan — IBAN edge cases
// ---------------------------------------------------------------------------

func TestScan_IBAN_EdgeCases(t *testing.T) {
	r := NewPatternRegistry()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"French IBAN", "IBAN: FR76 3000 6000 0112 3456 7890 189", 1},
		{"Spanish IBAN", "IBAN: ES91 2100 0418 4502 0005 1332", 1},
		{"Too short", "AB12", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := r.Scan(tt.input)
			ibanMatches := 0
			for _, m := range matches {
				if m.Type == PatternIBAN {
					ibanMatches++
				}
			}
			if ibanMatches != tt.expected {
				t.Errorf("expected %d iban matches, got %d for %q", tt.expected, ibanMatches, tt.input)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Scan — SSN edge cases
// ---------------------------------------------------------------------------

func TestScan_SSN_EdgeCases(t *testing.T) {
	r := NewPatternRegistry()

	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"Starts with 0", "012-34-5678", 1},
		{"Starts with 8", "812-34-5678", 1}, // [0-8] includes 8, so 812 matches
		{"999", "999-99-9999", 0},            // starts with 9, outside [0-8]
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := r.Scan(tt.input)
			ssnMatches := 0
			for _, m := range matches {
				if m.Type == PatternSSN {
					ssnMatches++
				}
			}
			if ssnMatches != tt.expected {
				t.Errorf("expected %d ssn matches, got %d for %q", tt.expected, ssnMatches, tt.input)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EngineLayer interface check
// ---------------------------------------------------------------------------

func TestEngineLayer_ImplementsEngineLayer(t *testing.T) {
	var _ engine.Layer = NewEngineLayer(&Config{Enabled: true})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func httptestRequest(method, url, body, contentType string) *http.Request {
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	return req
}
