package xss

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ersinkoc/guardianwaf/internal/engine"
)

// --- Attack payloads that MUST be detected (score >= 50) ---

var attackPayloads = []struct {
	name     string
	input    string
	minScore int
}{
	{"script block", "<script>alert(1)</script>", 95},
	{"img onerror", "<img src=x onerror=alert(1)>", 85},
	{"svg onload", "<svg/onload=alert(1)>", 85},
	{"javascript protocol", "javascript:alert(1)", 80},
	{"iframe javascript", `<iframe src="javascript:alert(1)">`, 80},
	{"body onload", "<body onload=alert(1)>", 85},
	{"div style javascript", `<div style="background:url(javascript:alert(1))">`, 80},
	{"input onfocus", "<input onfocus=alert(1) autofocus>", 70},
	{"hex encoded script", "\\x3cscript\\x3ealert(1)", 90},
	{"mixed case script", "<ScRiPt>alert(1)</ScRiPt>", 95},
	{"meta refresh", `<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(1)">`, 50},
	{"template mustache", "{{constructor.constructor('alert(1)')()}}", 55},
	{"template es6", "${alert(1)}", 55},
	{"document cookie", "document.cookie", 60},
	{"dangerous js func", "eval('alert(1)')", 65},
}

// --- Benign inputs that must NOT trigger high scores (score < 25) ---

var benignInputs = []struct {
	name     string
	input    string
	maxScore int
}{
	{"p tag", "<p>Hello World</p>", 24},
	{"bold tag", "This is a <b>bold</b> statement", 24},
	{"dollar amount", "The price is $100", 0},
	{"getElementById", "Use document.getElementById()", 24},
	{"heart emoji text", "I love <3 puppies", 0},
	{"plain text", "Click here for details", 0},
	{"comparison operators", "a > b && c < d", 0},
}

func TestDetect_AttackPayloads(t *testing.T) {
	for _, tt := range attackPayloads {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore < tt.minScore {
				t.Errorf("input=%q: total score %d < minimum %d\nfindings: %+v",
					tt.input, totalScore, tt.minScore, findings)
			}
		})
	}
}

func TestDetect_BenignInputs(t *testing.T) {
	for _, tt := range benignInputs {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore > tt.maxScore {
				t.Errorf("input=%q: total score %d > maximum %d\nfindings: %+v",
					tt.input, totalScore, tt.maxScore, findings)
			}
		})
	}
}

func TestDetect_EmptyInput(t *testing.T) {
	findings := Detect("", "query")
	if findings != nil {
		t.Errorf("expected nil findings for empty input, got %v", findings)
	}
}

func TestDetect_ScriptVariants(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minScore int
	}{
		{"basic script", "<script>alert(1)</script>", 95},
		{"script with attributes", `<script type="text/javascript">alert(1)</script>`, 95},
		{"script tag only", "<script src=evil.js>", 90},
		{"mixed case", "<ScRiPt>alert(1)</ScRiPt>", 95},
		{"uppercase", "<SCRIPT>alert(1)</SCRIPT>", 95},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore < tt.minScore {
				t.Errorf("input=%q: total score %d < %d", tt.input, totalScore, tt.minScore)
			}
		})
	}
}

func TestDetect_EventHandlers(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minScore int
	}{
		{"img onerror", "<img src=x onerror=alert(1)>", 85},
		{"body onload", "<body onload=alert(1)>", 85},
		{"div onmouseover", "<div onmouseover=alert(1)>", 85},
		{"svg onload", "<svg onload=alert(1)>", 85},
		{"input onfocus", "<input onfocus=alert(1) autofocus>", 70},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore < tt.minScore {
				t.Errorf("input=%q: total score %d < %d\nfindings: %+v",
					tt.input, totalScore, tt.minScore, findings)
			}
		})
	}
}

func TestDetect_JavaScriptProtocol(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minScore int
	}{
		{"plain", "javascript:alert(1)", 80},
		{"iframe", `<iframe src="javascript:alert(1)">`, 80},
		{"anchor", `<a href="javascript:void(0)">click</a>`, 80},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore < tt.minScore {
				t.Errorf("input=%q: total score %d < %d\nfindings: %+v",
					tt.input, totalScore, tt.minScore, findings)
			}
		})
	}
}

func TestDetect_TemplateInjection(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minScore int
	}{
		{"mustache", "{{constructor.constructor('alert(1)')()}}", 55},
		{"es6 template", "${alert(1)}", 55},
		{"ruby/pug", "#{alert(1)}", 55},
		{"angular", "{{7*7}}", 55},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore < tt.minScore {
				t.Errorf("input=%q: total score %d < %d\nfindings: %+v",
					tt.input, totalScore, tt.minScore, findings)
			}
		})
	}
}

func TestDetect_EncodedPayloads(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minScore int
	}{
		{"hex escape script", "\\x3cscript\\x3ealert(1)", 90},
		{"url encoded", "%3cscript%3ealert(1)", 90},
		{"html entity decimal", "&#60;script&#62;alert(1)", 20},
		{"unicode escape", "\\u003cscript\\u003e", 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore < tt.minScore {
				t.Errorf("input=%q: total score %d < %d\nfindings: %+v",
					tt.input, totalScore, tt.minScore, findings)
			}
		})
	}
}

func TestDetect_DOMManipulation(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minScore int
	}{
		{"document.cookie", "document.cookie", 60},
		{"document.write", "document.write('<h1>XSS</h1>')", 55},
		{"innerHTML", "element.innerHTML = payload", 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore < tt.minScore {
				t.Errorf("input=%q: total score %d < %d\nfindings: %+v",
					tt.input, totalScore, tt.minScore, findings)
			}
		})
	}
}

func TestDetect_DangerousTags(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minScore int
	}{
		{"iframe", "<iframe src=evil.html>", 50},
		{"object", "<object data=evil.swf>", 45},
		{"embed", "<embed src=evil.swf>", 45},
		{"form with action", `<form action="http://evil.com/steal">`, 40},
		{"meta refresh", `<meta http-equiv="refresh" content="0;url=http://evil.com">`, 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore < tt.minScore {
				t.Errorf("input=%q: total score %d < %d\nfindings: %+v",
					tt.input, totalScore, tt.minScore, findings)
			}
		})
	}
}

func TestDetect_CSSExpression(t *testing.T) {
	findings := Detect(`<div style="width:expression(alert(1))">`, "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 70 {
		t.Errorf("CSS expression: total score %d < 70\nfindings: %+v", totalScore, findings)
	}
}

func TestDetect_FindingFields(t *testing.T) {
	findings := Detect("<script>alert(1)</script>", "query")
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	for _, f := range findings {
		if f.DetectorName != "xss" {
			t.Errorf("DetectorName: expected 'xss', got %q", f.DetectorName)
		}
		if f.Category != "xss" {
			t.Errorf("Category: expected 'xss', got %q", f.Category)
		}
		if f.Location != "query" {
			t.Errorf("Location: expected 'query', got %q", f.Location)
		}
		if f.Score <= 0 {
			t.Errorf("Score should be > 0, got %d", f.Score)
		}
		if f.Description == "" {
			t.Error("Description should not be empty")
		}
		if f.Confidence <= 0 || f.Confidence > 1.0 {
			t.Errorf("Confidence should be in (0, 1.0], got %f", f.Confidence)
		}
		if len(f.MatchedValue) > 200 {
			t.Errorf("MatchedValue should be truncated to 200 chars, got %d", len(f.MatchedValue))
		}
	}
}

// --- Detector Integration Tests ---

func TestDetector_Interface(t *testing.T) {
	det := NewDetector(true, 1.0)

	// Verify interface compliance
	var _ engine.Detector = det

	if det.Name() != "xss-detector" {
		t.Errorf("expected name 'xss-detector', got %q", det.Name())
	}
	if det.DetectorName() != "xss" {
		t.Errorf("expected detector name 'xss', got %q", det.DetectorName())
	}
	if len(det.Patterns()) == 0 {
		t.Error("expected non-empty patterns list")
	}
}

func TestDetector_Process(t *testing.T) {
	det := NewDetector(true, 1.0)

	reqURL, _ := url.Parse("http://example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E")
	req := &http.Request{
		Method: "GET",
		URL:    reqURL,
		Header: http.Header{},
	}

	ctx := &engine.RequestContext{
		Request:        req,
		Method:         "GET",
		NormalizedPath: "/search",
		NormalizedQuery: map[string][]string{
			"q": {"<script>alert(1)</script>"},
		},
		Headers: map[string][]string{},
		Cookies: map[string]string{},
	}

	result := det.Process(ctx)

	if result.Action != engine.ActionLog {
		t.Errorf("expected ActionLog, got %v", result.Action)
	}
	if result.Score < 95 {
		t.Errorf("expected score >= 95, got %d", result.Score)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings for XSS payload")
	}

	for _, f := range result.Findings {
		if f.DetectorName != "xss" {
			t.Errorf("expected detector name 'xss', got %q", f.DetectorName)
		}
		if f.Category != "xss" {
			t.Errorf("expected category 'xss', got %q", f.Category)
		}
		if f.Location == "" {
			t.Error("expected non-empty location")
		}
	}
}

func TestDetector_Disabled(t *testing.T) {
	det := NewDetector(false, 1.0)

	ctx := &engine.RequestContext{
		NormalizedPath: "<script>alert(1)</script>",
		NormalizedQuery: map[string][]string{
			"q": {"<img src=x onerror=alert(1)>"},
		},
		Headers: map[string][]string{},
		Cookies: map[string]string{},
	}

	result := det.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("disabled detector should return ActionPass, got %v", result.Action)
	}
	if len(result.Findings) != 0 {
		t.Errorf("disabled detector should produce no findings, got %d", len(result.Findings))
	}
	if result.Score != 0 {
		t.Errorf("disabled detector should have score 0, got %d", result.Score)
	}
}

func TestDetector_Multiplier(t *testing.T) {
	input := "<script>alert(1)</script>"

	// Baseline at 1.0
	det1 := NewDetector(true, 1.0)
	ctx1 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{
			"q": {input},
		},
		Headers: map[string][]string{},
		Cookies: map[string]string{},
	}
	result1 := det1.Process(ctx1)

	// At 2.0
	det2 := NewDetector(true, 2.0)
	ctx2 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{
			"q": {input},
		},
		Headers: map[string][]string{},
		Cookies: map[string]string{},
	}
	result2 := det2.Process(ctx2)

	if result1.Score == 0 {
		t.Fatal("baseline score should not be 0")
	}

	expectedMin := result1.Score*2 - len(result1.Findings)
	if result2.Score < expectedMin {
		t.Errorf("2x multiplier: expected score >= %d, got %d (baseline=%d)",
			expectedMin, result2.Score, result1.Score)
	}

	// At 0.5x
	det05 := NewDetector(true, 0.5)
	ctx05 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{
			"q": {input},
		},
		Headers: map[string][]string{},
		Cookies: map[string]string{},
	}
	result05 := det05.Process(ctx05)

	if result05.Score >= result1.Score {
		t.Errorf("0.5x multiplier score %d should be less than 1.0x score %d",
			result05.Score, result1.Score)
	}
}

func TestDetector_ScanLocations(t *testing.T) {
	det := NewDetector(true, 1.0)
	payload := "<script>alert(1)</script>"

	// Body
	ctx := &engine.RequestContext{
		NormalizedBody:  payload,
		NormalizedQuery: map[string][]string{},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}
	result := det.Process(ctx)
	if result.Score < 95 {
		t.Errorf("body scan: expected score >= 95, got %d", result.Score)
	}
	hasBody := false
	for _, f := range result.Findings {
		if f.Location == "body" {
			hasBody = true
		}
	}
	if !hasBody {
		t.Error("expected findings with location 'body'")
	}

	// Cookie
	ctx2 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{},
		Headers:         map[string][]string{},
		Cookies: map[string]string{
			"session": payload,
		},
	}
	result2 := det.Process(ctx2)
	if result2.Score < 95 {
		t.Errorf("cookie scan: expected score >= 95, got %d", result2.Score)
	}

	// Referer header
	ctx3 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{},
		Headers: map[string][]string{
			"Referer": {payload},
		},
		Cookies: map[string]string{},
	}
	result3 := det.Process(ctx3)
	if result3.Score < 95 {
		t.Errorf("referer scan: expected score >= 95, got %d", result3.Score)
	}

	// User-Agent (scores halved)
	ctx4 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{},
		Headers: map[string][]string{
			"User-Agent": {payload},
		},
		Cookies: map[string]string{},
	}
	result4 := det.Process(ctx4)
	if result4.Score >= result.Score {
		t.Errorf("User-Agent scan score %d should be less than direct scan score %d (due to 0.5x)",
			result4.Score, result.Score)
	}
}

func TestDetect_CaseInsensitivity(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"lowercase", "<script>alert(1)</script>"},
		{"uppercase", "<SCRIPT>alert(1)</SCRIPT>"},
		{"mixed case", "<ScRiPt>alert(1)</ScRiPt>"},
		{"random case", "<sCrIpT>alert(1)</sCrIpT>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore < 95 {
				t.Errorf("input=%q: total score %d < 95 (case insensitive detection failed)\nfindings: %+v",
					tt.input, totalScore, findings)
			}
		})
	}
}

// --- Parser unit tests ---

func TestScanTags_Basic(t *testing.T) {
	tags := scanTags("<img src=x onerror=alert(1)>")
	if len(tags) == 0 {
		t.Fatal("expected at least one tag")
	}
	if tags[0].Name != "img" {
		t.Errorf("expected tag name 'img', got %q", tags[0].Name)
	}
	if _, ok := tags[0].Attributes["onerror"]; !ok {
		t.Error("expected 'onerror' attribute")
	}
}

func TestScanTags_QuotedAttributes(t *testing.T) {
	tags := scanTags(`<meta http-equiv="refresh" content="0;url=http://evil.com">`)
	if len(tags) == 0 {
		t.Fatal("expected at least one tag")
	}
	if tags[0].Name != "meta" {
		t.Errorf("expected tag name 'meta', got %q", tags[0].Name)
	}
	if v, ok := tags[0].Attributes["http-equiv"]; !ok || v != "refresh" {
		t.Errorf("expected http-equiv=refresh, got %q", v)
	}
}

func TestScanTags_NullBytes(t *testing.T) {
	// Null bytes between tag characters should be stripped
	input := "<scr\x00ipt>alert(1)</script>"
	cleaned := removeNullBytes(input)
	lower := strings.ToLower(cleaned)
	if !strings.Contains(lower, "<script") {
		t.Error("null byte removal should expose <script tag")
	}
}

func TestHasEventHandler(t *testing.T) {
	attrs := map[string]string{
		"src":     "x",
		"onerror": "alert(1)",
	}
	name, ok := hasEventHandler(attrs)
	if !ok {
		t.Error("expected event handler to be found")
	}
	if name != "onerror" {
		t.Errorf("expected 'onerror', got %q", name)
	}

	// No event handler
	attrs2 := map[string]string{
		"src": "image.png",
		"alt": "photo",
	}
	_, ok = hasEventHandler(attrs2)
	if ok {
		t.Error("expected no event handler")
	}
}

func TestDetectTemplateInjection(t *testing.T) {
	tests := []struct {
		input string
		count int
	}{
		{"{{constructor}}", 1},
		{"${alert(1)}", 1},
		{"#{alert(1)}", 1},
		{"{{a}} and ${b}", 2},
		{"normal text", 0},
	}

	for _, tt := range tests {
		found := detectTemplateInjection(tt.input)
		if len(found) != tt.count {
			t.Errorf("input=%q: expected %d template markers, got %d: %v",
				tt.input, tt.count, len(found), found)
		}
	}
}

func TestDetectEncodedLT(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"\\x3cscript\\x3e", true},
		{"%3cscript%3e", true},
		{"&#60;script&#62;", true},
		{"\\u003cscript", true},
		{"<script>", false},
		{"normal text", false},
	}

	for _, tt := range tests {
		got := detectEncodedLT(tt.input)
		if got != tt.expected {
			t.Errorf("input=%q: expected %v, got %v", tt.input, tt.expected, got)
		}
	}
}

func TestRemoveNullBytes(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"hel\x00lo", "hello"},
		{"\x00\x00\x00", ""},
		{"<scr\x00ipt>", "<script>"},
	}

	for _, tt := range tests {
		got := removeNullBytes(tt.input)
		if got != tt.expected {
			t.Errorf("input=%q: expected %q, got %q", tt.input, tt.expected, got)
		}
	}
}

// --- Benchmarks ---

func BenchmarkDetect(b *testing.B) {
	input := "<script>alert(1)</script>"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Detect(input, "query")
	}
}

func BenchmarkDetect_Complex(b *testing.B) {
	input := `<img src=x onerror="javascript:document.cookie">`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Detect(input, "query")
	}
}
