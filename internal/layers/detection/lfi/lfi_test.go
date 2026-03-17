package lfi

import (
	"testing"

	"github.com/ersinkoc/guardianwaf/internal/engine"
)

// Attack payloads that MUST be detected with score >= 50
var attackPayloads = []struct {
	name     string
	input    string
	minScore int
}{
	{"basic etc passwd", "../../../../etc/passwd", 50},
	{"deep traversal etc shadow", "../../../../../../etc/shadow", 50},
	{"windows drive letter", "..\\..\\..\\C:\\Windows\\system32\\config\\sam", 50},
	{"encoded traversal", "..%2f..%2f..%2fetc/passwd", 50},
	{"double encoded traversal", "..%252f..%252f..%252fetc/passwd", 50},
	{"overlong utf8", "..%c0%af..%c0%afetc/passwd", 50},
	{"php filter wrapper", "php://filter/convert.base64-encode/resource=/etc/passwd", 50},
	{"php input wrapper", "php://input", 85},
	{"expect wrapper", "expect://id", 90},
	{"file scheme", "file:///etc/passwd", 50},
	{"proc self environ", "/proc/self/environ", 50},
	{"var log access", "/var/log/apache2/access.log", 50},
	{"bypass dot-dot-slash", "....//....//etc/passwd", 50},
	{"null byte injection", "../../../etc/passwd%00.jpg", 50},
	{"windows backslash traversal", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", 50},
}

// Benign inputs that must NOT trigger high scores
var benignInputs = []struct {
	name     string
	input    string
	maxScore int
}{
	{"normal image path", "/images/photo.jpg", 0},
	{"relative doc path", "docs/readme.txt", 0},
	{"css file", "/static/css/style.css", 0},
	{"api endpoint", "/api/v1/users/123", 0},
	{"normal url", "https://example.com/page", 0},
	{"simple filename", "report.pdf", 0},
	{"nested dir", "/assets/images/icons/logo.png", 0},
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

func TestDetect_SensitivePathLists(t *testing.T) {
	// Ensure our path lists are populated
	if len(linuxSensitivePaths) < 30 {
		t.Errorf("expected at least 30 Linux sensitive paths, got %d", len(linuxSensitivePaths))
	}
	if len(windowsSensitivePaths) < 20 {
		t.Errorf("expected at least 20 Windows sensitive paths, got %d", len(windowsSensitivePaths))
	}
	if len(macosSensitivePaths) < 15 {
		t.Errorf("expected at least 15 macOS sensitive paths, got %d", len(macosSensitivePaths))
	}
}

func TestDetect_FindingFields(t *testing.T) {
	findings := Detect("../../../../etc/passwd", "query")
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	for _, f := range findings {
		if f.DetectorName != "lfi" {
			t.Errorf("DetectorName: expected 'lfi', got %q", f.DetectorName)
		}
		if f.Category != "lfi" {
			t.Errorf("Category: expected 'lfi', got %q", f.Category)
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

func TestDetector_Integration(t *testing.T) {
	det := NewDetector(true, 1.0)

	// Verify interface compliance
	var _ engine.Detector = det

	if det.Name() != "lfi-detector" {
		t.Errorf("expected name 'lfi-detector', got %q", det.Name())
	}
	if det.DetectorName() != "lfi" {
		t.Errorf("expected detector name 'lfi', got %q", det.DetectorName())
	}
	if len(det.Patterns()) == 0 {
		t.Error("expected non-empty patterns list")
	}

	ctx := &engine.RequestContext{
		NormalizedPath: "/download",
		NormalizedQuery: map[string][]string{
			"file": {"../../../../etc/passwd"},
		},
		Headers: map[string][]string{},
		Cookies: map[string]string{},
	}

	result := det.Process(ctx)

	if result.Action != engine.ActionLog {
		t.Errorf("expected ActionLog, got %v", result.Action)
	}
	if result.Score < 50 {
		t.Errorf("expected score >= 50, got %d", result.Score)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings for LFI payload")
	}
}

func TestDetector_Disabled(t *testing.T) {
	det := NewDetector(false, 1.0)

	ctx := &engine.RequestContext{
		NormalizedPath: "../../../../etc/passwd",
		NormalizedQuery: map[string][]string{
			"file": {"../../../../etc/passwd"},
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
}

func TestDetector_Multiplier(t *testing.T) {
	input := "../../../../etc/passwd"

	det1 := NewDetector(true, 1.0)
	ctx1 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{"file": {input}},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}
	result1 := det1.Process(ctx1)

	det2 := NewDetector(true, 2.0)
	ctx2 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{"file": {input}},
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

func TestDetect_WrapperSchemes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minScore int
	}{
		{"php filter", "php://filter/convert.base64-encode/resource=index.php", 85},
		{"php input", "php://input", 85},
		{"expect", "expect://id", 90},
		{"file scheme", "file:///etc/hosts", 65},
		{"data scheme", "data://text/plain;base64,SSBsb3ZlIFBIUAo=", 65},
		{"phar scheme", "phar://test.phar/test.txt", 75},
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

func BenchmarkDetect(b *testing.B) {
	input := "../../../../etc/passwd"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Detect(input, "query")
	}
}
