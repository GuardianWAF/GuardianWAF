package ssrf

import (
	"testing"

	"github.com/ersinkoc/guardianwaf/internal/engine"
)

// Attack payloads that MUST be detected
var attackPayloads = []struct {
	name     string
	input    string
	minScore int
}{
	{"localhost http", "http://localhost/admin", 80},
	{"127.0.0.1", "http://127.0.0.1/secret", 80},
	{"0.0.0.0", "http://0.0.0.0/", 85},
	{"ipv6 loopback", "http://[::1]/admin", 85},
	{"aws metadata", "http://169.254.169.254/latest/meta-data/", 95},
	{"gcp metadata", "http://metadata.google.internal/computeMetadata/v1/", 95},
	{"alibaba metadata", "http://100.100.100.200/latest/meta-data/", 90},
	{"private 10.x", "http://10.0.0.1/internal", 65},
	{"private 172.16.x", "http://172.16.0.1/admin", 65},
	{"private 192.168.x", "http://192.168.1.1/router", 65},
	{"decimal ip", "http://2130706433/", 85},
	{"octal ip", "http://0177.0.0.1/", 85},
	{"hex ip", "http://0x7f.0x0.0x0.0x1/", 85},
	{"url with at", "http://attacker.com@127.0.0.1/", 70},
	{"https localhost", "https://localhost:8443/api", 80},
}

// Benign inputs that must NOT trigger
var benignInputs = []struct {
	name     string
	input    string
	maxScore int
}{
	{"public url", "https://example.com/api/data", 0},
	{"google", "https://www.google.com/search?q=test", 0},
	{"plain text", "hello world", 0},
	{"normal path", "/api/v1/users", 0},
	{"email", "user@example.com", 0},
	{"number", "12345", 0},
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

func TestDetect_FindingFields(t *testing.T) {
	findings := Detect("http://127.0.0.1/admin", "query")
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	for _, f := range findings {
		if f.DetectorName != "ssrf" {
			t.Errorf("DetectorName: expected 'ssrf', got %q", f.DetectorName)
		}
		if f.Category != "ssrf" {
			t.Errorf("Category: expected 'ssrf', got %q", f.Category)
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
	}
}

func TestDetector_Integration(t *testing.T) {
	det := NewDetector(true, 1.0)

	var _ engine.Detector = det

	if det.Name() != "ssrf-detector" {
		t.Errorf("expected name 'ssrf-detector', got %q", det.Name())
	}
	if det.DetectorName() != "ssrf" {
		t.Errorf("expected detector name 'ssrf', got %q", det.DetectorName())
	}
	if len(det.Patterns()) == 0 {
		t.Error("expected non-empty patterns list")
	}

	ctx := &engine.RequestContext{
		NormalizedPath: "/proxy",
		NormalizedQuery: map[string][]string{
			"url": {"http://169.254.169.254/latest/meta-data/"},
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
		t.Error("expected findings for SSRF payload")
	}
}

func TestDetector_Disabled(t *testing.T) {
	det := NewDetector(false, 1.0)

	ctx := &engine.RequestContext{
		NormalizedPath: "http://127.0.0.1",
		NormalizedQuery: map[string][]string{
			"url": {"http://localhost/admin"},
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
	input := "http://127.0.0.1/admin"

	det1 := NewDetector(true, 1.0)
	ctx1 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{"url": {input}},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}
	result1 := det1.Process(ctx1)

	det2 := NewDetector(true, 2.0)
	ctx2 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{"url": {input}},
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

// --- IP Check Tests ---

func TestParseIPv4(t *testing.T) {
	tests := []struct {
		input string
		want  IPv4
	}{
		{"127.0.0.1", IPv4{127, 0, 0, 1}},
		{"10.0.0.1", IPv4{10, 0, 0, 1}},
		{"192.168.1.1", IPv4{192, 168, 1, 1}},
		{"255.255.255.255", IPv4{255, 255, 255, 255}},
		{"0.0.0.0", IPv4{0, 0, 0, 0}},
	}

	for _, tt := range tests {
		ip := ParseIPv4(tt.input)
		if ip == nil {
			t.Errorf("ParseIPv4(%q) returned nil", tt.input)
			continue
		}
		if ip[0] != tt.want[0] || ip[1] != tt.want[1] || ip[2] != tt.want[2] || ip[3] != tt.want[3] {
			t.Errorf("ParseIPv4(%q) = %v, want %v", tt.input, ip, tt.want)
		}
	}

	// Invalid inputs
	invalids := []string{"", "abc", "127.0.0", "127.0.0.1.2", "256.0.0.1", "127.0.0.abc"}
	for _, s := range invalids {
		ip := ParseIPv4(s)
		if ip != nil {
			t.Errorf("ParseIPv4(%q) should return nil, got %v", s, ip)
		}
	}
}

func TestParseDecimalIP(t *testing.T) {
	// 2130706433 = 127.0.0.1
	ip := ParseDecimalIP("2130706433")
	if ip == nil {
		t.Fatal("ParseDecimalIP(2130706433) returned nil")
	}
	if ip[0] != 127 || ip[1] != 0 || ip[2] != 0 || ip[3] != 1 {
		t.Errorf("expected 127.0.0.1, got %v", ip)
	}

	// 167772161 = 10.0.0.1
	ip2 := ParseDecimalIP("167772161")
	if ip2 == nil {
		t.Fatal("ParseDecimalIP(167772161) returned nil")
	}
	if ip2[0] != 10 || ip2[1] != 0 || ip2[2] != 0 || ip2[3] != 1 {
		t.Errorf("expected 10.0.0.1, got %v", ip2)
	}

	// Small numbers should not parse
	if ParseDecimalIP("100") != nil {
		t.Error("small number should not parse as decimal IP")
	}
	if ParseDecimalIP("abc") != nil {
		t.Error("non-numeric should not parse")
	}
}

func TestParseOctalIP(t *testing.T) {
	// 0177.0.0.1 = 127.0.0.1
	ip := ParseOctalIP("0177.0.0.1")
	if ip == nil {
		t.Fatal("ParseOctalIP(0177.0.0.1) returned nil")
	}
	if ip[0] != 127 || ip[1] != 0 || ip[2] != 0 || ip[3] != 1 {
		t.Errorf("expected 127.0.0.1, got %v", ip)
	}

	// Regular IP should return nil (no octal)
	if ParseOctalIP("127.0.0.1") != nil {
		t.Error("regular IP should not parse as octal")
	}
}

func TestParseHexIP(t *testing.T) {
	// 0x7f.0x0.0x0.0x1 = 127.0.0.1
	ip := ParseHexIP("0x7f.0x0.0x0.0x1")
	if ip == nil {
		t.Fatal("ParseHexIP(0x7f.0x0.0x0.0x1) returned nil")
	}
	if ip[0] != 127 || ip[1] != 0 || ip[2] != 0 || ip[3] != 1 {
		t.Errorf("expected 127.0.0.1, got %v", ip)
	}

	// Regular IP should return nil (no hex)
	if ParseHexIP("127.0.0.1") != nil {
		t.Error("regular IP should not parse as hex")
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   IPv4
		want bool
	}{
		{IPv4{10, 0, 0, 1}, true},
		{IPv4{10, 255, 255, 255}, true},
		{IPv4{172, 16, 0, 1}, true},
		{IPv4{172, 31, 255, 255}, true},
		{IPv4{172, 15, 0, 1}, false},
		{IPv4{172, 32, 0, 1}, false},
		{IPv4{192, 168, 0, 1}, true},
		{IPv4{192, 168, 255, 255}, true},
		{IPv4{8, 8, 8, 8}, false},
		{IPv4{1, 1, 1, 1}, false},
	}

	for _, tt := range tests {
		got := IsPrivateIP(tt.ip[:])
		if got != tt.want {
			t.Errorf("IsPrivateIP(%v) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	if !IsLoopback(IPv4{127, 0, 0, 1}) {
		t.Error("127.0.0.1 should be loopback")
	}
	if !IsLoopback(IPv4{127, 255, 255, 255}) {
		t.Error("127.255.255.255 should be loopback")
	}
	if IsLoopback(IPv4{128, 0, 0, 1}) {
		t.Error("128.0.0.1 should not be loopback")
	}
}

func TestIsLinkLocal(t *testing.T) {
	if !IsLinkLocal(IPv4{169, 254, 0, 1}) {
		t.Error("169.254.0.1 should be link-local")
	}
	if !IsLinkLocal(IPv4{169, 254, 169, 254}) {
		t.Error("169.254.169.254 should be link-local")
	}
	if IsLinkLocal(IPv4{169, 253, 0, 1}) {
		t.Error("169.253.0.1 should not be link-local")
	}
}

func TestIsMetadataEndpoint(t *testing.T) {
	if !IsMetadataEndpoint(IPv4{169, 254, 169, 254}) {
		t.Error("169.254.169.254 should be metadata endpoint")
	}
	if !IsMetadataEndpoint(IPv4{100, 100, 100, 200}) {
		t.Error("100.100.100.200 should be metadata endpoint")
	}
	if IsMetadataEndpoint(IPv4{169, 254, 0, 1}) {
		t.Error("169.254.0.1 should not be metadata endpoint")
	}
}

func BenchmarkDetect(b *testing.B) {
	input := "http://169.254.169.254/latest/meta-data/"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Detect(input, "query")
	}
}
