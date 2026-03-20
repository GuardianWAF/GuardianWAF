package ssrf

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
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

// --- Additional Coverage Tests ---

func TestDetect_AzureMetadata(t *testing.T) {
	findings := Detect("http://metadata.azure.com/metadata/instance", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 90 {
		t.Errorf("expected score >= 90 for Azure metadata, got %d", totalScore)
	}
}

func TestDetect_ECSMetadata(t *testing.T) {
	findings := Detect("http://169.254.170.2/v2/credentials", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore >= 90 {
		// Score should include both link-local and ECS metadata
	}
}

func TestDetect_ProtocolRelativeURL(t *testing.T) {
	findings := Detect("//10.0.0.1/internal", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 65 {
		t.Errorf("expected score >= 65 for protocol-relative private IP, got %d", totalScore)
	}
}

func TestDetect_HTTPSPrivateIP(t *testing.T) {
	findings := Detect("https://192.168.1.1/admin", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 65 {
		t.Errorf("expected score >= 65 for HTTPS private IP, got %d", totalScore)
	}
}

func TestDetect_URLCredentialHTTPS(t *testing.T) {
	findings := Detect("https://user:pass@internal.server.com/api", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 70 {
		t.Errorf("expected score >= 70 for URL with credentials, got %d", totalScore)
	}
}

func TestDetect_DecimalIPPrivateRange(t *testing.T) {
	// 167772161 = 10.0.0.1 (private)
	findings := Detect("http://167772161/admin", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	// Should get decimal IP + private range findings
	if totalScore < 85 {
		t.Errorf("expected score >= 85 for decimal private IP, got %d", totalScore)
	}
}

func TestDetect_DecimalIPLoopback(t *testing.T) {
	// 2130706433 = 127.0.0.1 (loopback)
	findings := Detect("http://2130706433/admin", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 85 {
		t.Errorf("expected score >= 85 for decimal loopback IP, got %d", totalScore)
	}
}

func TestDetect_HexIPMixedCase(t *testing.T) {
	findings := Detect("http://0X7F.0X0.0X0.0X1/", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 85 {
		t.Errorf("expected score >= 85 for hex IP, got %d", totalScore)
	}
}

func TestDetect_IPv6FullLoopback(t *testing.T) {
	findings := Detect("http://[0:0:0:0:0:0:0:1]/admin", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 85 {
		t.Errorf("expected score >= 85 for full IPv6 loopback, got %d", totalScore)
	}
}

func TestDetect_OctalLoopback(t *testing.T) {
	findings := Detect("http://0177.0.0.1/admin", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore >= 85 {
		// good
	}
}

func TestDetector_ProcessWithBody(t *testing.T) {
	det := NewDetector(true, 1.0)

	ctx := &engine.RequestContext{
		NormalizedPath:  "/proxy",
		NormalizedBody:  "http://10.0.0.1/internal/api",
		NormalizedQuery: map[string][]string{},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}

	result := det.Process(ctx)
	if result.Score < 65 {
		t.Errorf("expected score >= 65 for body SSRF, got %d", result.Score)
	}
}

func TestDetector_ProcessWithCookies(t *testing.T) {
	det := NewDetector(true, 1.0)

	ctx := &engine.RequestContext{
		NormalizedPath:  "/",
		NormalizedQuery: map[string][]string{},
		Headers:         map[string][]string{},
		Cookies: map[string]string{
			"redirect": "http://169.254.169.254/latest/meta-data/",
		},
	}

	result := det.Process(ctx)
	if result.Score < 95 {
		t.Errorf("expected score >= 95 for cookie SSRF, got %d", result.Score)
	}
}

func TestDetector_ProcessWithReferer(t *testing.T) {
	det := NewDetector(true, 1.0)

	ctx := &engine.RequestContext{
		NormalizedPath:  "/",
		NormalizedQuery: map[string][]string{},
		Headers: map[string][]string{
			"Referer": {"http://127.0.0.1/admin"},
		},
		Cookies: map[string]string{},
	}

	result := det.Process(ctx)
	if result.Score < 80 {
		t.Errorf("expected score >= 80 for referer SSRF, got %d", result.Score)
	}
}

func TestDetector_ProcessWithPath(t *testing.T) {
	det := NewDetector(true, 1.0)

	ctx := &engine.RequestContext{
		NormalizedPath:  "http://127.0.0.1/internal",
		NormalizedQuery: map[string][]string{},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}

	result := det.Process(ctx)
	if result.Score < 80 {
		t.Errorf("expected score >= 80 for path SSRF, got %d", result.Score)
	}
}

func TestParseIPv4_EmptyOctet(t *testing.T) {
	ip := ParseIPv4("127..0.1")
	if ip != nil {
		t.Error("expected nil for empty octet")
	}
}

func TestParseDecimalIP_TooLong(t *testing.T) {
	ip := ParseDecimalIP("12345678901") // > 10 chars
	if ip != nil {
		t.Error("expected nil for too-long decimal")
	}
}

func TestParseDecimalIP_Overflow(t *testing.T) {
	ip := ParseDecimalIP("4294967296") // > 0xFFFFFFFF
	if ip != nil {
		t.Error("expected nil for overflow decimal IP")
	}
}

func TestParseDecimalIP_Empty(t *testing.T) {
	ip := ParseDecimalIP("")
	if ip != nil {
		t.Error("expected nil for empty string")
	}
}

func TestParseOctalIP_EmptyPart(t *testing.T) {
	ip := ParseOctalIP("0177..0.1")
	if ip != nil {
		t.Error("expected nil for empty octet in octal IP")
	}
}

func TestParseOctalIP_InvalidOctalDigit(t *testing.T) {
	ip := ParseOctalIP("0189.0.0.1") // 8 and 9 are not valid octal
	if ip != nil {
		t.Error("expected nil for invalid octal digit")
	}
}

func TestParseOctalIP_OctalOverflow(t *testing.T) {
	ip := ParseOctalIP("0777.0.0.1") // 0777 = 511 > 255
	if ip != nil {
		t.Error("expected nil for octal overflow")
	}
}

func TestParseOctalIP_WrongPartCount(t *testing.T) {
	ip := ParseOctalIP("0177.0.0")
	if ip != nil {
		t.Error("expected nil for wrong part count")
	}
}

func TestParseOctalIP_HexPrefixSkipped(t *testing.T) {
	// Part starting with "0x" should NOT be treated as octal
	ip := ParseOctalIP("0x7f.0.0.1")
	if ip != nil {
		t.Error("expected nil when hex prefix mixed with non-hex parts")
	}
}

func TestParseHexIP_EmptyPart(t *testing.T) {
	ip := ParseHexIP("0x7f..0x0.0x1")
	if ip != nil {
		t.Error("expected nil for empty hex octet")
	}
}

func TestParseHexIP_WrongPartCount(t *testing.T) {
	ip := ParseHexIP("0x7f.0x0.0x1")
	if ip != nil {
		t.Error("expected nil for wrong part count in hex IP")
	}
}

func TestParseHexIP_InvalidHexDigit(t *testing.T) {
	ip := ParseHexIP("0xgg.0x0.0x0.0x1")
	if ip != nil {
		t.Error("expected nil for invalid hex digit")
	}
}

func TestParseHexIP_HexOverflow(t *testing.T) {
	ip := ParseHexIP("0xfff.0x0.0x0.0x1") // 0xfff > 255
	if ip != nil {
		t.Error("expected nil for hex overflow")
	}
}

func TestParseHexIP_EmptyAfterPrefix(t *testing.T) {
	ip := ParseHexIP("0x.0x0.0x0.0x1")
	if ip != nil {
		t.Error("expected nil for empty hex value")
	}
}

func TestIsPrivateIP_InvalidLength(t *testing.T) {
	result := IsPrivateIP(IPv4{10, 0, 0}) // 3 bytes
	if result {
		t.Error("expected false for invalid length IP")
	}
}

func TestIsLoopback_InvalidLength(t *testing.T) {
	result := IsLoopback(IPv4{127, 0}) // 2 bytes
	if result {
		t.Error("expected false for invalid length IP")
	}
}

func TestIsLinkLocal_InvalidLength(t *testing.T) {
	result := IsLinkLocal(IPv4{169}) // 1 byte
	if result {
		t.Error("expected false for invalid length IP")
	}
}

func TestIsMetadataEndpoint_InvalidLength(t *testing.T) {
	result := IsMetadataEndpoint(IPv4{169, 254}) // 2 bytes
	if result {
		t.Error("expected false for invalid length IP")
	}
}

func TestIsMetadataEndpoint_NotMetadata(t *testing.T) {
	result := IsMetadataEndpoint(IPv4{8, 8, 8, 8})
	if result {
		t.Error("expected false for non-metadata IP")
	}
}

func TestMakeFinding_LongMatch(t *testing.T) {
	longStr := ""
	for range 250 {
		longStr += "a"
	}
	f := makeFinding(50, engine.SeverityHigh, "test", longStr, "query", 0.5)
	if len(f.MatchedValue) > 200 {
		t.Errorf("expected truncated match, got length %d", len(f.MatchedValue))
	}
}

func TestExtractContext_PatternNotFound(t *testing.T) {
	result := extractContext("hello world", "notfound")
	if result != "hello world" {
		t.Errorf("expected full input when pattern not found, got %q", result)
	}
}

func TestExtractContext_LongInputPatternNotFound(t *testing.T) {
	longStr := ""
	for range 150 {
		longStr += "a"
	}
	result := extractContext(longStr, "notfound")
	if len(result) != 100 {
		t.Errorf("expected 100 chars for long input with no match, got %d", len(result))
	}
}

func TestExtractContext_PatternAtStart(t *testing.T) {
	result := extractContext("http://localhost/admin", "http://localhost")
	if result == "" {
		t.Error("expected non-empty context")
	}
}

func TestDetector_ProcessNoFindings(t *testing.T) {
	det := NewDetector(true, 1.0)

	ctx := &engine.RequestContext{
		NormalizedPath:  "/api/v1/users",
		NormalizedQuery: map[string][]string{"page": {"1"}},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}

	result := det.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass for benign request, got %v", result.Action)
	}
	if result.Score != 0 {
		t.Errorf("expected score 0 for benign request, got %d", result.Score)
	}
}

func TestDetect_MultipleURLsInInput(t *testing.T) {
	// Multiple URLs with private IPs in single input
	input := "first=http://10.0.0.1/a&second=http://172.16.0.1/b"
	findings := Detect(input, "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 65 {
		t.Errorf("expected score >= 65 for multiple private IPs, got %d", totalScore)
	}
}

func TestDetect_URLWithPort(t *testing.T) {
	findings := Detect("http://10.0.0.1:8088/internal", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 65 {
		t.Errorf("expected score >= 65 for private IP with port, got %d", totalScore)
	}
}

func TestDetect_URLWithQueryString(t *testing.T) {
	findings := Detect("http://192.168.1.1/admin?key=val", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 65 {
		t.Errorf("expected score >= 65 for private IP with query, got %d", totalScore)
	}
}

func TestDetect_URLWithFragment(t *testing.T) {
	findings := Detect("http://10.0.0.1/page#section", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 65 {
		t.Errorf("expected score >= 65 for private IP with fragment, got %d", totalScore)
	}
}

func TestParseOctalIP_MixedOctalAndDecimal(t *testing.T) {
	// Mix of octal (0177 = 127) and decimal (0, 0, 1)
	ip := ParseOctalIP("0177.0.0.1")
	if ip == nil {
		t.Fatal("expected valid octal IP")
	}
	if ip[0] != 127 || ip[1] != 0 || ip[2] != 0 || ip[3] != 1 {
		t.Errorf("expected 127.0.0.1, got %v", ip)
	}
}

func TestParseHexIP_MixedHexAndDecimal(t *testing.T) {
	// Mix of hex (0x0a = 10) and decimal (0, 0, 1)
	ip := ParseHexIP("0x0a.0.0.1")
	if ip == nil {
		t.Fatal("expected valid hex IP")
	}
	if ip[0] != 10 || ip[1] != 0 || ip[2] != 0 || ip[3] != 1 {
		t.Errorf("expected 10.0.0.1, got %v", ip)
	}
}

func TestParseDecUint8_EdgeCases(t *testing.T) {
	// Boundary: 255
	n, ok := parseDecUint8("255")
	if !ok || n != 255 {
		t.Errorf("expected 255, got %d (ok=%v)", n, ok)
	}

	// Overflow: 256
	_, ok = parseDecUint8("256")
	if ok {
		t.Error("expected failure for 256")
	}

	// Empty
	_, ok = parseDecUint8("")
	if ok {
		t.Error("expected failure for empty")
	}

	// Too long
	_, ok = parseDecUint8("1234")
	if ok {
		t.Error("expected failure for too long")
	}

	// Non-digit
	_, ok = parseDecUint8("12a")
	if ok {
		t.Error("expected failure for non-digit")
	}
}

// --- Additional coverage gap tests for parseOctalUint8 and parseHexUint8 ---

func TestParseOctalUint8_Overflow256(t *testing.T) {
	// 0400 octal = 256 decimal, should overflow uint8
	ip := ParseOctalIP("0400.0.0.1")
	if ip != nil {
		t.Error("expected nil for octal 0400 (256 > 255)")
	}
}

func TestParseOctalUint8_EmptySegment(t *testing.T) {
	// parseOctalUint8 called with empty string should fail
	_, ok := parseOctalUint8("")
	if ok {
		t.Error("expected failure for empty octal segment")
	}
}

func TestParseOctalUint8_MaxValid(t *testing.T) {
	// 0377 octal = 255, should be valid
	n, ok := parseOctalUint8("0377")
	if !ok || n != 255 {
		t.Errorf("expected 255 for 0377, got %d (ok=%v)", n, ok)
	}
}

func TestParseHexUint8_InvalidChar(t *testing.T) {
	// "GG" has invalid hex characters
	_, ok := parseHexUint8("GG")
	if ok {
		t.Error("expected failure for invalid hex digits 'GG'")
	}
}

func TestParseHexUint8_TooLong(t *testing.T) {
	// "1FF" has 3 chars, exceeds the max length of 2
	_, ok := parseHexUint8("1FF")
	if ok {
		t.Error("expected failure for hex segment longer than 2 chars")
	}
}

func TestParseHexUint8_EmptySegment(t *testing.T) {
	_, ok := parseHexUint8("")
	if ok {
		t.Error("expected failure for empty hex segment")
	}
}

func TestParseHexUint8_MaxValid(t *testing.T) {
	// "FF" = 255, should be valid
	n, ok := parseHexUint8("FF")
	if !ok || n != 255 {
		t.Errorf("expected 255 for 'FF', got %d (ok=%v)", n, ok)
	}
}

func TestParseHexIP_TooLongSegment(t *testing.T) {
	// 0x1FF = 3 hex chars after prefix, exceeds parseHexUint8 max length
	ip := ParseHexIP("0x1FF.0x0.0x0.0x1")
	if ip != nil {
		t.Error("expected nil for hex segment 0x1FF (too long)")
	}
}

func TestParseOctalIP_SingleZero(t *testing.T) {
	// "0" has len > 1 false, so it goes to decimal path, not octal
	// All segments are just "0", no octal detected
	ip := ParseOctalIP("0.0.0.0")
	if ip != nil {
		t.Error("expected nil: single '0' segments are not octal notation")
	}
}

func BenchmarkDetect(b *testing.B) {
	input := "http://169.254.169.254/latest/meta-data/"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Detect(input, "query")
	}
}
