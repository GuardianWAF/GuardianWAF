package ssrf

import (
	"strings"
	"testing"
)

func TestExtractContext_LongResultTruncated(t *testing.T) {
	prefix := strings.Repeat("a", 50)
	pattern := strings.Repeat("b", 200)
	suffix := strings.Repeat("c", 50)
	input := prefix + pattern + suffix

	ctx := extractContext(input, pattern)
	if len(ctx) != 200 {
		t.Errorf("expected context length 200, got %d", len(ctx))
	}
	if !strings.HasSuffix(ctx, "...") {
		t.Error("expected truncated context to end with ...")
	}
}

// --- Abbreviated IP tests ---

func TestDetect_AbbreviatedIP_Loopback(t *testing.T) {
	findings := Detect("http://127.1/admin", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 80 {
		t.Errorf("expected score >= 80 for abbreviated loopback 127.1, got %d", totalScore)
	}
}

func TestDetect_AbbreviatedIP_Private(t *testing.T) {
	findings := Detect("http://10.1/secret", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 80 {
		t.Errorf("expected score >= 80 for abbreviated private IP 10.1, got %d", totalScore)
	}
}

func TestDetect_AbbreviatedIP_Private192(t *testing.T) {
	// 192.168.1 → 192.168.0.1
	findings := Detect("http://192.168.1/router", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 80 {
		t.Errorf("expected score >= 80 for abbreviated private 192.168.1, got %d", totalScore)
	}
}

// --- Hex single number IP tests ---

func TestDetect_HexSingleIP_Loopback(t *testing.T) {
	findings := Detect("http://0x7f000001/admin", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 85 {
		t.Errorf("expected score >= 85 for hex single loopback 0x7f000001, got %d", totalScore)
	}
}

func TestDetect_HexSingleIP_Private(t *testing.T) {
	// 0x0a000001 = 10.0.0.1
	findings := Detect("http://0x0a000001/internal", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 85 {
		t.Errorf("expected score >= 85 for hex single private IP 0x0a000001, got %d", totalScore)
	}
}

// --- ParseAbbreviatedIP tests ---

func TestParseAbbreviatedIP_TwoParts(t *testing.T) {
	ip := ParseAbbreviatedIP("127.1")
	if ip == nil {
		t.Fatal("expected valid abbreviated IP")
	}
	if ip[0] != 127 || ip[1] != 0 || ip[2] != 0 || ip[3] != 1 {
		t.Errorf("expected 127.0.0.1, got %d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	}
}

func TestParseAbbreviatedIP_ThreeParts(t *testing.T) {
	ip := ParseAbbreviatedIP("192.168.1")
	if ip == nil {
		t.Fatal("expected valid abbreviated IP")
	}
	if ip[0] != 192 || ip[1] != 168 || ip[2] != 0 || ip[3] != 1 {
		t.Errorf("expected 192.168.0.1, got %d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	}
}

func TestParseAbbreviatedIP_FourParts(t *testing.T) {
	// Standard 4-part should return nil (handled by ParseIPv4)
	ip := ParseAbbreviatedIP("127.0.0.1")
	if ip != nil {
		t.Error("4-part IP should not be abbreviated")
	}
}

func TestParseAbbreviatedIP_EmptyPart(t *testing.T) {
	ip := ParseAbbreviatedIP("127.")
	if ip != nil {
		t.Error("expected nil for trailing dot")
	}
}

func TestParseAbbreviatedIP_InvalidChar(t *testing.T) {
	ip := ParseAbbreviatedIP("127.abc")
	if ip != nil {
		t.Error("expected nil for invalid chars")
	}
}

// --- ParseHexSingleIP tests ---

func TestParseHexSingleIP_Loopback(t *testing.T) {
	ip := ParseHexSingleIP("0x7f000001")
	if ip == nil {
		t.Fatal("expected valid hex single IP")
	}
	if ip[0] != 127 || ip[1] != 0 || ip[2] != 0 || ip[3] != 1 {
		t.Errorf("expected 127.0.0.1, got %d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	}
}

func TestParseHexSingleIP_Private(t *testing.T) {
	// 0x0a000001 = 10.0.0.1
	ip := ParseHexSingleIP("0x0a000001")
	if ip == nil {
		t.Fatal("expected valid hex single IP")
	}
	if ip[0] != 10 || ip[1] != 0 || ip[2] != 0 || ip[3] != 1 {
		t.Errorf("expected 10.0.0.1, got %d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	}
}

func TestParseHexSingleIP_NoPrefix(t *testing.T) {
	ip := ParseHexSingleIP("7f000001")
	if ip != nil {
		t.Error("expected nil without 0x prefix")
	}
}

func TestParseHexSingleIP_TooLong(t *testing.T) {
	ip := ParseHexSingleIP("0x7f00000100")
	if ip != nil {
		t.Error("expected nil for too-long hex")
	}
}

func TestParseHexSingleIP_Empty(t *testing.T) {
	ip := ParseHexSingleIP("0x")
	if ip != nil {
		t.Error("expected nil for empty hex value")
	}
}

func TestParseHexSingleIP_Uppercase(t *testing.T) {
	ip := ParseHexSingleIP("0X7F000001")
	if ip == nil {
		t.Fatal("expected valid hex single IP")
	}
	if ip[0] != 127 || ip[3] != 1 {
		t.Errorf("expected 127.0.0.1, got %d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	}
}

func TestParseHexSingleIP_Metadata(t *testing.T) {
	// 0xa9fea9fe = 169.254.169.254
	ip := ParseHexSingleIP("0xa9fea9fe")
	if ip == nil {
		t.Fatal("expected valid hex single IP")
	}
	if !IsMetadataEndpoint(ip) {
		t.Errorf("expected metadata endpoint, got %d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	}
}
