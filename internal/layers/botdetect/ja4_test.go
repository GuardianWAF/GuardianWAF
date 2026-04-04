package botdetect

import (
	"testing"
)

func TestComputeJA4_Example(t *testing.T) {
	// Test based on the official JA4 specification example
	// JA4 = t13d1516h2_8daaf6152771_e5627efa2ab1
	//
	// Ciphers (after sorting, ignoring GREASE):
	// 002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9
	//
	// Extensions (after sorting, excluding SNI 0000 and ALPN 0010):
	// 0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01
	//
	// Signature algorithms (in original order):
	// 0403,0804,0401,0503,0805,0501,0806,0601

	params := JA4Params{
		Protocol:   "t",
		TLSVersion: 0x0303, // TLS 1.2 in ProtocolVersion, but we'll use supported_versions
		SNI:        true,
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
			0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
		},
		Extensions: []uint16{
			0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d,
			0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
		},
		ALPN:             "h2",
		SignatureAlgs:    []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
		SupportedVersion: 0x0304, // TLS 1.3
	}

	fp := ComputeJA4(params)

	// Check format: t13d1516h2_8daaf6152771_e5627efa2ab1
	expectedPrefix := "t13d1516h2_"
	if len(fp.Full) < 11 || fp.Full[:11] != expectedPrefix {
		t.Errorf("expected prefix %q, got %q", expectedPrefix, fp.Full[:min(11, len(fp.Full))])
	}

	// Full fingerprint should have format: XXXXXXXXX_XXXXXXXXXXXX_XXXXXXXXXXXX
	parts := splitJA4(fp.Full)
	if len(parts) != 3 {
		t.Errorf("expected 3 parts in JA4, got %d: %s", len(parts), fp.Full)
	}

	// Check part A
	expectedA := "t13d1516h2"
	if parts[0] != expectedA {
		t.Errorf("expected part A %q, got %q", expectedA, parts[0])
	}

	// Check part B (cipher hash)
	expectedB := "8daaf6152771"
	if parts[1] != expectedB {
		t.Errorf("expected part B %q, got %q", expectedB, parts[1])
	}

	// Check part C (extension hash with sig algs)
	expectedC := "e5627efa2ab1"
	if parts[2] != expectedC {
		t.Errorf("expected part C %q, got %q", expectedC, parts[2])
	}

	// Verify full fingerprint
	expected := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if fp.Full != expected {
		t.Errorf("expected full %q, got %q", expected, fp.Full)
	}
}

func TestComputeJA4_WithGREASE(t *testing.T) {
	// Test that GREASE values are properly ignored
	params := JA4Params{
		Protocol:         "t",
		TLSVersion:       0x0303,
		SNI:              true,
		CipherSuites:     []uint16{0x0a0a, 0x1301, 0x1302, 0x2a2a}, // GREASE mixed in
		Extensions:       []uint16{0x001b, 0x1a1a, 0x0000},         // GREASE mixed in
		ALPN:             "h2",
		SupportedVersion: 0x0304,
	}

	fp := ComputeJA4(params)

	// Should have 2 ciphers (GREASE ignored)
	// Should have 1 extension (GREASE ignored, SNI excluded from count for part C but included in count for part A)
	parts := splitJA4(fp.Full)
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	// Part A should show 02 ciphers, 02 extensions
	if parts[0] != "t13d0202h2" {
		t.Errorf("expected part A 't13d0202h2', got %q", parts[0])
	}
}

func TestComputeJA4_NoSNI(t *testing.T) {
	params := JA4Params{
		Protocol:         "t",
		TLSVersion:       0x0304,
		SNI:              false, // No SNI = going to IP
		CipherSuites:     []uint16{0x1301},
		Extensions:       []uint16{0x001b},
		ALPN:             "h2",
		SupportedVersion: 0x0304,
	}

	fp := ComputeJA4(params)

	// Should start with t13i (no SNI = i)
	if fp.Full[:4] != "t13i" {
		t.Errorf("expected prefix 't13i', got %q", fp.Full[:4])
	}
}

func TestComputeJA4_NoALPN(t *testing.T) {
	params := JA4Params{
		Protocol:         "t",
		TLSVersion:       0x0304,
		SNI:              true,
		CipherSuites:     []uint16{0x1301},
		Extensions:       []uint16{0x001b},
		ALPN:             "", // No ALPN
		SupportedVersion: 0x0304,
	}

	fp := ComputeJA4(params)

	// ALPN code is at positions 8-10 in "t13d010100_..."
	// Format: t + 13 + d + 01 + 01 + 00 = t13d010100
	if fp.Full[8:10] != "00" {
		t.Errorf("expected ALPN code '00', got %q", fp.Full[8:10])
	}
}

func TestComputeJA4_QUIC(t *testing.T) {
	params := JA4Params{
		Protocol:         "q", // QUIC
		TLSVersion:       0x0304,
		SNI:              true,
		CipherSuites:     []uint16{0x1301},
		Extensions:       []uint16{0x001b},
		ALPN:             "h3",
		SupportedVersion: 0x0304,
	}

	fp := ComputeJA4(params)

	// Should start with q13
	if fp.Full[:3] != "q13" {
		t.Errorf("expected prefix 'q13', got %q", fp.Full[:3])
	}
}

func TestComputeJA4_DTLS(t *testing.T) {
	params := JA4Params{
		Protocol:         "d", // DTLS
		TLSVersion:       0xfefd,
		SNI:              true,
		CipherSuites:     []uint16{0x1301},
		Extensions:       []uint16{0x001b},
		ALPN:             "",
		SupportedVersion: 0xfefd,
	}

	fp := ComputeJA4(params)

	// Should start with dd2 (DTLS, DTLS 1.2)
	if fp.Full[:3] != "dd2" {
		t.Errorf("expected prefix 'dd2', got %q", fp.Full[:3])
	}
}

func TestComputeJA4_TLS12(t *testing.T) {
	params := JA4Params{
		Protocol:         "t",
		TLSVersion:       0x0303, // TLS 1.2
		SNI:              true,
		CipherSuites:     []uint16{0x002f},
		Extensions:       []uint16{0x001b},
		ALPN:             "h2",
		SupportedVersion: 0, // No supported_versions extension
	}

	fp := ComputeJA4(params)

	// Should show TLS 1.2 = 12
	if fp.Full[:4] != "t12d" {
		t.Errorf("expected prefix 't12d', got %q", fp.Full[:4])
	}
}

func TestComputeJA4_EmptyLists(t *testing.T) {
	params := JA4Params{
		Protocol:         "t",
		TLSVersion:       0x0304,
		SNI:              false,
		CipherSuites:     []uint16{},
		Extensions:       []uint16{},
		ALPN:             "",
		SupportedVersion: 0x0304,
	}

	fp := ComputeJA4(params)

	parts := splitJA4(fp.Full)
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	// Empty cipher list should hash to 000000000000
	if parts[1] != "000000000000" {
		t.Errorf("expected empty cipher hash '000000000000', got %q", parts[1])
	}

	// Empty extension list should hash to 000000000000
	if parts[2] != "000000000000" {
		t.Errorf("expected empty extension hash '000000000000', got %q", parts[2])
	}
}

func TestComputeJA4_SingleCharALPN(t *testing.T) {
	params := JA4Params{
		Protocol:         "t",
		TLSVersion:       0x0304,
		SNI:              true,
		CipherSuites:     []uint16{0x1301},
		Extensions:       []uint16{0x001b},
		ALPN:             "a", // Single char
		SupportedVersion: 0x0304,
	}

	fp := ComputeJA4(params)

	// Single char ALPN should repeat: "aa"
	// ALPN code is at positions 8-10: "t13d0101aa_..."
	if fp.Full[8:10] != "aa" {
		t.Errorf("expected ALPN code 'aa', got %q in %s", fp.Full[8:10], fp.Full)
	}
}

func TestComputeJA4_NonAlphaNumALPN(t *testing.T) {
	params := JA4Params{
		Protocol:         "t",
		TLSVersion:       0x0304,
		SNI:              true,
		CipherSuites:     []uint16{0x1301},
		Extensions:       []uint16{0x001b},
		ALPN:             "\xab", // Non-alphanumeric
		SupportedVersion: 0x0304,
	}

	fp := ComputeJA4(params)

	// Hex of \xab is "ab", first and last char = "ab"
	// ALPN code is at positions 8-10: "t13d0101ab_..."
	if fp.Full[8:10] != "ab" {
		t.Errorf("expected ALPN code 'ab', got %q in %s", fp.Full[8:10], fp.Full)
	}
}

func TestComputeJA4_ManyCiphers(t *testing.T) {
	// Test that >99 ciphers are capped at 99
	ciphers := make([]uint16, 105)
	for i := range 105 {
		ciphers[i] = uint16(0x1300 + i)
	}

	params := JA4Params{
		Protocol:         "t",
		TLSVersion:       0x0304,
		SNI:              true,
		CipherSuites:     ciphers,
		Extensions:       []uint16{0x001b},
		ALPN:             "h2",
		SupportedVersion: 0x0304,
	}

	fp := ComputeJA4(params)

	// Should cap at 99 ciphers
	parts := splitJA4(fp.Full)
	if len(parts[0]) < 8 {
		t.Fatalf("part A too short: %s", parts[0])
	}
	// cipher count should be "99"
	if parts[0][4:6] != "99" {
		t.Errorf("expected cipher count '99', got %q in %s", parts[0][4:6], parts[0])
	}
}

func TestIsGREASE(t *testing.T) {
	tests := []struct {
		val      uint16
		expected bool
	}{
		{0x0a0a, true},
		{0x1a1a, true},
		{0x2a2a, true},
		{0xfafa, true},
		{0x1301, false},
		{0xc02b, false},
		{0x0000, false},
	}

	for _, tt := range tests {
		result := isGREASE(tt.val)
		if result != tt.expected {
			t.Errorf("isGREASE(0x%04x) = %v, expected %v", tt.val, result, tt.expected)
		}
	}
}

func TestTLSVersionCode(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{0x0304, "13"},
		{0x0303, "12"},
		{0x0302, "11"},
		{0x0301, "10"},
		{0x0300, "s3"},
		{0x0002, "s2"},
		{0xfeff, "d1"},
		{0xfefd, "d2"},
		{0xfefc, "d3"},
		{0x9999, "00"},
	}

	for _, tt := range tests {
		result := tlsVersionCode(tt.version)
		if result != tt.expected {
			t.Errorf("tlsVersionCode(0x%04x) = %q, expected %q", tt.version, result, tt.expected)
		}
	}
}

func TestALPNCode(t *testing.T) {
	tests := []struct {
		alpn     string
		expected string
	}{
		{"h2", "h2"},
		{"http/1.1", "h1"},
		{"", "00"},
		{"a", "aa"},
		{"ab", "ab"},
		{"abc", "ac"},
		{"\xab", "ab"}, // Non-alpha -> hex
		{"\x20\x61", "21"},
	}

	for _, tt := range tests {
		result := alpnCode(tt.alpn)
		if result != tt.expected {
			t.Errorf("alpnCode(%q) = %q, expected %q", tt.alpn, result, tt.expected)
		}
	}
}

// Helper function to split JA4 fingerprint into parts
func splitJA4(fp string) []string {
	parts := make([]string, 0, 3)
	start := 0
	for i := range fp {
		if fp[i] == '_' {
			parts = append(parts, fp[start:i])
			start = i + 1
		}
	}
	if start < len(fp) {
		parts = append(parts, fp[start:])
	}
	return parts
}

// Benchmarks

func BenchmarkComputeJA4(b *testing.B) {
	params := JA4Params{
		Protocol:         "t",
		TLSVersion:       0x0303,
		SNI:              true,
		CipherSuites:     []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		Extensions:       []uint16{0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015},
		ALPN:             "h2",
		SignatureAlgs:    []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
		SupportedVersion: 0x0304,
	}

	b.ResetTimer()
	for range b.N {
		ComputeJA4(params)
	}
}

func BenchmarkComputeJA4_Minimal(b *testing.B) {
	params := JA4Params{
		Protocol:         "t",
		TLSVersion:       0x0304,
		SNI:              false,
		CipherSuites:     []uint16{0x1301},
		Extensions:       []uint16{0x001b},
		ALPN:             "",
		SupportedVersion: 0x0304,
	}

	b.ResetTimer()
	for range b.N {
		ComputeJA4(params)
	}
}

func BenchmarkComputeJA4_Large(b *testing.B) {
	// Simulate a client with many cipher suites and extensions
	ciphers := make([]uint16, 50)
	for i := range 50 {
		ciphers[i] = uint16(0x1300 + i)
	}
	exts := make([]uint16, 30)
	for i := range 30 {
		exts[i] = uint16(0x0001 + i)
	}
	sigAlgs := make([]uint16, 20)
	for i := range 20 {
		sigAlgs[i] = uint16(0x0400 + i)
	}

	params := JA4Params{
		Protocol:         "t",
		TLSVersion:       0x0304,
		SNI:              true,
		CipherSuites:     ciphers,
		Extensions:       exts,
		ALPN:             "h2",
		SignatureAlgs:    sigAlgs,
		SupportedVersion: 0x0304,
	}

	b.ResetTimer()
	for range b.N {
		ComputeJA4(params)
	}
}

func BenchmarkComputeJA4_WithGREASE(b *testing.B) {
	params := JA4Params{
		Protocol:         "t",
		TLSVersion:       0x0303,
		SNI:              true,
		CipherSuites:     []uint16{0x0a0a, 0x1301, 0x1302, 0x2a2a, 0x1303, 0x3a3a, 0xc02b, 0x4a4a},
		Extensions:       []uint16{0x5a5a, 0x001b, 0x6a6a, 0x0000, 0x7a7a, 0x0010},
		ALPN:             "h2",
		SignatureAlgs:    []uint16{0x8a8a, 0x0403, 0x9a9a, 0x0804},
		SupportedVersion: 0x0304,
	}

	b.ResetTimer()
	for range b.N {
		ComputeJA4(params)
	}
}

func BenchmarkLookupJA4Fingerprint(b *testing.B) {
	fp := "t13d1516h2_8daaf6152771_e5627efa2ab1"

	b.ResetTimer()
	for range b.N {
		LookupJA4Fingerprint(fp)
	}
}

func BenchmarkLookupJA4Fingerprint_Unknown(b *testing.B) {
	fp := "t13d010100_000000000000_000000000000"

	b.ResetTimer()
	for range b.N {
		LookupJA4Fingerprint(fp)
	}
}
