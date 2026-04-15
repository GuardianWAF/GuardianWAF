package botdetect

import (
	"testing"
)

func FuzzJA3Fingerprint(f *testing.F) {
	// Valid TLS versions
	f.Add(uint16(0x0303), "0x0001-0x0002-0x0003", "0x0000-0x0001", "0x0001-0x0002", "0x00")
	f.Add(uint16(0x0304), "0x0001", "0x0000", "0x0001", "0x00")
	f.Add(uint16(0x0300), "", "", "", "")
	f.Add(uint16(0x0301), "0x0001-0x0002-0x0003-0x0004-0x0005-0x0006", "0x0000-0x0001-0x0002-0x0003", "0x0001-0x0002-0x0003", "0x00")
	f.Add(uint16(0xfeff), "0x0a0a", "0x0000", "0x0001", "0x00")

	f.Fuzz(func(t *testing.T, tlsVersion uint16, cipherStr, extStr, curveStr, pointStr string) {
		ciphers := parseUint16List(cipherStr)
		extensions := parseUint16List(extStr)
		curves := parseUint16List(curveStr)
		points := parseUint8List(pointStr)

		// ComputeJA3 should not panic
		fp := ComputeJA3(tlsVersion, ciphers, extensions, curves, points)

		// Hash should be 32 hex chars (MD5)
		if len(fp.Hash) != 32 {
			t.Errorf("expected 32-char hash, got %d", len(fp.Hash))
		}

		// Raw should contain the TLS version
		if fp.Raw != "" && len(fp.Raw) < 5 {
			t.Errorf("raw fingerprint too short: %s", fp.Raw)
		}
	})
}

func FuzzJA4Fingerprint(f *testing.F) {
	f.Add("t", uint16(0x0304), true, "0x0001-0x0002-0x0003", "0x0000-0x0001-0x0002", "h2", "0x0001-0x0002", uint16(0x0304))
	f.Add("q", uint16(0x0303), false, "", "", "", "", uint16(0))
	f.Add("d", uint16(0x0300), true, "0x0a0a-0x0001", "0x0000", "http/1.1", "0x0001", uint16(0))
	f.Add("t", uint16(0x0304), false, "0x0001-0x0002-0x0003-0x0004-0x0005", "0x0000-0x0001-0x0002-0x0003-0x0004", "grpc", "0x0001-0x0002-0x0003", uint16(0x0303))
	f.Add("t", uint16(0x0301), true, "0x0001", "0x0000", "", "", uint16(0))
	f.Add("", uint16(0x0304), true, "0x0001-0x0002", "0x0000-0x0001", "aaa", "0x0001", uint16(0x0304))

	f.Fuzz(func(t *testing.T, protocol string, tlsVersion uint16, sni bool, cipherStr, extStr, alpn string, sigAlgStr string, supportedVersion uint16) {
		ciphers := parseUint16List(cipherStr)
		extensions := parseUint16List(extStr)
		sigAlgs := parseUint16List(sigAlgStr)

		params := JA4Params{
			Protocol:         protocol,
			TLSVersion:       tlsVersion,
			SNI:              sni,
			CipherSuites:     ciphers,
			Extensions:       extensions,
			ALPN:             alpn,
			SignatureAlgs:    sigAlgs,
			SupportedVersion: supportedVersion,
		}

		// ComputeJA4 should not panic
		fp := ComputeJA4(params)

		// Full fingerprint should be non-empty
		if fp.Full == "" {
			t.Error("full fingerprint is empty")
		}

		// Full fingerprint should match expected format (3 parts separated by _)
		parts := splitN(fp.Full, '_', 3)
		if len(parts) != 3 {
			t.Errorf("expected 3 parts in fingerprint, got %d: %s", len(parts), fp.Full)
		}
	})
}

func FuzzGREASEFilter(f *testing.F) {
	f.Add("0x0a0a-0x0001-0x1a1a-0x0002-0x2a2a")
	f.Add("0x0001-0x0002-0x0003")
	f.Add("0x0a0a-0x0a0a-0x0a0a-0x0a0a")
	f.Add("")
	f.Add("0xfafa-0x0001-0xbaba-0x0002")
	f.Add("0x0001")

	f.Fuzz(func(t *testing.T, cipherStr string) {
		ciphers := parseUint16List(cipherStr)
		filtered := filterGREASE(ciphers)

		// No GREASE values should remain
		for _, v := range filtered {
			if isGREASE(v) {
				t.Errorf("GREASE value 0x%04x found in filtered result", v)
			}
		}

		// Filtered should be <= original length
		if len(filtered) > len(ciphers) {
			t.Errorf("filtered length %d > original length %d", len(filtered), len(ciphers))
		}
	})
}

func FuzzTLSVersionCode(f *testing.F) {
	f.Add(uint16(0x0304))
	f.Add(uint16(0x0303))
	f.Add(uint16(0x0302))
	f.Add(uint16(0x0301))
	f.Add(uint16(0x0300))
	f.Add(uint16(0x0002))
	f.Add(uint16(0xfeff))
	f.Add(uint16(0xfefd))
	f.Add(uint16(0xfefc))
	f.Add(uint16(0x1234))
	f.Add(uint16(0))
	f.Add(uint16(0xffff))

	f.Fuzz(func(t *testing.T, v uint16) {
		code := tlsVersionCode(v)
		// Code should be 2 characters
		if len(code) != 2 {
			t.Errorf("expected 2-char code, got %d: %s", len(code), code)
		}
	})
}

func FuzzALPNCode(f *testing.F) {
	f.Add("h2")
	f.Add("http/1.1")
	f.Add("")
	f.Add("grpc")
	f.Add("a")
	f.Add("ab")
	f.Add("abc")
	f.Add("123")
	f.Add("a1b2")
	f.Add("\x00\x01")
	f.Add("ü") // non-ASCII

	f.Fuzz(func(t *testing.T, alpn string) {
		code := alpnCode(alpn)
		// Code should be 2 characters
		if len(code) != 2 {
			t.Errorf("expected 2-char code, got %d: %s", len(code), code)
		}
	})
}

// parseUint16List parses a string like "0x0001-0x0002-0x0003" into []uint16
func parseUint16List(s string) []uint16 {
	if s == "" {
		return nil
	}
	var result []uint16
	for _, part := range splitStr(s, "-") {
		part = trimSpace(part)
		if len(part) > 2 && part[0] == '0' && (part[1] == 'x' || part[1] == 'X') {
			var v uint16
			for j := 2; j < len(part); j++ {
				c := part[j]
				var nibble uint16
				switch {
				case c >= '0' && c <= '9':
					nibble = uint16(c - '0')
				case c >= 'a' && c <= 'f':
					nibble = uint16(c - 'a' + 10)
				case c >= 'A' && c <= 'F':
					nibble = uint16(c - 'A' + 10)
				default:
					return result
				}
				v = v<<4 | nibble
			}
			result = append(result, v)
		}
	}
	return result
}

// parseUint8List parses a string like "0x00-0x01-0x02" into []uint8
func parseUint8List(s string) []uint8 {
	if s == "" {
		return nil
	}
	var result []uint8
	for _, part := range splitStr(s, "-") {
		part = trimSpace(part)
		if len(part) > 2 && part[0] == '0' && (part[1] == 'x' || part[1] == 'X') {
			var v uint8
			for j := 2; j < len(part) && j < 4; j++ {
				c := part[j]
				var nibble uint8
				switch {
				case c >= '0' && c <= '9':
					nibble = c - '0'
				case c >= 'a' && c <= 'f':
					nibble = c - 'a' + 10
				case c >= 'A' && c <= 'F':
					nibble = c - 'A' + 10
				default:
					break
				}
				v = v<<4 | nibble
			}
			result = append(result, v)
		}
	}
	return result
}

func splitStr(s, sep string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

func splitN(s string, sep rune, n int) []string {
	var result []string
	for i := 0; i < n-1; i++ {
		idx := -1
		for j := 0; j < len(s); j++ {
			if s[j] == byte(sep) {
				idx = j
				break
			}
		}
		if idx == -1 {
			break
		}
		result = append(result, s[:idx])
		s = s[idx+1:]
	}
	result = append(result, s)
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}