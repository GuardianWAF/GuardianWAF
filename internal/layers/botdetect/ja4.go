package botdetect

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// JA4Fingerprint represents a computed JA4 fingerprint.
type JA4Fingerprint struct {
	Full string // Complete JA4 fingerprint
	Raw  string // Raw fingerprint for debugging
}

// JA4Params contains the parameters needed to compute a JA4 fingerprint.
type JA4Params struct {
	Protocol         string   // "t" (TLS), "q" (QUIC), "d" (DTLS)
	TLSVersion       uint16   // TLS version from supported_versions extension or ProtocolVersion
	SNI              bool     // Whether SNI extension exists
	CipherSuites     []uint16 // Cipher suite list
	Extensions       []uint16 // Extension list
	ALPN             string   // First ALPN value
	SignatureAlgs    []uint16 // Signature algorithms in original order
	SupportedVersion uint16   // Highest version from supported_versions extension (0 if not present)
}

// GREASE values to ignore per RFC 8701
var greaseValues = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

// isGREASE checks if a value is a GREASE value.
func isGREASE(v uint16) bool {
	return greaseValues[v]
}

// filterGREASE removes GREASE values from a slice.
func filterGREASE(vals []uint16) []uint16 {
	result := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if !isGREASE(v) {
			result = append(result, v)
		}
	}
	return result
}

// tlsVersionCode converts a TLS version to its 2-character code.
func tlsVersionCode(v uint16) string {
	switch v {
	case 0x0304: // TLS 1.3
		return "13"
	case 0x0303: // TLS 1.2
		return "12"
	case 0x0302: // TLS 1.1
		return "11"
	case 0x0301: // TLS 1.0
		return "10"
	case 0x0300: // SSL 3.0
		return "s3"
	case 0x0002: // SSL 2.0
		return "s2"
	case 0xfeff: // DTLS 1.0
		return "d1"
	case 0xfefd: // DTLS 1.2
		return "d2"
	case 0xfefc: // DTLS 1.3
		return "d3"
	default:
		return "00"
	}
}

// alpnCode extracts the first and last alphanumeric characters from an ALPN value.
// If either first or last byte is non-alphanumeric, uses hex representation instead.
func alpnCode(alpn string) string {
	if alpn == "" {
		return "00"
	}

	// Check if a byte is ASCII alphanumeric
	isAlphaNum := func(b byte) bool {
		return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
	}

	firstByte := alpn[0]
	lastByte := alpn[len(alpn)-1]

	// If first AND last byte are alphanumeric, use those chars directly
	if isAlphaNum(firstByte) && isAlphaNum(lastByte) {
		return string(firstByte) + string(lastByte)
	}

	// Otherwise, use hex representation of the entire ALPN
	hexStr := hex.EncodeToString([]byte(alpn))
	if hexStr == "" {
		return "00"
	}
	if len(hexStr) == 1 {
		return hexStr + hexStr
	}
	return string(hexStr[0]) + string(hexStr[len(hexStr)-1])
}

// truncateHash returns the first 12 characters of a SHA256 hash.
func truncateHash(data string) string {
	if data == "" {
		return "000000000000"
	}
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:12]
}

// sortHex sorts a slice of uint16 in ascending order.
func sortHex(vals []uint16) []uint16 {
	sorted := make([]uint16, len(vals))
	copy(sorted, vals)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	return sorted
}

// formatHexList formats a slice of uint16 as comma-separated 4-char hex strings.
func formatHexList(vals []uint16) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strings.ToLower(hex.EncodeToString([]byte{byte(v >> 8), byte(v)}))
	}
	return strings.Join(parts, ",")
}

// ComputeJA4 computes the JA4 fingerprint from TLS ClientHello parameters.
// Format: {protocol}{version}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{extension_hash}
// Example: t13d1516h2_8daaf6152771_e5627efa2ab1
func ComputeJA4(params JA4Params) JA4Fingerprint {
	// Determine protocol character (default to "t" for TLS over TCP)
	protocol := params.Protocol
	if protocol == "" {
		protocol = "t"
	}

	// Determine TLS version - prefer supported_versions extension if present
	version := params.TLSVersion
	if params.SupportedVersion > 0 {
		version = params.SupportedVersion
	}
	versionCode := tlsVersionCode(version)

	// SNI indicator
	sniCode := "i"
	if params.SNI {
		sniCode = "d"
	}

	// Filter GREASE values
	ciphers := filterGREASE(params.CipherSuites)
	extensions := filterGREASE(params.Extensions)
	sigAlgs := filterGREASE(params.SignatureAlgs)

	// Cipher count (max 99)
	cipherCount := len(ciphers)
	if cipherCount > 99 {
		cipherCount = 99
	}

	// Extension count (max 99)
	extCount := len(extensions)
	if extCount > 99 {
		extCount = 99
	}

	// ALPN code
	alpnCodeVal := alpnCode(params.ALPN)

	// Build part A: protocol + version + sni + counts + alpn
	partA := protocol + versionCode + sniCode +
		padInt(cipherCount) + padInt(extCount) + alpnCodeVal

	// Build part B: sorted cipher hash
	sortedCiphers := sortHex(ciphers)
	cipherList := formatHexList(sortedCiphers)
	partB := truncateHash(cipherList)

	// Build part C: sorted extensions (excluding SNI 0x0000 and ALPN 0x0010) + sig_algs
	filteredExts := make([]uint16, 0, len(extensions))
	for _, ext := range extensions {
		if ext != 0x0000 && ext != 0x0010 { // Exclude SNI and ALPN
			filteredExts = append(filteredExts, ext)
		}
	}
	sortedExts := sortHex(filteredExts)
	extList := formatHexList(sortedExts)

	// Add signature algorithms in original order (not sorted)
	sigAlgList := formatHexList(sigAlgs)

	var extData string
	switch {
	case extList != "" && sigAlgList != "":
		extData = extList + "_" + sigAlgList
	case extList != "":
		extData = extList
	case sigAlgList != "":
		extData = "_" + sigAlgList
	}
	partC := truncateHash(extData)

	// Build full fingerprint
	full := partA + "_" + partB + "_" + partC

	// Build raw fingerprint for debugging
	raw := partA + "_" + cipherList + "_" + extList
	if sigAlgList != "" {
		raw += "_" + sigAlgList
	}

	return JA4Fingerprint{
		Full: full,
		Raw:  raw,
	}
}

// padInt pads an integer to 2 digits.
func padInt(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}
