package botdetect

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
)

// JA3Fingerprint represents a computed JA3 hash.
type JA3Fingerprint struct {
	Hash string // MD5 hex string
	Raw  string // raw JA3 string before hashing
}

// ComputeJA3 computes the JA3 fingerprint from TLS ClientHello parameters.
// Format: SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
// Each group is a dash-separated list of decimal values; groups are separated by commas.
func ComputeJA3(tlsVersion uint16, cipherSuites, extensions, curves []uint16, points []uint8) JA3Fingerprint {
	parts := make([]string, 5)
	parts[0] = fmt.Sprintf("%d", tlsVersion)
	parts[1] = joinUint16(cipherSuites)
	parts[2] = joinUint16(extensions)
	parts[3] = joinUint16(curves)
	parts[4] = joinUint8(points)

	raw := strings.Join(parts, ",")
	hash := md5.Sum([]byte(raw))

	return JA3Fingerprint{
		Hash: hex.EncodeToString(hash[:]),
		Raw:  raw,
	}
}

// joinUint16 joins a slice of uint16 values into a dash-separated string.
func joinUint16(vals []uint16) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}

// joinUint8 joins a slice of uint8 values into a dash-separated string.
func joinUint8(vals []uint8) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, "-")
}
