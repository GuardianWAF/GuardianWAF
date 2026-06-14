package botdetect

import (
	// #nosec G501 -- JA3 fingerprints are defined as MD5 digests of the JA3 string;
	// this is protocol fingerprinting, not cryptographic integrity or authentication.
	"crypto/md5"
	"encoding/hex"
	"strconv"
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
	var b strings.Builder
	b.Grow(128)
	b.WriteString(strconv.FormatUint(uint64(tlsVersion), 10))
	b.WriteByte(',')
	joinUint16(&b, cipherSuites)
	b.WriteByte(',')
	joinUint16(&b, extensions)
	b.WriteByte(',')
	joinUint16(&b, curves)
	b.WriteByte(',')
	joinUint8(&b, points)

	raw := b.String()
	// #nosec G401 -- JA3 interoperability requires MD5 over the canonical JA3 string.
	hash := md5.Sum([]byte(raw))

	return JA3Fingerprint{
		Hash: hex.EncodeToString(hash[:]),
		Raw:  raw,
	}
}

// joinUint16 appends dash-separated uint16 values to the builder.
func joinUint16(b *strings.Builder, vals []uint16) {
	for i, v := range vals {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
}

// joinUint8 appends dash-separated uint8 values to the builder.
func joinUint8(b *strings.Builder, vals []uint8) {
	for i, v := range vals {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
}
