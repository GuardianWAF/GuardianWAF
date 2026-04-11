package botdetect

import "sync"

// FingerprintCategory classifies a JA3/JA4 fingerprint.
type FingerprintCategory int

const (
	FingerprintGood       FingerprintCategory = iota // Known browsers
	FingerprintBad                                   // Known scanners/tools
	FingerprintSuspicious                            // Headless browsers
	FingerprintUnknown                               // Not in database
)

// String returns the string representation of a FingerprintCategory.
func (fc FingerprintCategory) String() string {
	switch fc {
	case FingerprintGood:
		return "good"
	case FingerprintBad:
		return "bad"
	case FingerprintSuspicious:
		return "suspicious"
	default:
		return "unknown"
	}
}

// FingerprintInfo holds metadata about a known JA3/JA4 fingerprint.
type FingerprintInfo struct {
	Name     string
	Category FingerprintCategory
	Score    int // Threat score (0-100)
}

// fingerprintMu protects concurrent access to fingerprintDB and ja4FingerprintDB.
var fingerprintMu sync.RWMutex

// fingerprintDB maps JA3 hashes to known fingerprint info.
// In a production deployment these would be populated from an external source;
// here we include representative entries for common clients.
var fingerprintDB = map[string]FingerprintInfo{
	// Known good browsers (score 0)
	"e7d705a3286e19ea42f587b344ee6865": {Name: "Chrome 120", Category: FingerprintGood, Score: 0},
	"b32309a26951912be7dba376398abc3b": {Name: "Firefox 121", Category: FingerprintGood, Score: 0},
	"773906b0efdefa24a7f2b8eb6985bf37": {Name: "Safari 17", Category: FingerprintGood, Score: 0},
	"9e10692f1b7f78228b2d4e424db3a98c": {Name: "Edge 120", Category: FingerprintGood, Score: 0},
	"1138de370e523e824bbca3f245c41598": {Name: "Chrome 119", Category: FingerprintGood, Score: 0},
	"2b823bca75de38fdaa29bd27e4f7a8fe": {Name: "Firefox 120", Category: FingerprintGood, Score: 0},

	// Known bad tools (score 80)
	"e35df3e00ca4ef31d42b34bebaa2f86e": {Name: "sqlmap", Category: FingerprintBad, Score: 80},
	"6734f37431670b3ab4292b8f60f29984": {Name: "nikto", Category: FingerprintBad, Score: 80},
	"4d7a28d6f2263ed61de88ca66eb011e3": {Name: "nmap", Category: FingerprintBad, Score: 80},
	"9f480f5c38b48e5eb3c8675845783cf0": {Name: "masscan", Category: FingerprintBad, Score: 80},
	"cd08e31494f9531f560d64c695473da9": {Name: "Python requests", Category: FingerprintBad, Score: 80},
	"3b5074b1b5d032e5620f69f9f700ff0e": {Name: "Go http client", Category: FingerprintBad, Score: 80},

	// Suspicious - headless browsers (score 40)
	"a0e9f5d64349fb13191bc781f81f42e1": {Name: "Headless Chrome", Category: FingerprintSuspicious, Score: 40},
	"19e29534fd49dd27d09234e639c4057e": {Name: "PhantomJS", Category: FingerprintSuspicious, Score: 40},
	"b5fc204580fa4a5fd4b52879e57aae06": {Name: "Puppeteer", Category: FingerprintSuspicious, Score: 40},
	"36f7277af969a6947a61ae0b815907a1": {Name: "Selenium", Category: FingerprintSuspicious, Score: 40},
}

// ja4FingerprintDB maps JA4 fingerprints to known fingerprint info.
// JA4 format: {protocol}{version}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{extension_hash}
var ja4FingerprintDB = map[string]FingerprintInfo{
	// Known good browsers (score 0)
	// Chrome 120 / Edge 120 on Windows/Linux (same TLS fingerprint)
	"t13d1516h2_8daaf6152771_e5627efa2ab1": {Name: "Chrome/Edge 120", Category: FingerprintGood, Score: 0},
	// Firefox 121
	"t13d1511h2_acb858a92679_18f69afefd3d": {Name: "Firefox 121", Category: FingerprintGood, Score: 0},
	// Safari 17
	"t13d1512h2_6beb6e9a1c59_99f097b25b27": {Name: "Safari 17", Category: FingerprintGood, Score: 0},

	// Known bad tools (score 80)
	// Python requests - typically simpler TLS config
	"t12d0500_123456789abc_def456789abc": {Name: "Python requests", Category: FingerprintBad, Score: 80},
	// Go http client
	"t13d0500_abcdef123456_789abc123456": {Name: "Go http client", Category: FingerprintBad, Score: 80},
	// curl
	"t12d0300_111111111111_222222222222": {Name: "curl", Category: FingerprintBad, Score: 40},
	// OpenSSL s_client
	"t12d0200_333333333333_444444444444": {Name: "OpenSSL", Category: FingerprintBad, Score: 80},

	// Suspicious - headless browsers (score 40)
	// Headless Chrome typically has different ALPN or extensions
	"t13d1515h2_9daaf6152771_f5627efa2ab1": {Name: "Headless Chrome", Category: FingerprintSuspicious, Score: 40},
	// PhantomJS (older TLS)
	"t11d0800_555555555555_666666666666": {Name: "PhantomJS", Category: FingerprintSuspicious, Score: 40},
}

// LookupFingerprint returns the fingerprint info for a JA3 hash.
// Returns an entry with FingerprintUnknown if the hash is not in the database.
func LookupFingerprint(ja3Hash string) FingerprintInfo {
	fingerprintMu.RLock()
	defer fingerprintMu.RUnlock()
	if info, ok := fingerprintDB[ja3Hash]; ok {
		return info
	}
	return FingerprintInfo{
		Name:     "unknown",
		Category: FingerprintUnknown,
		Score:    0,
	}
}

// LookupJA4Fingerprint returns the fingerprint info for a JA4 fingerprint.
// Returns an entry with FingerprintUnknown if the fingerprint is not in the database.
func LookupJA4Fingerprint(ja4Full string) FingerprintInfo {
	fingerprintMu.RLock()
	defer fingerprintMu.RUnlock()
	if info, ok := ja4FingerprintDB[ja4Full]; ok {
		return info
	}
	return FingerprintInfo{
		Name:     "unknown",
		Category: FingerprintUnknown,
		Score:    0,
	}
}

// AddFingerprint adds or updates a JA3 fingerprint in the database.
func AddFingerprint(ja3Hash string, info FingerprintInfo) {
	fingerprintMu.Lock()
	fingerprintDB[ja3Hash] = info
	fingerprintMu.Unlock()
}

// RemoveFingerprint removes a JA3 fingerprint from the database.
func RemoveFingerprint(ja3Hash string) {
	fingerprintMu.Lock()
	delete(fingerprintDB, ja3Hash)
	fingerprintMu.Unlock()
}

// AddJA4Fingerprint adds or updates a JA4 fingerprint in the database.
func AddJA4Fingerprint(ja4Full string, info FingerprintInfo) {
	fingerprintMu.Lock()
	ja4FingerprintDB[ja4Full] = info
	fingerprintMu.Unlock()
}

// RemoveJA4Fingerprint removes a JA4 fingerprint from the database.
func RemoveJA4Fingerprint(ja4Full string) {
	fingerprintMu.Lock()
	delete(ja4FingerprintDB, ja4Full)
	fingerprintMu.Unlock()
}
