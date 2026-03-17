package botdetect

// FingerprintCategory classifies a JA3 fingerprint.
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

// FingerprintInfo holds metadata about a known JA3 fingerprint.
type FingerprintInfo struct {
	Name     string
	Category FingerprintCategory
	Score    int // Threat score (0-100)
}

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

// LookupFingerprint returns the fingerprint info for a JA3 hash.
// Returns an entry with FingerprintUnknown if the hash is not in the database.
func LookupFingerprint(ja3Hash string) FingerprintInfo {
	if info, ok := fingerprintDB[ja3Hash]; ok {
		return info
	}
	return FingerprintInfo{
		Name:     "unknown",
		Category: FingerprintUnknown,
		Score:    0,
	}
}

// AddFingerprint adds or updates a fingerprint in the database.
func AddFingerprint(ja3Hash string, info FingerprintInfo) {
	fingerprintDB[ja3Hash] = info
}

// RemoveFingerprint removes a fingerprint from the database.
func RemoveFingerprint(ja3Hash string) {
	delete(fingerprintDB, ja3Hash)
}
