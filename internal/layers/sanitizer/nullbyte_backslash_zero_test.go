package sanitizer

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// containsNullByte's contract (validate.go) names three null-byte spellings:
// the literal \x00 byte, the %00 sequence, and backslash-zero \0. The
// implementation tested only the first two, while the sibling normalizer
// RemoveNullBytes (normalize.go) strips all three. The two functions therefore
// disagreed about which spellings are null bytes: with block_null_bytes on
// (the shipped default) the operator's null-byte block was bypassed by using
// the one spelling the package had already agreed was a null byte.
const bslashZeroURI = "/download\\0.jsp"

func nullByteFindings(fs []engine.Finding) []engine.Finding {
	var out []engine.Finding
	for _, f := range fs {
		if f.Description == "Null byte detected in URL" {
			out = append(out, f)
		}
	}
	return out
}

// All three spellings the contract names must be detected.
func TestContainsNullByte_DetectsEveryDocumentedSpelling(t *testing.T) {
	for _, in := range []string{
		"/a\x00b",     // literal NUL
		"/a%00b",      // percent-encoded
		bslashZeroURI, // backslash-zero — the form that was missing
	} {
		if !containsNullByte(in) {
			t.Errorf("FAIL: containsNullByte(%q) = false; the function's "+
				"contract names literal NUL, %%00, and backslash-zero", in)
		}
	}
}

// The validator and the normalizer must agree on which spellings are null
// bytes — the asymmetry is the defect. Each spelling accepted by
// RemoveNullBytes must also be flagged by containsNullByte.
func TestNullByteValidatorAgreesWithNormalizer(t *testing.T) {
	for _, in := range []string{
		"/a\x00b",
		"/a%00b",
		bslashZeroURI,
	} {
		stripped := RemoveNullBytes(in)
		if stripped == in {
			t.Errorf("CONTROL BROKEN: RemoveNullBytes did not strip %q, so "+
				"this input does not isolate the validator", in)
			continue
		}
		if !containsNullByte(in) {
			t.Errorf("FAIL: RemoveNullBytes strips %q but containsNullByte "+
				"does not flag it; the two must agree", in)
		}
	}
}

// End-to-end through the real production path: Layer.Process ->
// ValidateRequest -> containsNullByte, with block_null_bytes enabled.
func TestBlockNullBytes_EndToEndAcrossSpellings(t *testing.T) {
	for _, uri := range []string{"/a\x00b", "/a%00b", bslashZeroURI} {
		l := &Layer{config: Config{BlockNullBytes: true}, enabled: true}
		res := l.Process(&engine.RequestContext{
			Method: "GET", Path: uri, URI: uri,
		})
		if len(nullByteFindings(res.Findings)) == 0 {
			t.Errorf("FAIL: %q produced no null-byte finding end-to-end "+
				"(findings=%d)", uri, len(res.Findings))
		}
	}
}

// Precision control: benign paths that merely contain a backslash, or the
// digits "0" next to one, must NOT be flagged. Only a backslash IMMEDIATELY
// followed by '0' is a null byte.
func TestContainsNullByte_DoesNotOverMatch(t *testing.T) {
	for _, in := range []string{
		"/a/b",
		`/a\b`,  // backslash, not backslash-zero
		"/a\\1", // backslash-digit
		"/0/b",  // leading zero, no escape
		`/a\`,   // trailing lone backslash
	} {
		if containsNullByte(in) {
			t.Errorf("FAIL: containsNullByte(%q) = true, but it is not a "+
				"null byte; only \\0 is", in)
		}
	}
}

// Boundary: the \\0 sequence must still be detected at the very end of the
// string, where the i+1 bounds check is closest to its limit.
func TestContainsNullByte_BackslashZeroAtStringBoundary(t *testing.T) {
	for _, in := range []string{
		`\0`,        // sequence is the whole string
		"/x" + `\0`, // sequence at the end
		`\0` + "/x", // sequence at the start
	} {
		if !containsNullByte(in) {
			t.Errorf("FAIL: containsNullByte(%q) = false; the \\0 sequence at "+
				"a string boundary must still be detected", in)
		}
	}
}
