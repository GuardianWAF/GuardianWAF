package response

import "testing"

// Regression tests: MaskAPIKeys must search the ORIGINAL string
// case-insensitively (indexFold) and mask at offsets valid in the original.
// The previous implementation searched a strings.ToLower copy — ToLower is
// not length-preserving (İ U+0130: 2 bytes → "i"; ẞ U+1E9E: 3 bytes → "ß") —
// so any length-changing character before the keyword shifted the mask
// window and leaked the key's tail (and could misclassify entirely).

const maskKey = "ABCDEFGHIJKLMNOP1234" // ABCD + 12 secret + 1234

func TestMaskAPIKeysUnicodeBeforeKeyword(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"İ before keyword (2→1 shift)", "İst api_key=" + maskKey, "İst api_key=ABCD************1234"},
		{"ẞ before keyword (3→2 shift)", "ẞ api_key=" + maskKey, "ẞ api_key=ABCD************1234"},
	}
	for _, tc := range cases {
		if got := MaskAPIKeys(tc.in); got != tc.want {
			t.Errorf("FAIL: %s: MaskAPIKeys(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestMaskAPIKeysKeywordCaseInsensitive(t *testing.T) {
	// indexFold must keep the keyword match case-insensitive without a
	// ToLower copy.
	if got := MaskAPIKeys("API_KEY=" + maskKey); got != "API_KEY=ABCD************1234" {
		t.Fatalf("FAIL: uppercase keyword masked as %q", got)
	}
}

func TestMaskAPIKeysASCIIControl(t *testing.T) {
	if got := MaskAPIKeys("api_key=" + maskKey); got != "api_key=ABCD************1234" {
		t.Fatalf("FAIL: ASCII control masked as %q", got)
	}
}

// Boundary: a value starting with a multi-byte character is not an API key
// (real keys are ASCII) — the scan skips it, leaving the text untouched.
// Masking it would corrupt legitimate localized content.
func TestMaskAPIKeysMultibyteAfterEqualsBoundary(t *testing.T) {
	in := "api_key=İ" + maskKey
	if got := MaskAPIKeys(in); got != in {
		t.Fatalf("FAIL: non-ASCII value start was masked: %q", got)
	}
}
