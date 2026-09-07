package apivalidation

import (
	"strings"
	"testing"
)

// Regression tests: minLength/maxLength must count Unicode code points
// (JSON Schema §6.3.1/6.3.2), not bytes. The previous implementation used
// len(str), which miscounts multi-byte characters: maxLength false-blocked
// legitimate internationalized content and minLength passed 1-emoji strings
// against a 3-character minimum.

func emojiString(n int) string {
	return strings.Repeat("\U0001F600", n) // 😀 — 4 bytes, 1 code point each
}

func TestMinLengthCountsCodePoints(t *testing.T) {
	v := NewSchemaValidator(true)
	minLen := 3

	// 1 emoji = 1 code point, 4 bytes: must be INVALID under minLength=3
	// (the old byte-counting code accepted it).
	res := v.Validate(emojiString(1), &Schema{Type: "string", MinLength: &minLen}, "body.name")
	if res.Valid {
		t.Fatalf("FAIL: a 1-code-point string (4 bytes) passed minLength=3 — byte counting is still in effect")
	}

	// 3 emoji = 3 code points: must be VALID.
	res = v.Validate(emojiString(3), &Schema{Type: "string", MinLength: &minLen}, "body.name")
	if !res.Valid {
		t.Fatalf("FAIL: a 3-code-point string rejected by minLength=3 (errors=%v)", res.Errors)
	}

	// ASCII controls: byte length == code-point length.
	if res := v.Validate("ab", &Schema{Type: "string", MinLength: &minLen}, "body.name"); res.Valid {
		t.Fatalf("FAIL: ASCII \"ab\" (2 chars) accepted by minLength=3")
	}
	if res := v.Validate("abc", &Schema{Type: "string", MinLength: &minLen}, "body.name"); !res.Valid {
		t.Fatalf("FAIL: ASCII \"abc\" (3 chars) rejected by minLength=3 (errors=%v)", res.Errors)
	}
}

func TestMaxLengthCountsCodePoints(t *testing.T) {
	v := NewSchemaValidator(true)
	maxLen := 10

	// 8 emoji = 8 code points, 32 bytes: must be VALID under maxLength=10
	// (the old byte-counting code rejected it — 32 > 10).
	res := v.Validate(emojiString(8), &Schema{Type: "string", MaxLength: &maxLen}, "body.name")
	if !res.Valid {
		t.Fatalf("FAIL: an 8-code-point string (32 bytes) rejected by maxLength=10 (errors=%v) — legitimate multi-byte content is false-blocked", res.Errors)
	}

	// 11 emoji = 11 code points: must be INVALID.
	res = v.Validate(emojiString(11), &Schema{Type: "string", MaxLength: &maxLen}, "body.name")
	if res.Valid {
		t.Fatalf("FAIL: an 11-code-point string accepted by maxLength=10")
	}

	// ASCII boundary: exactly 10 chars valid, 11 invalid.
	if res := v.Validate(strings.Repeat("a", 10), &Schema{Type: "string", MaxLength: &maxLen}, "body.name"); !res.Valid {
		t.Fatalf("FAIL: ASCII 10-char string rejected by maxLength=10 (errors=%v)", res.Errors)
	}
	if res := v.Validate(strings.Repeat("a", 11), &Schema{Type: "string", MaxLength: &maxLen}, "body.name"); res.Valid {
		t.Fatalf("FAIL: ASCII 11-char string accepted by maxLength=10")
	}
}

func TestLengthConstraintsMultiByteDiscriminating(t *testing.T) {
	// ẞ (U+1E9E) is 3 bytes but 1 code point. 3×ẞ = 9 bytes / 3 code points:
	// discriminating for both constraints against (min=6, max=6) — byte
	// counting would reject (9 > 6), code-point counting accepts (3 < 6...
	// wait: 3 < 6 fails min). Use max only: byte counting rejects 9 > 6,
	// code-point counting accepts 3 ≤ 6.
	v := NewSchemaValidator(true)
	maxLen := 6

	res := v.Validate("ßßß", &Schema{Type: "string", MaxLength: &maxLen}, "body.name")
	if !res.Valid {
		t.Fatalf("FAIL: a 3-code-point string (9 bytes) rejected by maxLength=6 (errors=%v) — byte counting miscounts multi-byte characters", res.Errors)
	}

	// Discriminating minLength case: 1×ẞ = 3 bytes / 1 code point against
	// min=2: byte counting accepts (3 >= 2), code-point counting rejects
	// (1 < 2).
	minLen := 2
	res = v.Validate("ß", &Schema{Type: "string", MinLength: &minLen}, "body.name")
	if res.Valid {
		t.Fatalf("FAIL: a 1-code-point string (3 bytes) passed minLength=2 — byte counting is still in effect")
	}
}
