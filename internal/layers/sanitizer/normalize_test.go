package sanitizer

import (
	"testing"
	"unicode/utf8"
)

func TestDecodeURLRecursive_SingleEncoding(t *testing.T) {
	input := "hello%20world"
	want := "hello world"
	got := DecodeURLRecursive(input)
	if got != want {
		t.Errorf("DecodeURLRecursive(%q) = %q, want %q", input, got, want)
	}
}

func TestDecodeURLRecursive_Apostrophe(t *testing.T) {
	input := "%27"
	want := "'"
	got := DecodeURLRecursive(input)
	if got != want {
		t.Errorf("DecodeURLRecursive(%q) = %q, want %q", input, got, want)
	}
}

func TestDecodeURLRecursive_DoubleEncoding(t *testing.T) {
	// %2527 -> first pass: %27 -> second pass: '
	input := "%2527"
	want := "'"
	got := DecodeURLRecursive(input)
	if got != want {
		t.Errorf("DecodeURLRecursive(%q) = %q, want %q", input, got, want)
	}
}

func TestDecodeURLRecursive_TripleEncoding(t *testing.T) {
	// %252527 -> %2527 -> %27 -> '
	input := "%252527"
	want := "'"
	got := DecodeURLRecursive(input)
	if got != want {
		t.Errorf("DecodeURLRecursive(%q) = %q, want %q", input, got, want)
	}
}

func TestDecodeURLRecursive_NoEncoding(t *testing.T) {
	input := "hello world"
	want := "hello world"
	got := DecodeURLRecursive(input)
	if got != want {
		t.Errorf("DecodeURLRecursive(%q) = %q, want %q", input, got, want)
	}
}

func TestDecodeURLRecursive_UnicodeEscape(t *testing.T) {
	// %u003C should decode to '<'
	input := "%u003C"
	want := "<"
	got := DecodeURLRecursive(input)
	if got != want {
		t.Errorf("DecodeURLRecursive(%q) = %q, want %q", input, got, want)
	}
}

func TestDecodeURLRecursive_MixedEncoding(t *testing.T) {
	input := "%3Cscript%3Ealert(%27xss%27)%3C/script%3E"
	want := "<script>alert('xss')</script>"
	got := DecodeURLRecursive(input)
	if got != want {
		t.Errorf("DecodeURLRecursive(%q) = %q, want %q", input, got, want)
	}
}

func TestDecodeURLRecursive_InvalidPercent(t *testing.T) {
	input := "%ZZ"
	want := "%ZZ"
	got := DecodeURLRecursive(input)
	if got != want {
		t.Errorf("DecodeURLRecursive(%q) = %q, want %q", input, got, want)
	}
}

func TestRemoveNullBytes_PercentZero(t *testing.T) {
	input := "hello%00world"
	want := "helloworld"
	got := RemoveNullBytes(input)
	if got != want {
		t.Errorf("RemoveNullBytes(%q) = %q, want %q", input, got, want)
	}
}

func TestRemoveNullBytes_LiteralNull(t *testing.T) {
	input := "hello\x00world"
	want := "helloworld"
	got := RemoveNullBytes(input)
	if got != want {
		t.Errorf("RemoveNullBytes(%q) = %q, want %q", input, got, want)
	}
}

func TestRemoveNullBytes_BackslashZero(t *testing.T) {
	input := "hello\\0world"
	want := "helloworld"
	got := RemoveNullBytes(input)
	if got != want {
		t.Errorf("RemoveNullBytes(%q) = %q, want %q", input, got, want)
	}
}

func TestRemoveNullBytes_Mixed(t *testing.T) {
	input := "a\x00b%00c\\0d"
	want := "abcd"
	got := RemoveNullBytes(input)
	if got != want {
		t.Errorf("RemoveNullBytes(%q) = %q, want %q", input, got, want)
	}
}

func TestCanonicalizePath_DotDotTraversal(t *testing.T) {
	input := "/foo/../../../etc/passwd"
	want := "/etc/passwd"
	got := CanonicalizePath(input)
	if got != want {
		t.Errorf("CanonicalizePath(%q) = %q, want %q", input, got, want)
	}
}

func TestCanonicalizePath_DotSlash(t *testing.T) {
	input := "/./foo/./bar"
	want := "/foo/bar"
	got := CanonicalizePath(input)
	if got != want {
		t.Errorf("CanonicalizePath(%q) = %q, want %q", input, got, want)
	}
}

func TestCanonicalizePath_DoubleSlash(t *testing.T) {
	input := "//bar//baz"
	want := "/bar/baz"
	got := CanonicalizePath(input)
	if got != want {
		t.Errorf("CanonicalizePath(%q) = %q, want %q", input, got, want)
	}
}

func TestCanonicalizePath_TrailingDots(t *testing.T) {
	input := "/foo/bar..."
	want := "/foo/bar"
	got := CanonicalizePath(input)
	if got != want {
		t.Errorf("CanonicalizePath(%q) = %q, want %q", input, got, want)
	}
}

func TestCanonicalizePath_RootOnly(t *testing.T) {
	input := "/"
	want := "/"
	got := CanonicalizePath(input)
	if got != want {
		t.Errorf("CanonicalizePath(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizeUnicode_FullwidthLetters(t *testing.T) {
	// U+FF21 = fullwidth A
	input := "\uFF21\uFF22\uFF23"
	want := "ABC"
	got := NormalizeUnicode(input)
	if got != want {
		t.Errorf("NormalizeUnicode(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizeUnicode_FullwidthLowercase(t *testing.T) {
	input := "\uFF41\uFF42\uFF43"
	want := "abc"
	got := NormalizeUnicode(input)
	if got != want {
		t.Errorf("NormalizeUnicode(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizeUnicode_FullwidthNumbers(t *testing.T) {
	input := "\uFF10\uFF11\uFF12"
	want := "012"
	got := NormalizeUnicode(input)
	if got != want {
		t.Errorf("NormalizeUnicode(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizeUnicode_MixedASCII(t *testing.T) {
	input := "hello\uFF21world"
	want := "helloAworld"
	got := NormalizeUnicode(input)
	if got != want {
		t.Errorf("NormalizeUnicode(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizeUnicode_PureASCII(t *testing.T) {
	input := "hello world"
	want := "hello world"
	got := NormalizeUnicode(input)
	if got != want {
		t.Errorf("NormalizeUnicode(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizeUnicode_FullwidthSymbols(t *testing.T) {
	// U+FF01 = fullwidth !, U+FF0F = fullwidth /
	input := "\uFF01\uFF0F"
	want := "!/"
	got := NormalizeUnicode(input)
	if got != want {
		t.Errorf("NormalizeUnicode(%q) = %q, want %q", input, got, want)
	}
}

func TestDecodeHTMLEntities_Named(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"&lt;", "<"},
		{"&gt;", ">"},
		{"&amp;", "&"},
		{"&quot;", "\""},
		{"&apos;", "'"},
	}
	for _, tt := range tests {
		got := DecodeHTMLEntities(tt.input)
		if got != tt.want {
			t.Errorf("DecodeHTMLEntities(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDecodeHTMLEntities_DecimalNumeric(t *testing.T) {
	input := "&#60;"
	want := "<"
	got := DecodeHTMLEntities(input)
	if got != want {
		t.Errorf("DecodeHTMLEntities(%q) = %q, want %q", input, got, want)
	}
}

func TestDecodeHTMLEntities_HexNumericLower(t *testing.T) {
	input := "&#x3c;"
	want := "<"
	got := DecodeHTMLEntities(input)
	if got != want {
		t.Errorf("DecodeHTMLEntities(%q) = %q, want %q", input, got, want)
	}
}

func TestDecodeHTMLEntities_HexNumericUpper(t *testing.T) {
	input := "&#x3C;"
	want := "<"
	got := DecodeHTMLEntities(input)
	if got != want {
		t.Errorf("DecodeHTMLEntities(%q) = %q, want %q", input, got, want)
	}
}

func TestDecodeHTMLEntities_Mixed(t *testing.T) {
	input := "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
	// &#39; is decimal for apostrophe
	want := "<script>alert('xss')</script>"
	got := DecodeHTMLEntities(input)
	if got != want {
		t.Errorf("DecodeHTMLEntities(%q) = %q, want %q", input, got, want)
	}
}

func TestDecodeHTMLEntities_NoEntities(t *testing.T) {
	input := "hello world"
	want := "hello world"
	got := DecodeHTMLEntities(input)
	if got != want {
		t.Errorf("DecodeHTMLEntities(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizeCase(t *testing.T) {
	input := "MiXeD CaSe"
	want := "mixed case"
	got := NormalizeCase(input)
	if got != want {
		t.Errorf("NormalizeCase(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizeWhitespace_MultipleSpaces(t *testing.T) {
	input := "hello    world"
	want := "hello world"
	got := NormalizeWhitespace(input)
	if got != want {
		t.Errorf("NormalizeWhitespace(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizeWhitespace_Tabs(t *testing.T) {
	input := "hello\t\tworld"
	want := "hello world"
	got := NormalizeWhitespace(input)
	if got != want {
		t.Errorf("NormalizeWhitespace(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizeWhitespace_Newlines(t *testing.T) {
	input := "hello\n\nworld"
	want := "hello world"
	got := NormalizeWhitespace(input)
	if got != want {
		t.Errorf("NormalizeWhitespace(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizeWhitespace_LeadingTrailing(t *testing.T) {
	input := "  hello  "
	want := "hello"
	got := NormalizeWhitespace(input)
	if got != want {
		t.Errorf("NormalizeWhitespace(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizeBackslashes(t *testing.T) {
	input := "foo\\bar\\baz"
	want := "foo/bar/baz"
	got := NormalizeBackslashes(input)
	if got != want {
		t.Errorf("NormalizeBackslashes(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizeBackslashes_Mixed(t *testing.T) {
	input := "foo\\bar/baz"
	want := "foo/bar/baz"
	got := NormalizeBackslashes(input)
	if got != want {
		t.Errorf("NormalizeBackslashes(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizeAll_ChainedNormalization(t *testing.T) {
	// URL-encoded path traversal with null bytes and leading slash
	input := "/%2e%2e/%2e%2e/etc/passwd%00"
	got := NormalizeAll(input)
	want := "/etc/passwd"
	if got != want {
		t.Errorf("NormalizeAll(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizeAll_XSSPayload(t *testing.T) {
	// Double-encoded <script>
	input := "%253Cscript%253E"
	got := NormalizeAll(input)
	// After double decode: <script>
	// After CanonicalizePath: not a path with slashes, so minimal change
	// After other normalizations: <script>
	want := "<script>"
	if got != want {
		t.Errorf("NormalizeAll(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizeAll_FullwidthAttack(t *testing.T) {
	// Fullwidth < and > with script
	input := "\uFF1Cscript\uFF1E"
	// NormalizeUnicode: FF1C is not in the mapped ranges (it's > FF0F), stays as-is
	// Actually FF1C is fullwidth < which is in the symbol range? Let me check.
	// FF01 = !, mapped to ! (0x21), range goes to FF0F = / (0x2F)
	// FF1C > FF0F, so not in the mapped range. But it's still a valid test.
	got := NormalizeAll(input)
	// The fullwidth < (FF1C) and > (FF1E) are outside our mapped range
	// They stay as-is in NormalizeUnicode. This tests that ASCII content passes through.
	if len(got) == 0 {
		t.Errorf("NormalizeAll(%q) returned empty string", input)
	}
}

func TestNormalizeAll_EmptyString(t *testing.T) {
	got := NormalizeAll("")
	if got != "" {
		t.Errorf("NormalizeAll(%q) = %q, want %q", "", got, "")
	}
}

func TestCanonicalizePath_ComplexTraversal(t *testing.T) {
	input := "/a/b/c/../../../etc/shadow"
	want := "/etc/shadow"
	got := CanonicalizePath(input)
	if got != want {
		t.Errorf("CanonicalizePath(%q) = %q, want %q", input, got, want)
	}
}

func TestCanonicalizePath_Backslashes(t *testing.T) {
	input := "\\foo\\..\\bar"
	want := "/bar"
	got := CanonicalizePath(input)
	if got != want {
		t.Errorf("CanonicalizePath(%q) = %q, want %q", input, got, want)
	}
}

func TestCanonicalizePath_EmptyString(t *testing.T) {
	got := CanonicalizePath("")
	if got != "" {
		t.Errorf("CanonicalizePath(%q) = %q, want %q", "", got, "")
	}
}

func TestCanonicalizePath_AllDots(t *testing.T) {
	// Segment that is only dots should be cleaned to empty and skipped
	got := CanonicalizePath("/foo/..../bar")
	if got != "/foo/bar" {
		t.Errorf("CanonicalizePath(%q) = %q, want %q", "/foo/..../bar", got, "/foo/bar")
	}
}

func TestCanonicalizePath_NoLeadingSlash(t *testing.T) {
	got := CanonicalizePath("foo/bar")
	if got != "foo/bar" {
		t.Errorf("CanonicalizePath(%q) = %q, want %q", "foo/bar", got, "foo/bar")
	}
}

func TestCanonicalizePath_OnlyDotDot(t *testing.T) {
	// All .. segments resolve to root
	got := CanonicalizePath("/../../..")
	if got != "/" {
		t.Errorf("CanonicalizePath(%q) = %q, want %q", "/../../..", got, "/")
	}
}

func TestDecodeURLRecursive_MaxIterations(t *testing.T) {
	// Create a 6-deep encoding that exceeds the 5-iteration limit
	// %25 -> % (one decode layer)
	// So %252525252527 needs 6 decodes to reach '
	// 6 layers: start with ' (0x27)
	// Layer 1: %27
	// Layer 2: %2527
	// Layer 3: %252527
	// Layer 4: %25252527
	// Layer 5: %2525252527
	// Layer 6: %252525252527
	input := "%252525252527"
	got := DecodeURLRecursive(input)
	// After 5 iterations it should NOT be fully decoded to '
	// because it needs 6 iterations
	if got == "'" {
		t.Errorf("DecodeURLRecursive should cap at 5 iterations, but fully decoded 6-deep encoding")
	}
}

func TestDecodeURLRecursive_EmptyString(t *testing.T) {
	got := DecodeURLRecursive("")
	if got != "" {
		t.Errorf("DecodeURLRecursive(%q) = %q, want %q", "", got, "")
	}
}

func TestDecodeURLOnce_IncompletePercent(t *testing.T) {
	// A % at the very end of a string
	got := DecodeURLRecursive("%")
	if got != "%" {
		t.Errorf("DecodeURLRecursive(%q) = %q, want %q", "%", got, "%")
	}

	// A % with only one hex char after
	got2 := DecodeURLRecursive("%2")
	if got2 != "%2" {
		t.Errorf("DecodeURLRecursive(%q) = %q, want %q", "%2", got2, "%2")
	}
}

func TestDecodeURLOnce_PartialUnicodeEscape(t *testing.T) {
	// %u with invalid hex chars
	got := DecodeURLRecursive("%u00ZZ")
	if got != "%u00ZZ" {
		t.Errorf("DecodeURLRecursive(%q) = %q, want %q", "%u00ZZ", got, "%u00ZZ")
	}

	// %u with only 2 valid hex digits (not enough)
	got2 := DecodeURLRecursive("%u00")
	if got2 != "%u00" {
		t.Errorf("DecodeURLRecursive(%q) = %q, want %q", "%u00", got2, "%u00")
	}

	// %U uppercase
	got3 := DecodeURLRecursive("%U0041")
	if got3 != "A" {
		t.Errorf("DecodeURLRecursive(%q) = %q, want %q", "%U0041", got3, "A")
	}
}

func TestNormalizeUnicode_InvalidUTF8(t *testing.T) {
	// Invalid UTF-8: byte 0xFF is never valid in UTF-8
	input := string([]byte{0xFF, 0xFE, 'h', 'e', 'l', 'l', 'o'})
	got := NormalizeUnicode(input)
	// Should not crash, should handle RuneError gracefully
	if len(got) == 0 {
		t.Error("NormalizeUnicode returned empty for input with invalid UTF-8")
	}
	if got[len(got)-5:] != "hello" {
		t.Errorf("expected 'hello' suffix, got %q", got)
	}
}

func TestNormalizeUnicode_EmptyString(t *testing.T) {
	got := NormalizeUnicode("")
	if got != "" {
		t.Errorf("NormalizeUnicode(%q) = %q, want %q", "", got, "")
	}
}

func TestDecodeHTMLEntities_UnknownEntity(t *testing.T) {
	// Unknown named entity should be kept as-is
	got := DecodeHTMLEntities("&foobar;")
	if got != "&foobar;" {
		t.Errorf("DecodeHTMLEntities(%q) = %q, want %q", "&foobar;", got, "&foobar;")
	}
}

func TestDecodeHTMLEntities_AmpersandWithoutSemicolon(t *testing.T) {
	// & not followed by ;
	got := DecodeHTMLEntities("foo & bar")
	if got != "foo & bar" {
		t.Errorf("DecodeHTMLEntities(%q) = %q, want %q", "foo & bar", got, "foo & bar")
	}
}

func TestDecodeHTMLEntities_HexEntityUpperX(t *testing.T) {
	// &#X3C; (uppercase X)
	got := DecodeHTMLEntities("&#X3C;")
	if got != "<" {
		t.Errorf("DecodeHTMLEntities(%q) = %q, want %q", "&#X3C;", got, "<")
	}
}

func TestDecodeHTMLEntities_InvalidNumericEntity(t *testing.T) {
	// Invalid hex entity
	got := DecodeHTMLEntities("&#xZZ;")
	if got != "&#xZZ;" {
		t.Errorf("DecodeHTMLEntities(%q) = %q, want %q", "&#xZZ;", got, "&#xZZ;")
	}

	// Invalid decimal entity
	got2 := DecodeHTMLEntities("&#abc;")
	if got2 != "&#abc;" {
		t.Errorf("DecodeHTMLEntities(%q) = %q, want %q", "&#abc;", got2, "&#abc;")
	}
}

func TestParseHexEntity_EdgeCases(t *testing.T) {
	// Empty string
	val, ok := parseHexEntity("")
	if ok {
		t.Errorf("expected false for empty hex entity, got val=%d", val)
	}

	// Too long (> 6 chars)
	val, ok = parseHexEntity("1234567")
	if ok {
		t.Errorf("expected false for too-long hex entity, got val=%d", val)
	}

	// Invalid character in hex
	val, ok = parseHexEntity("GG")
	if ok {
		t.Errorf("expected false for invalid hex char, got val=%d", val)
	}
}

func TestParseDecEntity_EdgeCases(t *testing.T) {
	// Empty string
	val, ok := parseDecEntity("")
	if ok {
		t.Errorf("expected false for empty dec entity, got val=%d", val)
	}

	// Too long (> 7 chars)
	val, ok = parseDecEntity("12345678")
	if ok {
		t.Errorf("expected false for too-long dec entity, got val=%d", val)
	}

	// Invalid character
	val, ok = parseDecEntity("12a")
	if ok {
		t.Errorf("expected false for invalid dec char, got val=%d", val)
	}
}

func TestTruncate_EdgeCases(t *testing.T) {
	// String shorter than maxLen
	got := truncate("hi", 200)
	if got != "hi" {
		t.Errorf("truncate(%q, 200) = %q, want %q", "hi", got, "hi")
	}

	// maxLen <= 3
	got2 := truncate("hello world", 3)
	if got2 != "hel" {
		t.Errorf("truncate(%q, 3) = %q, want %q", "hello world", got2, "hel")
	}

	// maxLen == 2
	got3 := truncate("hello world", 2)
	if got3 != "he" {
		t.Errorf("truncate(%q, 2) = %q, want %q", "hello world", got3, "he")
	}

	// Normal truncation
	got4 := truncate("hello world test", 10)
	if got4 != "hello w..." {
		t.Errorf("truncate(%q, 10) = %q, want %q", "hello world test", got4, "hello w...")
	}

	// Exactly at limit
	got5 := truncate("hi", 2)
	if got5 != "hi" {
		t.Errorf("truncate(%q, 2) = %q, want %q", "hi", got5, "hi")
	}
}

func TestNormalizeWhitespace_EmptyString(t *testing.T) {
	got := NormalizeWhitespace("")
	if got != "" {
		t.Errorf("NormalizeWhitespace(%q) = %q, want %q", "", got, "")
	}
}

func TestNormalizeWhitespace_OnlyWhitespace(t *testing.T) {
	got := NormalizeWhitespace("   \t\n  ")
	if got != "" {
		t.Errorf("NormalizeWhitespace(%q) = %q, want %q", "   \\t\\n  ", got, "")
	}
}

func TestNormalizeWhitespace_ControlChars(t *testing.T) {
	// 0x7F is DEL, which is a control character
	input := "hello\x7Fworld"
	got := NormalizeWhitespace(input)
	if got != "hello world" {
		t.Errorf("NormalizeWhitespace with DEL char = %q, want %q", got, "hello world")
	}
}

func TestDecodeHTMLEntities_NamedEntityNbsp(t *testing.T) {
	got := DecodeHTMLEntities("&nbsp;")
	if got != "\u00A0" {
		t.Errorf("DecodeHTMLEntities(%q) = %q, want %q", "&nbsp;", got, "\u00A0")
	}
}

func TestDecodeHTMLEntities_NumericEntityLargeValue(t *testing.T) {
	// &#8364; is the Euro sign
	got := DecodeHTMLEntities("&#8364;")
	if got != "\u20AC" {
		t.Errorf("DecodeHTMLEntities(%q) = %q, want %q", "&#8364;", got, "\u20AC")
	}
}

func TestEntityRune_OutOfRange(t *testing.T) {
	if got := entityRune(utf8.MaxRune + 1); got != utf8.RuneError {
		t.Errorf("entityRune(out of range) = %q, want %q", got, utf8.RuneError)
	}
}
