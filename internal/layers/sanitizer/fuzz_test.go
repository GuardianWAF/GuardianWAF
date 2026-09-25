package sanitizer

import (
	"strings"
	"testing"
)

// Strengthened round-19 properties (on top of the original crash-freedom):
// every helper is monotone-shrinking or stable (decode 3->1 / 6-><=4 bytes,
// entity decode shrinks, canonicalize joins <= parts, whitespace collapses),
// RemoveNullBytes never emits NUL, CanonicalizePath never emits a ".."
// segment and preserves absolute-root, NormalizeWhitespace trims and never
// doubles spaces.

func hasDotDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

func FuzzNormalizeAll(f *testing.F) {
	f.Add("%27%20OR%201%3D1")
	f.Add("normal")
	f.Add("%2527")
	f.Add("")
	f.Add("/hello/world")
	f.Add("/../../../etc/passwd")
	f.Add("%252e%252e%252f")
	f.Add("&lt;script&gt;alert(1)&lt;/script&gt;")
	f.Add("%00null%00byte")
	f.Add("hello\\0world")
	f.Add("C:\\Windows\\System32")
	f.Add("\uff53\uff45\uff4c\uff45\uff43\uff54")
	f.Add("   lots   of   spaces   ")
	f.Add("%u0027%u0020OR%u00201=1")
	f.Add("&#x3c;script&#x3e;")
	// Round-19 composite edges.
	f.Add("..")
	f.Add("/..")
	f.Add("a/../../b")
	f.Add("..\\..\\windows")
	f.Add("%2e%2e%2f%2e%2e%2fetc%2fpasswd")
	f.Add("/a/b/../../../../../c")
	f.Add("&#x2e;&#x2e;/")

	f.Fuzz(func(t *testing.T, input string) {
		// NormalizeAll should not panic and never grow the input.
		result := NormalizeAll(input)
		if len(result) > len(input) {
			t.Fatalf("NormalizeAll grew input %d -> %d (%q -> %q)", len(input), len(result), input, result)
		}

		decoded := DecodeURLRecursive(input)
		if len(decoded) > len(input) {
			t.Fatalf("DecodeURLRecursive grew input %d -> %d", len(input), len(decoded))
		}

		cleaned := RemoveNullBytes(input)
		if strings.Contains(cleaned, "\x00") {
			t.Fatalf("RemoveNullBytes left a NUL byte: %q -> %q", input, cleaned)
		}
		if len(cleaned) > len(input) {
			t.Fatalf("RemoveNullBytes grew input %d -> %d", len(input), len(cleaned))
		}

		canon := CanonicalizePath(input)
		if hasDotDotSegment(canon) {
			t.Fatalf("CanonicalizePath emitted a .. segment: %q -> %q", input, canon)
		}
		if strings.HasPrefix(input, "/") && !strings.HasPrefix(canon, "/") {
			t.Fatalf("CanonicalizePath lost absolute root: %q -> %q", input, canon)
		}

		uni := NormalizeUnicode(input)
		if len(uni) > len(input) {
			t.Fatalf("NormalizeUnicode grew input %d -> %d", len(input), len(uni))
		}

		html := DecodeHTMLEntities(input)
		if len(html) > len(input) {
			t.Fatalf("DecodeHTMLEntities grew input %d -> %d (%q -> %q)", len(input), len(html), input, html)
		}

		ws := NormalizeWhitespace(input)
		if strings.HasPrefix(ws, " ") || strings.HasSuffix(ws, " ") {
			t.Fatalf("NormalizeWhitespace left edge space: %q -> %q", input, ws)
		}
		if strings.Contains(ws, "  ") {
			t.Fatalf("NormalizeWhitespace doubled spaces: %q -> %q", input, ws)
		}
	})
}

func FuzzDecodeURLRecursive(f *testing.F) {
	f.Add("%27")
	f.Add("%2527")
	f.Add("%252527")
	f.Add("normal text")
	f.Add("")
	f.Add("%")
	f.Add("%%")
	f.Add("%zz")
	f.Add("%u0041")
	f.Add("%uffff")
	f.Add("100%25 complete")

	f.Fuzz(func(t *testing.T, input string) {
		result := DecodeURLRecursive(input)
		if len(result) > len(input) {
			t.Fatalf("DecodeURLRecursive grew input %d -> %d (%q -> %q)", len(input), len(result), input, result)
		}
	})
}

func FuzzCanonicalizePath(f *testing.F) {
	f.Add("/a/b/c")
	f.Add("/../../../etc/passwd")
	f.Add("/a/./b/../c")
	f.Add("")
	f.Add("/")
	f.Add("//")
	f.Add("/a//b///c")
	f.Add("\\a\\b\\c")
	f.Add("/a/b/..")
	f.Add("a/b/c")
	f.Add("..")
	f.Add("/..")
	f.Add("a/../../b")

	f.Fuzz(func(t *testing.T, input string) {
		result := CanonicalizePath(input)
		if hasDotDotSegment(result) {
			t.Fatalf("CanonicalizePath emitted a .. segment: %q -> %q", input, result)
		}
		if strings.HasPrefix(input, "/") && !strings.HasPrefix(result, "/") {
			t.Fatalf("CanonicalizePath lost absolute root: %q -> %q", input, result)
		}
	})
}
