package sanitizer

import (
	"math/rand/v2"
	"testing"
)

// The fast paths in NormalizeWhitespace and CanonicalizePath skip work only
// when the full transformation would return its input unchanged.
func TestNormalizeFastPathsMatchFullTransform(t *testing.T) {
	alphabet := []byte("ab. /\\\t\n\x00\x7f")
	rng := rand.New(rand.NewPCG(1, 2))
	for range 200000 {
		b := make([]byte, rng.IntN(8))
		for i := range b {
			b[i] = alphabet[rng.IntN(len(alphabet))]
		}
		s := string(b)
		if got, want := NormalizeWhitespace(s), collapseWhitespace(s); got != want {
			t.Fatalf("NormalizeWhitespace(%q) = %q, full transform %q", s, got, want)
		}
		if got, want := CanonicalizePath(s), canonicalizePath(s); got != want {
			t.Fatalf("CanonicalizePath(%q) = %q, full transform %q", s, got, want)
		}
	}
}

func FuzzNormalizeFastPaths(f *testing.F) {
	for _, s := range []string{"", " ", "a b", "a  b", " a", "a ", "a\tb", "a.", "..", "a/b", `a\b`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := NormalizeWhitespace(s), collapseWhitespace(s); got != want {
			t.Fatalf("NormalizeWhitespace(%q) = %q, full transform %q", s, got, want)
		}
		if got, want := CanonicalizePath(s), canonicalizePath(s); got != want {
			t.Fatalf("CanonicalizePath(%q) = %q, full transform %q", s, got, want)
		}
	})
}
