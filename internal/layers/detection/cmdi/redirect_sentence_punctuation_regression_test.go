package cmdi

import "testing"

// Regression: a sentence-final period after '>' ("Coffee > tea.") was read as a
// filename extension, scoring prose as output redirection (45) and, with any
// second weak signal, blocking profile bios and comments.
func TestRedirectionTargetIgnoresSentencePunctuation(t *testing.T) {
	for _, tc := range []struct {
		rest string
		want bool
	}{
		{" tea.", false},
		{" tea!", false},
		{" the rest...", false},
		{" out.txt", true},
		{"/tmp/x", true},
		{" x.sh;", true},
		{"&1", true},
	} {
		if got := redirectionTargetLooksLikeFileOrFD(tc.rest); got != tc.want {
			t.Errorf("redirectionTargetLooksLikeFileOrFD(%q) = %v, want %v", tc.rest, got, tc.want)
		}
	}
}
