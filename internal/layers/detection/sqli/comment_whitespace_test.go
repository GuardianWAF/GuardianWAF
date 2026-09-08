package sqli

import "testing"

// Regression: checkCommentAfterString's between-tokens scan broke on
// TokenWhitespace (it was not in the allow-continue list), so the canonical
// auth-bypass "admin') -- xyz" — with a space before the comment — tokenized
// as [Other(admin), StringLiteral('), ParenClose, Whitespace, Comment] and
// yielded ZERO findings. The tight shape only fired without the space
// ("admin')-- xyz"), and the documented loose example ("it's -- great",
// patterns.go's own doc comment) never produced its 35-score log-only signal
// either.
func TestDetectCommentAfterWhitespaceGap(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		minScore int
	}{
		{"canonical auth bypass with space", "admin') -- xyz", 60},
		{"documented loose apostrophe example", "it's -- great", 35},
		{"control: no space before comment", "admin')-- xyz", 60},
	}
	for _, tc := range cases {
		findings := Detect(tc.input, "query")
		best := 0
		for _, f := range findings {
			if f.Score > best {
				best = f.Score
			}
		}
		if best < tc.minScore {
			t.Errorf("FAIL: %s: Detect(%q) best score = %d, want >= %d",
				tc.name, tc.input, best, tc.minScore)
		}
	}
}
