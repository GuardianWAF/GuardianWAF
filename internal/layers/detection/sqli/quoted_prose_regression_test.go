package sqli

import "testing"

func totalScore(input string) int {
	total := 0
	for _, f := range Detect(input, "body") {
		total += f.Score
	}
	return total
}

// Regression: English prose with an apostrophe or quoted word, "and"/"or",
// and " -- " (a common em-dash substitute) scored 65-150 and was blocked:
// a quote closing a quoted word read as a breakout quote, and two weak
// signals (string before AND, comment after a string) added up.
func TestQuotedProseWithDashesNotBlocked(t *testing.T) {
	for _, s := range []string{
		"Don't say 'no' and leave -- please",
		"I said 'yes' and he said 'no' -- typical",
		"It's 'fine' or so they say -- whatever",
		"the 'red' and 'blue' options -- pick one",
		"Mark's 'draft' and 'final' versions -- both attached",
		"you're 'it' and I'm not -- tag!",
		"we'll go 'early' and stay late",
	} {
		if got := totalScore(s); got >= 50 {
			t.Errorf("%q scored %d, want below the block threshold (50)", s, got)
		}
	}
}

// The same shapes with an SQL operand stay above the block threshold.
func TestQuoteBreakoutAttacksStillBlocked(t *testing.T) {
	for _, s := range []string{
		"admin' and 1=1 --",
		"x' or 1 --",
		"x' or true --",
		"x' and sleep(5) --",
		"x' and 'a'='a' --",
		`x' or "a"="a" --`,
		"' OR 'a'='a",
		"' AND SUBSTRING(username,1,1)='a' --",
		"admin'--",
		"admin')--",
	} {
		if got := totalScore(s); got < 50 {
			t.Errorf("%q scored %d, want at least the block threshold (50)", s, got)
		}
	}
}
