package sqli

import "testing"

func detectScore(s string) int {
	total := 0
	for _, f := range Detect(s, "query") {
		total += f.Score
	}
	return total
}

// Regression: a quote breakout followed by boolean logic and a comment or a
// quote-balancing comparison scored below the block threshold unless it was
// the exact "1=1" tautology.
func TestQuoteBreakoutLogicBlocks(t *testing.T) {
	for _, s := range []string{
		"' OR 1 --", "' OR true --", "' AND 1=2 --", "' HAVING 1=1 --",
		"'||1=1 --", "') OR ('1'='1", "' OR ''='", `" OR ""="`,
		"' GROUP BY users.id HAVING 1=1 --", "' ORDER BY 3--",
	} {
		if got := detectScore(s); got < 50 {
			t.Errorf("%q scored %d, want >= 50", s, got)
		}
	}
}

// Natural text with apostrophes must stay below the block threshold.
func TestQuoteBreakoutLogicIgnoresProse(t *testing.T) {
	for _, s := range []string{
		"it's -- great", "O'Brien or Smith", "the 90' and 80's", "rock 'n' roll and more",
		`I'm 5'10" and 170 lbs`, "don't stop me now or ever",
		"exec office chair", "exec summary template",
	} {
		if got := detectScore(s); got >= 50 {
			t.Errorf("%q scored %d, want < 50", s, got)
		}
	}
}

// EXEC keeps blocking when followed by something executable.
func TestExecTargetsStillBlock(t *testing.T) {
	for _, s := range []string{"EXEC xp_cmdshell 'dir'", "exec master..xp_cmdshell 'whoami'", "EXEC @sql", "exec dbo.GetUsers", "exec('select 1')"} {
		if got := detectScore(s); got < 50 {
			t.Errorf("%q scored %d, want >= 50", s, got)
		}
	}
}
