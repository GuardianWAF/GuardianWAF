package sqli

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// SQL Server parses `EXEC 'cmd'` and `EXEC('cmd')` as the same statement — the
// paren only delimits the argument list. checkExecString's lookahead used to
// `break` on TokenParenOpen, so the paren-wrapped spelling never reached the
// 80-score "EXEC/EXECUTE with dynamic argument" finding and scored only the
// isolated-keyword crumbs (10), far below the default block_threshold of 50.
// The bare spelling is the one sqlmap and friends emit, so the evasion was
// free: append two characters to a detection and it stops firing.
const execArgDesc = "EXEC/EXECUTE with dynamic argument"

func sumExecScores(fs []engine.Finding) int {
	total := 0
	for _, f := range fs {
		total += f.Score
	}
	return total
}

func hasExecArgFinding(fs []engine.Finding) bool {
	for _, f := range fs {
		if f.Description == execArgDesc {
			return true
		}
	}
	return false
}

func TestDetect_ExecParenArgumentDetected(t *testing.T) {
	// Control: the bare spelling the check was written for. If this stops
	// firing the test cannot tell the two shapes apart and proves nothing.
	bare := Detect("EXEC 'xp_cmdshell'", "query")
	if !hasExecArgFinding(bare) {
		t.Fatalf("CONTROL BROKEN: bare EXEC 'cmd' no longer reports %q", execArgDesc)
	}

	// Subjects: the paren-wrapped spellings must reach the same classification.
	for _, in := range []string{
		"EXEC('xp_cmdshell')",
		"EXEC ('xp_cmdshell')",
		"EXECUTE('sp_who')",
	} {
		got := Detect(in, "query")
		if !hasExecArgFinding(got) {
			t.Errorf("FAIL: %q scored %d and did not report %q; the opening "+
				"paren must be stepped over, not treated as a terminator",
				in, sumExecScores(got), execArgDesc)
		}
	}
}

// Boundary: the paren form is still detected when an obfuscating comment sits
// between EXEC and the paren, and when a close paren precedes the argument.
// Both exercise the lookahead continuing past a non-literal token rather than
// stopping at the first one.
func TestDetect_ExecParenArgumentWithInterveningTokens(t *testing.T) {
	for _, in := range []string{
		"EXEC/**/('xp_cmdshell')", // comment between EXEC and paren
		"EXEC(('xp_cmdshell'))",   // nested parens
		"EXEC('a'+'b')",           // concatenated argument
	} {
		if got := Detect(in, "query"); !hasExecArgFinding(got) {
			t.Errorf("FAIL: %q scored %d and did not report %q", in, sumExecScores(got), execArgDesc)
		}
	}
}

// Precision control: stepping over the paren must not turn a bare EXEC that is
// followed by nothing usable into a finding, and must not fire for a word that
// merely contains "exec" (the tokenizer classifies those as a single Other
// token, not TokenKeyword EXEC).
func TestDetect_ExecNoArgumentDoesNotReport(t *testing.T) {
	for _, in := range []string{
		"EXEC",
		"EXEC()",
		"execute", // lowercase word, no paren-wrapped argument
	} {
		if got := Detect(in, "query"); hasExecArgFinding(got) {
			t.Errorf("FAIL: %q reported %q but has no dynamic argument", in, execArgDesc)
		}
	}
}
