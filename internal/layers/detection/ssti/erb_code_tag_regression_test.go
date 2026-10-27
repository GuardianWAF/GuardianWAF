package ssti

// Regression: the ERB/JSP CODE tag "<% ... %>" was not covered by the SSTI
// detector, while its sibling — the ERB OUTPUT tag "<%= ... %>" — was.
//
// The construct pair is handled on one side only:
//   - `delimiters` listed "<%=" (the output tag) but not "<%" (the code tag
//     used by ERB for side-effecting expressions and by JSP scriptlets), so an
//     expression inside a code tag was neither probed for the arithmetic
//     signature nor checked for engine-internal access.
//   - `exploitGadgets` listed "<%= system" / "<%=system" but not the code-tag
//     spellings "<% system" / "<%system", so the ERB RCE payload in the code
//     tag form produced ZERO findings.
//
// Effect: "<% system('id') %>" — the spelling real ERB payloads use — passed
// the SSTI detector entirely, while "<%= system('id') %>" was reported at 85
// (above the default block threshold of 50). Same asymmetry family as the
// "{%include" no-space directive fix, different construct.
//
// The tests below assert the contract on the production entry point (Detect,
// called by Detector.Process): the code tag is reported like its output-tag
// twin, the twin keeps working, and benign "<%" prose is not flagged.

import "testing"

// codeTagPayload is the ERB code-tag RCE payload — the exact trigger.
const codeTagPayload = "<% system('id') %>"

// outputTagPayload is the ERB output-tag twin — the control that was already
// detected before the fix.
const outputTagPayload = "<%= system('id') %>"

func TestDetect_ERBCodeTagDetected(t *testing.T) {
	findings := Detect(codeTagPayload, "query")
	if len(findings) == 0 {
		t.Fatalf("FAIL: Detect(%q) reported nothing — the ERB code tag \"<%%\" is not covered while its "+
			"sibling \"<%%=\" is (delimiters + exploitGadgets \"<%%= system\"), so an ERB template-injection "+
			"payload in the code-tag form passes the SSTI detector entirely", codeTagPayload)
	}
	total := 0
	for _, f := range findings {
		total += f.Score
	}
	if total < 50 {
		t.Fatalf("FAIL: Detect(%q) scored %d, below the default block threshold of 50", codeTagPayload, total)
	}
}

// The code-tag probe twin of the covered "<%= 7*7 %>" must be reported too.
func TestDetect_ERBCodeTagProbeDetected(t *testing.T) {
	for _, payload := range []string{
		"<% 7*7 %>",
		"<% config.items() %>", // engine-internal access inside a code tag
	} {
		if findings := Detect(payload, "query"); len(findings) == 0 {
			t.Errorf("FAIL: Detect(%q) reported nothing — the code-tag expression is not covered", payload)
		}
	}
}

// The output-tag twin must keep being reported (it was detected before the
// fix; the fix must not disturb it).
func TestDetect_ERBOutputTagStillDetected(t *testing.T) {
	if findings := Detect(outputTagPayload, "query"); len(findings) == 0 {
		t.Fatalf("FAIL: Detect(%q) reported nothing — the already-covered output-tag spelling regressed",
			outputTagPayload)
	}
}

// Guard against over-matching: a "<%" that is not a template expression must
// stay unreported.
func TestDetect_BenignAnglePercentTextClean(t *testing.T) {
	for _, benign := range []string{
		"less than 5 <% 10 percent of the total",
		"5<%10",
		"a < b and c > d",
		"100% < 200",
	} {
		if findings := Detect(benign, "query"); len(findings) != 0 {
			t.Errorf("FAIL: benign input %q produced %d finding(s) — the fix must not flag every \"<%%\"",
				benign, len(findings))
		}
	}
}
