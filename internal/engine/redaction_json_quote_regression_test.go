package engine

// Regression: evidence redaction must see JSON-quoted credential keys.
//
// redactSensitiveEvidence is the only guard applied to attacker-controlled
// evidence before it is persisted (NewEvent -> redactFindings, buildEvent ->
// redactFindings, and the panic-path event). Its key/value regex required the
// key to be followed directly by optional whitespace and then ':' or '='. In a
// JSON body the key is itself quoted — "password":"value" — so a closing quote
// sits between the key and the ':' that \s* cannot consume, and the quoted form
// never matched. Request bodies are overwhelmingly JSON, and detection
// detectors copy raw request content into MatchedValue (xss/patterns.go:332,
// sqli/patterns.go:120), so credentials arrived in events verbatim and were
// shown in the dashboard.
//
// The contract this pins is the one internal/engine/redaction_leak_test.go
// already states: credentials must not be stored in events.

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// placeholder is a synthetic marker, not credential material. Assertions look
// for it by exact string so a redaction that merely altered formatting still
// fails the test rather than passing by accident.
const jsonCredPlaceholder = "PLACEHOLDER_NOT_A_REAL_SECRET"

func jsonEvidenceShape(key, value string) string {
	q := string(rune(34)) // '"'
	c := string(rune(58)) // ':'
	return q + key + q + c + q + value + q
}

// TestRedactSensitiveEvidenceQuotedKeys is the exact trigger from the proof,
// driven through the real NewEvent production constructor.
func TestRedactSensitiveEvidenceQuotedKeys(t *testing.T) {
	keys := []string{
		"password", "passwd", "api_key", "apikey", "token", "access_token",
		"refresh_token", "id_token", "client_secret", "secret", "jwt",
		"authorization", "cookie", "session_id", "csrf_token", "xsrf_token",
	}

	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			evidence := jsonEvidenceShape(key, jsonCredPlaceholder)

			acc := &ScoreAccumulator{}
			acc.Add(&Finding{
				DetectorName: "xss",
				Category:     "xss",
				Severity:     SeverityHigh,
				Score:        90,
				MatchedValue: evidence,
				Location:     "body",
			})

			ctx := &RequestContext{
				Method:      http.MethodPost,
				Path:        "/login",
				StartTime:   time.Now(),
				Accumulator: acc,
			}
			ev := NewEvent(ctx, http.StatusOK)

			for _, f := range ev.Findings {
				if strings.Contains(f.MatchedValue, jsonCredPlaceholder) {
					t.Fatalf("NewEvent stored an unredacted JSON-shaped credential "+
						"for key %q: %q", key, f.MatchedValue)
				}
			}
		})
	}
}

// TestRedactSensitiveEvidenceQuotedKeyVariants covers the separator and value
// spellings JSON allows, so a fix tailored to one exact string is not enough.
func TestRedactSensitiveEvidenceQuotedKeyVariants(t *testing.T) {
	q := string(rune(34)) // '"'
	c := string(rune(58)) // ':'
	e := string(rune(61)) // '='

	variants := []struct {
		name     string
		evidence string
	}{
		{"json object", "{" + q + "password" + q + c + q + jsonCredPlaceholder + q + "}"},
		{"json spaced value", q + "password" + q + c + " " + q + jsonCredPlaceholder + q},
		{"quoted key equals form", q + "password" + q + " " + e + " " + jsonCredPlaceholder},
		{"single-quoted key", "'password'" + c + q + jsonCredPlaceholder + q},
		{"nested in json array", "[" + q + "token" + q + c + q + jsonCredPlaceholder + q + "]"},
		{"key with space before colon", q + "api_key" + q + "  :  " + q + jsonCredPlaceholder + q},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			out := redactSensitiveEvidence(v.evidence)
			if strings.Contains(out, jsonCredPlaceholder) {
				t.Fatalf("redactSensitiveEvidence left the credential in place for %q: %q",
					v.name, out)
			}
		})
	}
}

// TestRedactSensitiveEvidenceBareFormStillRedacted is the control: the fix must
// not regress the pre-existing bare key=value and header forms that the
// original regex already handled.
func TestRedactSensitiveEvidenceBareFormStillRedacted(t *testing.T) {
	cases := []string{
		"password=" + jsonCredPlaceholder,
		"api_key=" + jsonCredPlaceholder,
		"token: " + jsonCredPlaceholder,
		"Authorization: " + jsonCredPlaceholder,
		"client_secret=" + jsonCredPlaceholder,
		"user=bob&password=" + jsonCredPlaceholder, // query form
	}

	for _, in := range cases {
		out := redactSensitiveEvidence(in)
		if strings.Contains(out, jsonCredPlaceholder) {
			t.Errorf("bare-form credential not redacted: in=%q out=%q", in, out)
		}
	}
}

// TestRedactSensitiveEvidencePreservesKeyNames guards evidence fidelity: the
// redacted output must still name the parameter, so an operator can see WHICH
// credential was present rather than an opaque string.
func TestRedactSensitiveEvidencePreservesKeyNames(t *testing.T) {
	out := redactSensitiveEvidence(jsonEvidenceShape("api_key", jsonCredPlaceholder))
	if !strings.Contains(out, "api_key") {
		t.Errorf("redaction dropped the parameter name: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("redaction did not mark the value: %q", out)
	}
}

// TestRedactSensitiveEvidenceLeavesNonSensitiveIntact is the fidelity control
// in the other direction: ordinary evidence must survive untouched, or
// redaction would destroy the forensic value of every event.
func TestRedactSensitiveEvidenceLeavesNonSensitiveIntact(t *testing.T) {
	intact := []string{
		"username=bob",
		"SELECT * FROM users WHERE id=1",
		"/api/v1/users/42",
		"q=hello+world",
		"the secret of the garden", // "secret" with no separator — not a key/value pair
	}

	for _, in := range intact {
		if out := redactSensitiveEvidence(in); out != in {
			t.Errorf("non-sensitive evidence altered: in=%q out=%q", in, out)
		}
	}
}

// TestRedactFindingsJSONEvidence pins the boundary the pipeline actually uses:
// redactFindings over a mixed batch, where only the credential-bearing finding
// may change.
func TestRedactFindingsJSONEvidence(t *testing.T) {
	findings := []Finding{
		{DetectorName: "xss", Score: 90, MatchedValue: jsonEvidenceShape("password", jsonCredPlaceholder)},
		{DetectorName: "sqli", Score: 90, MatchedValue: "id=1 OR 1=1"},
	}

	out := redactFindings(findings)
	if strings.Contains(out[0].MatchedValue, jsonCredPlaceholder) {
		t.Errorf("redactFindings left a JSON credential in place: %q", out[0].MatchedValue)
	}
	if out[1].MatchedValue != "id=1 OR 1=1" {
		t.Errorf("redactFindings altered non-credential evidence: %q", out[1].MatchedValue)
	}
	// The caller's own slice must be left untouched: redactFindings builds a
	// new slice, so redaction must not rewrite the input in place. The input
	// therefore still carries its ORIGINAL (unredacted) value.
	if !strings.Contains(findings[0].MatchedValue, jsonCredPlaceholder) {
		t.Errorf("redactFindings mutated its input slice in place — the caller's "+
			"finding was rewritten: %q", findings[0].MatchedValue)
	}
	if out[0].MatchedValue == findings[0].MatchedValue {
		t.Errorf("redactFindings returned an aliased slice: the redacted copy shares " +
			"storage with the caller's input")
	}
}
