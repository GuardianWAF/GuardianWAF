package engine

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Regression tests: malformed query strings must still have credentials
// scrubbed. redactSensitiveQueryParams used to return the raw query
// unredacted whenever url.ParseQuery reported an error — which happens for
// any pair containing a semicolon separator or any invalid percent-escape,
// i.e. exactly the inputs attackers send — leaking token=/password=/
// api_key= credentials into stored events. The sibling redactSensitiveURL
// already fell back to the regex scrubber (redactSensitiveEvidence) on
// parse failure; the query path now does the same.

func TestRedactSensitiveQueryParamsMalformedSemicolon(t *testing.T) {
	result := redactSensitiveQueryParams("a=1;b=2&token=SECRET")
	if strings.Contains(result, "SECRET") {
		t.Fatalf("FAIL: credential leaked through malformed (semicolon) query: %q", result)
	}
	if !strings.Contains(result, "token=") {
		t.Fatalf("FAIL: sensitive parameter name itself was dropped: %q", result)
	}
}

func TestRedactSensitiveQueryParamsMalformedEscape(t *testing.T) {
	result := redactSensitiveQueryParams("id=1%zz&password=hunter2")
	if strings.Contains(result, "hunter2") {
		t.Fatalf("FAIL: credential leaked through malformed (invalid escape) query: %q", result)
	}
}

// Production path: NewEvent must not store unredacted credentials from a
// malformed query.
func TestNewEventRedactsCredentialsInMalformedQuery(t *testing.T) {
	req := &http.Request{URL: &url.URL{RawQuery: "id=1%zz&api_key=XYZ123"}}
	ctx := &RequestContext{
		Request:   req,
		Method:    "GET",
		Path:      "/x",
		StartTime: time.Now(),
	}
	ev := NewEvent(ctx, http.StatusOK)
	if strings.Contains(ev.Query, "XYZ123") {
		t.Fatalf("FAIL: NewEvent stored unredacted api_key from malformed query: %q", ev.Query)
	}
}

// Boundaries: valid queries keep the existing ParseQuery-based redaction;
// '='-less strings are untouched; non-credential content in malformed
// queries is preserved (evidence fidelity).
func TestRedactSensitiveQueryParamsBoundaries(t *testing.T) {
	if got := redactSensitiveQueryParams("token=SECRET&x=1"); strings.Contains(got, "SECRET") {
		t.Fatalf("FAIL: valid query credential not redacted: %q", got)
	}
	if got := redactSensitiveQueryParams("justastring"); got != "justastring" {
		t.Fatalf("FAIL: '='-less query modified: %q", got)
	}
	if got := redactSensitiveQueryParams("a=1;b=2"); got != "a=1;b=2" {
		t.Fatalf("FAIL: non-credential malformed query altered: %q", got)
	}
}
