package crs

// FuzzCrsLayerProcess exercises the CRS layer's request path —
// Process → createTransaction → evaluateRule → expandMacros/applyVarActions
// and the operator evaluators — against hostile parsed rulesets and hostile
// request contexts. The layer must never panic and must always return Pass
// or Block with a non-negative score. Rule input is SecRule directive text
// (structurally invalid input is skipped — the parser's LoadError contract
// is fuzzed separately by FuzzCrsParse).

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func FuzzCrsLayerProcess(f *testing.F) {
	seeds := []string{
		`SecRule REQUEST_URI "@contains /" "id:1,deny"`,
		`SecRule ARGS "@rx attack" "id:2,deny"`,
		`SecRule TX:anomaly_score "@ge %{tx.inbound_anomaly_score_threshold}" "id:3,deny"`,
		`SecRule !ARGS:password "@contains pass" "id:4,deny"`,
		`SecRule &ARGS "@ge 3" "id:5,deny"`,
		`SecAction "id:6,phase:1,setvar:tx.anomaly_score=+5,chain"`,
		`SecRule ARGS "@validateByteRange 1-255" "id:7,deny,msg:\"a, b\""`,
		`SecRule REQUEST_METHOD "@streq POST" "id:8,skip:1,deny"`,
		"SecRule ARGS \"@rx x\" \"id:9,deny,chain\"\nSecRule REQUEST_METHOD \"@streq POST\" \"id:10\"",
		`SecRule 0 0 "`,
	}
	for _, s := range seeds {
		f.Add(s, "POST", "/login?user=me&id=7", "X-Probe", "probe-value", "user=me&pw=secret", "192.0.2.7")
	}

	f.Fuzz(func(t *testing.T, ruleText, method, target, headerName, headerVal, body, ip string) {
		if len(ruleText) > 4096 || len(target) > 512 || len(body) > 2048 ||
			len(method) > 16 || len(headerName) > 64 || len(headerVal) > 256 || len(ip) > 64 {
			return
		}
		// The request is constructed DIRECTLY below (not via
		// httptest.NewRequest, which re-parses a synthesized request line
		// for URL-ish targets and panics on malformed fuzz strings — two
		// corpus entries proved it). Struct construction cannot panic, so
		// no input needs skipping: the CRS layer sees exactly the strings
		// the fuzzer produces, like the real ctx builder.
		u, uerr := url.Parse(target)
		if uerr != nil || u == nil {
			return
		}

		layer := NewLayer(&Config{Enabled: true})
		p := NewParser()
		parsed, err := p.ParseFile(ruleText)
		if err == nil {
			layer.rules = parsed
			layer.buildRuleMaps()
		}

		req := &http.Request{
			Method:        method,
			URL:           u,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        http.Header{},
			Host:          "crs-fuzz.invalid",
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
		}
		req.Header.Set(headerName, headerVal)
		ctx := &engine.RequestContext{
			Method:      method,
			Path:        target,
			ClientIP:    net.ParseIP(ip),
			Headers:     req.Header,
			Body:        []byte(body),
			BodyString:  body,
			Request:     req,
			Accumulator: engine.NewScoreAccumulator(2),
		}

		res := layer.Process(ctx)

		switch res.Action {
		case engine.ActionPass, engine.ActionBlock:
		default:
			t.Fatalf("FAIL: invalid action %v (CRS layer returns only Pass or Block)", res.Action)
		}
		if res.Score < 0 {
			t.Fatalf("FAIL: negative score %d", res.Score)
		}
	})
}
