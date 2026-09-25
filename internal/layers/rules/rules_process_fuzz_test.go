package rules

// FuzzRulesProcess exercises the rules layer's Process against hostile rule
// sets and request shapes. The layer must never panic and must always return
// a valid engine action with a non-negative score. Rule inputs are JSON
// arrays; structurally invalid input is skipped (the dashboard's mapToRule
// already guards type shape — round 2026-09-25-round9-maptorule).

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func FuzzRulesProcess(f *testing.F) {
	seeds := []string{
		`[]`,
		`[{"id":"r1","enabled":true,"action":"block","conditions":[{"field":"path","op":"equals","value":"/x"}]}]`,
		`[{"id":"w1","enabled":true,"action":"pass","priority":1,"conditions":[{"field":"header:X-Probe","op":"matches","value":"."}]},{"id":"b1","enabled":true,"action":"block","priority":2,"conditions":[{"field":"path","op":"equals","value":"/probe"}]}]`,
		`[{"id":"r2","enabled":true,"action":"challenge","score":30,"conditions":[{"field":"cookie:session","op":"contains","value":"admin"},{"field":"user_agent","op":"starts_with","value":"curl"}]}]`,
		`[{"id":"r3","enabled":true,"action":"log","conditions":[{"field":"ip","op":"in_cidr","value":"10.0.0.0/8"}]}]`,
		`[{"id":"r4","enabled":true,"action":"block","score":90,"conditions":[{"field":"body_size","op":"greater_than","value":5},{"field":"country","op":"in","value":["DE","AT"]},{"field":"score","op":"less_than","value":"99"}]}]`,
		`[{"id":"r5","enabled":true,"action":"log","conditions":[{"field":"header:X-Probe","op":"matches","value":"(((((((a)))))))"},{"field":"host","op":"not_in","value":"example.com"},{"field":"query","op":"not_contains","value":"q"}]}]`,
		`[{"id":"r6","enabled":false,"action":"weird","priority":-5,"conditions":[{"field":"unknown_field","op":"unknown_op","value":{"nested":[1,2,3]}}]}]`,
	}
	for _, s := range seeds {
		f.Add([]byte(s), "/probe", "GET", "probe-ua", "probe-value", "sess=1", "192.0.2.7")
	}

	f.Fuzz(func(t *testing.T, data []byte, path, method, ua, headerVal, cookieVal, clientIP string) {
		if len(data) > 4096 || len(path) > 256 || len(method) > 16 ||
			len(ua) > 256 || len(headerVal) > 256 || len(cookieVal) > 256 || len(clientIP) > 64 {
			return
		}
		var rs []Rule
		if err := json.Unmarshal(data, &rs); err != nil {
			return
		}
		layer := NewLayer(&Config{Enabled: true, Rules: rs}, nil)
		ctx := &engine.RequestContext{
			Path:     path,
			Method:   method,
			ClientIP: net.ParseIP(clientIP),
			Headers: map[string][]string{
				"X-Probe":    {headerVal},
				"User-Agent": {ua},
			},
			Cookies:     map[string][]string{"session": {cookieVal}},
			Accumulator: engine.NewScoreAccumulator(2),
		}

		res := layer.Process(ctx)

		switch res.Action {
		case engine.ActionPass, engine.ActionLog, engine.ActionChallenge, engine.ActionBlock:
		default:
			t.Fatalf("FAIL: invalid layer action %v", res.Action)
		}
		if res.Score < 0 {
			t.Fatalf("FAIL: negative layer score %d", res.Score)
		}
	})
}
