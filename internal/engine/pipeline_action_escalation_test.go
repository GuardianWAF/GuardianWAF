package engine

import "testing"

// escalationStubLayer returns a fixed LayerResult. It is not a Detector, so
// pipeline exclusions never skip it.
type escalationStubLayer struct {
	name   string
	action Action
}

func (l *escalationStubLayer) Name() string { return l.name }
func (l *escalationStubLayer) Order() int   { return 0 }
func (l *escalationStubLayer) Process(_ *RequestContext) LayerResult {
	return LayerResult{Action: l.action}
}

func escalationLayer(name string, action Action, order int) OrderedLayer {
	return OrderedLayer{Layer: &escalationStubLayer{name: name, action: action}, Order: order}
}

// TestPipeline_ActionEscalation pins the monotonic action escalation
// Pass < Log < Challenge < Block.
//
// The old guards were asymmetric — "ActionLog: anything but Block becomes
// Log" and "ActionChallenge: only over Pass" — so a Challenge was cancelled
// by a Log in EITHER order: a later Log overwrote an earlier Challenge, and
// an earlier Log suppressed a later one. Detection layers (Order 400) log
// every sub-threshold score > 0 and run before the JS-challenge layer
// (Order 430), so any request with a minor sub-threshold signal silently
// skipped the challenge — a bot-mitigation bypass. Custom rules (Order 150)
// and botdetect (Order 500) can also emit Challenge.
func TestPipeline_ActionEscalation(t *testing.T) {
	cases := []struct {
		name  string
		want  Action
		shift []OrderedLayer
	}{
		{"log then challenge stays challenge", ActionChallenge, []OrderedLayer{
			escalationLayer("logger", ActionLog, 400),
			escalationLayer("challenge", ActionChallenge, 430),
		}},
		{"challenge then log stays challenge", ActionChallenge, []OrderedLayer{
			escalationLayer("challenge", ActionChallenge, 430),
			escalationLayer("logger", ActionLog, 500),
		}},
		{"challenge alone", ActionChallenge, []OrderedLayer{
			escalationLayer("challenge", ActionChallenge, 430),
		}},
		{"log alone", ActionLog, []OrderedLayer{
			escalationLayer("logger", ActionLog, 400),
		}},
		{"block still wins", ActionBlock, []OrderedLayer{
			escalationLayer("challenge", ActionChallenge, 430),
			escalationLayer("blocker", ActionBlock, 500),
		}},
		{"log does not escalate from pass", ActionLog, []OrderedLayer{
			escalationLayer("passthrough", ActionPass, 100),
			escalationLayer("logger", ActionLog, 400),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewPipeline(tc.shift...)
			ctx := testContext()
			res := p.Execute(ctx)
			if res.Action != tc.want {
				t.Fatalf("final action = %v, want %v", res.Action, tc.want)
			}
			if ctx.Action != tc.want {
				t.Fatalf("ctx.Action = %v, want %v", ctx.Action, tc.want)
			}
		})
	}
}
