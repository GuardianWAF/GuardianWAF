package ssti

import (
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestDetect_AttackPayloads(t *testing.T) {
	attacks := []string{
		"{{7*7}}",    // Jinja2/Twig arithmetic probe
		"${7*7}",     // JSP/Freemarker probe
		"#{7*7}",     // Ruby/JSF probe
		"<%= 7*7 %>", // ERB probe
		"{{7*'7'}}",  // string-mul probe
		"{{config.__class__.__init__.__globals__}}", // Jinja2 sandbox escape
		"{{''.__class__.__mro__[1].__subclasses__()}}",
		"{{cycler.__init__.__globals__.os.popen('id').read()}}",
		"${T(java.lang.Runtime).getRuntime().exec('id')}", // SpEL RCE
		"${@java.lang.Runtime@getRuntime()}",
		"<#assign ex=\"freemarker.template.utility.Execute\"?new()>", // Freemarker
		"{php}system('id');{/php}",                                   // Smarty
		"{{_self.env.registerUndefinedFilterCallback('system')}}",    // Twig
		"<%= system('id') %>",                                        // ERB RCE
	}
	for _, a := range attacks {
		f := Detect(a, "query")
		total := 0
		for _, x := range f {
			total += x.Score
		}
		if total < 50 {
			t.Errorf("attack not blocked (score %d < 50): %q", total, a)
		}
	}
}

func TestDetect_BenignInputs(t *testing.T) {
	benign := []string{
		"hello world",
		"{{ username }}",      // legit template variable
		"${greeting}",         // legit interpolation
		"price * quantity",    // variable arithmetic, no delimiter
		"a {{ b }} c {{ d }}", // plain template vars
		"search for templates",
		"#{color}", // CSS-ish / legit interpolation, no literal mul
		"The cost is 7 dollars",
		"",
	}
	for _, b := range benign {
		if f := Detect(b, "query"); len(f) != 0 {
			t.Errorf("false positive on benign input %q: %+v", b, f)
		}
	}
}

func TestDetect_EmptyInput(t *testing.T) {
	if f := Detect("", "query"); f != nil {
		t.Errorf("expected nil for empty input, got %v", f)
	}
}

func TestDetector_Integration(t *testing.T) {
	det := NewDetector(true, 1.0)
	var _ engine.Detector = det
	if det.DetectorName() != "ssti" {
		t.Errorf("DetectorName = %q, want ssti", det.DetectorName())
	}
	if len(det.Patterns()) == 0 {
		t.Error("expected non-empty patterns")
	}

	ctx := &engine.RequestContext{
		Path:            "/render",
		NormalizedPath:  "/render",
		QueryParams:     map[string][]string{"tpl": {"{{config.__class__}}"}},
		NormalizedQuery: map[string][]string{"tpl": {"{{config.__class__}}"}},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}
	if r := det.Process(ctx); r.Score < 50 || len(r.Findings) == 0 {
		t.Errorf("Process did not flag SSTI gadget; score=%d findings=%d", r.Score, len(r.Findings))
	}

	det.enabled = false
	if r := det.Process(ctx); r.Action != engine.ActionPass || len(r.Findings) != 0 {
		t.Error("disabled detector should pass")
	}
}

func TestDetector_Multiplier(t *testing.T) {
	ctx := &engine.RequestContext{
		QueryParams:     map[string][]string{"q": {"{{7*7}}"}},
		NormalizedQuery: map[string][]string{"q": {"{{7*7}}"}},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}
	base := NewDetector(true, 1.0).Process(ctx).Score
	doubled := NewDetector(true, 2.0).Process(ctx).Score
	if doubled != base*2 {
		t.Errorf("multiplier not applied: base=%d doubled=%d", base, doubled)
	}
}

func TestDetector_RefererAndCookieScanning(t *testing.T) {
	det := NewDetector(true, 1.0)
	ctx := &engine.RequestContext{
		Path:              "/test",
		NormalizedPath:    "/test",
		Headers:           map[string][]string{"Referer": {"{{7*7}}"}},
		NormalizedHeaders: map[string][]string{"Referer": {"{{7*7}}"}},
		Cookies:           map[string]string{"session": "{{config}}"},
	}
	r := det.Process(ctx)
	if r.Score == 0 {
		t.Error("expected score > 0 for SSTI in Referer and cookies")
	}
}

func TestDetector_SeenDedup(t *testing.T) {
	det := NewDetector(true, 1.0)
	ctx := &engine.RequestContext{
		Path:            "{{7*7}}",
		NormalizedPath:  "{{7*7}}",
		QueryParams:     map[string][]string{"q": {"{{7*7}}"}},
		NormalizedQuery: map[string][]string{"q": {"{{7*7}}"}},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}
	r := det.Process(ctx)
	if r.Score == 0 {
		t.Error("expected score > 0 even with dedup")
	}
}

// Merged from ssti_gap_test.go
func TestDetectorNameAndOrder(t *testing.T) {
	detector := NewDetector(true, 1)
	if got := detector.Name(); got != "ssti-detector" {
		t.Fatalf("Name() = %q, want %q", got, "ssti-detector")
	}
	if got := detector.Order(); got != 0 {
		t.Fatalf("Order() = %d, want 0", got)
	}
}

func TestHasLiteralMultiplicationBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "asterisk first", input: "*7", want: false},
		{name: "spaces without left operand", input: "  *7", want: false},
		{name: "non-digit left operand", input: "x*7", want: false},
		{name: "missing right operand", input: "7*", want: false},
		{name: "spaces without right operand", input: "7*  ", want: false},
		{name: "quote without right operand", input: "7*'", want: false},
		{name: "non-digit right operand", input: "7*x", want: false},
		{name: "spaced quoted multiplication", input: "7 * '7'", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasLiteralMultiplication(tt.input); got != tt.want {
				t.Fatalf("hasLiteralMultiplication(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestMakeFindingMatchedValueFallbackAndTruncation(t *testing.T) {
	context := strings.Repeat("x", 205)
	finding := makeFinding(1, engine.SeverityLow, "description", "", context, "body", 0.5)

	if got := len(finding.MatchedValue); got != 200 {
		t.Fatalf("len(MatchedValue) = %d, want 200", got)
	}
	if !strings.HasSuffix(finding.MatchedValue, "...") {
		t.Fatalf("MatchedValue = %q, want ellipsis suffix", finding.MatchedValue)
	}
}

func TestExtractContext(t *testing.T) {
	t.Run("missing pattern short input", func(t *testing.T) {
		if got := extractContext("short input", "absent"); got != "short input" {
			t.Fatalf("extractContext() = %q, want %q", got, "short input")
		}
	})

	t.Run("missing pattern long input", func(t *testing.T) {
		input := strings.Repeat("x", 101)
		if got := extractContext(input, "absent"); got != input[:100] {
			t.Fatalf("extractContext() length = %d, want 100", len(got))
		}
	})

	t.Run("long matching pattern is truncated", func(t *testing.T) {
		pattern := strings.Repeat("p", 201)
		input := "prefix" + pattern + "suffix"
		got := extractContext(input, pattern)
		if len(got) != 200 {
			t.Fatalf("extractContext() length = %d, want 200", len(got))
		}
		if !strings.HasSuffix(got, "...") {
			t.Fatalf("extractContext() = %q, want ellipsis suffix", got)
		}
	})
}
