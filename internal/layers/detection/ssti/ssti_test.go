package ssti

import (
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
