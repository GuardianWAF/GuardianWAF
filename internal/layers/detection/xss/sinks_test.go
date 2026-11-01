package xss

import "testing"

func total(in string) int {
	t := 0
	for _, f := range Detect(in, "query") {
		t += f.Score
	}
	return t
}

func TestIndirectSinks(t *testing.T) {
	for _, a := range []string{
		`alert.call( , "XSS");`,
		`confirm.call(null,1)`,
		`prompt.call(null,1)`,
		`alert.apply(null, [1])`,
		`alert?.(document?.cookie)`,
		`(alert)(1)`,
		`(eval)('alert(1)')`,
		`document["cookie"]`,
		`document?.cookie`,
		`window['eval']('x')`,
		`"));if(!self.x)self.x=!alert(document.domain)}catch(e){}//`,
		`__proto__[v-if]=_c.constructor('alert(1)')()`,
		`\"autof<x>ocus o<x>nfocus=alert<x>(1)//`,
		`<img src=x on<x>error=alert(1)>`,
		`javascript:alert(1)`,
		`javascript: alert(1)`,
		`javascript:void(0)`,
	} {
		if got := total(a); got < 50 {
			t.Errorf("Detect(%q) = %d, want >= 50", a, got)
		}
	}
}

func TestIndirectSinkBenign(t *testing.T) {
	for _, b := range []string{
		`JavaScript: Basics of JavaScript Language`,
		`JavaScript:+Basics+of+JavaScript+Language`,
		`JavaScript%3A+Basics+of+JavaScript+Language`,
		`JavaScript: Tips (part 1) for beginners`,
		`Learn JavaScript: the good parts`,
		`javascript: a language`,
		`please alert the team and call the manager`,
		`the prompt is shown to users`,
		`use document.title for the heading`,
		`a<b and c>d`,
		`x < y > z`,
		`they say <b>hello</b> to everyone`,
		`array.call is not a function`,
		`confirm that the order was received`,
	} {
		if got := total(b); got >= 50 {
			t.Errorf("Detect(%q) = %d, want < 50", b, got)
		}
	}
}

func TestSqueezeJunkTags(t *testing.T) {
	if got, ok := squeezeJunkTags("o<x>nfocus=alert<x>(1)"); !ok || got != "onfocus=alert(1)" {
		t.Errorf("squeeze = %q %v", got, ok)
	}
	if _, ok := squeezeJunkTags("<b>bold</b> text"); ok {
		t.Error("squeezed a real tag")
	}
	if _, ok := squeezeJunkTags("no tags here"); ok {
		t.Error("changed text without tags")
	}
}
