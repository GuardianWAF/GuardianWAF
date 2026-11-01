package ldapi

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func maxScore(f []engine.Finding) int {
	m := 0
	for _, x := range f {
		m = max(m, x.Score)
	}
	return m
}

func TestDetectsInjection(t *testing.T) {
	attacks := []string{
		"(&(uid=admin)(!(&(1=0)(userPassword=q))))",
		"*(|(objectclass=*))",
		"userPassword:2.5.13.18:=123",
		"admin)(&)",
		"admin)(uid=*))(|(uid=*",
		"*)(uid=*))(|(uid=*",
		"*)(objectclass=*",
		"x)(|(cn=*",
		"cn:dn:=admin",
		"(|(uid=a)(uid=b))",
		"uid=*)(|(password=*)",
		"jsmith)(!(uid=",
	}
	for _, a := range attacks {
		if got := maxScore(Detect(a, "query")); got < 50 {
			t.Errorf("Detect(%q) score = %d, want >= 50", a, got)
		}
	}
}

func TestIgnoresOrdinaryText(t *testing.T) {
	benign := []string{
		"hello world",
		"(see figure 2) and (table 3)",
		"f(x) = (a+b)(c+d)",
		"call me (555) 123-4567",
		"sum = (a=b) and (c=d)",
		"The answer (1) is (a) right",
		"function(a) { return (b) }",
		"if (x == 1) (y = 2)",
		"smile :) (: ok",
		"price: $5 (was $6)",
		"mailto:user@example.com",
		"key:value:=assigned",
		"a:=b",
		"(uid)",
		"",
	}
	for _, b := range benign {
		if got := maxScore(Detect(b, "body")); got >= 50 {
			t.Errorf("Detect(%q) score = %d, want < 50", b, got)
		}
	}
}

func TestProcess(t *testing.T) {
	ctx := &engine.RequestContext{QueryParams: map[string][]string{"user": {"*)(uid=*))(|(uid=*"}}}
	if res := NewDetector(true, 1.0).Process(ctx); res.Score < 50 {
		t.Fatalf("Process score = %d, want >= 50", res.Score)
	}
	if res := NewDetector(false, 1.0).Process(ctx); res.Score != 0 {
		t.Fatalf("disabled detector scored %d", res.Score)
	}
}

func FuzzDetect(f *testing.F) {
	for _, s := range []string{"", "(", ")", "(&(a=b))", "*)(a=b", "a:1.2.3:=x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _ = Detect(s, "query") })
}
