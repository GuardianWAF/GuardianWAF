package engine

import (
	"slices"
	"testing"
)

func TestCookieViewsDecodeLikeBackends(t *testing.T) {
	ctx := &RequestContext{
		Cookies: map[string][]string{
			"pref":  {"%27+OR+1%3D1+--"},
			"theme": {"dark"},
			"bad":   {"%zz+x"},
		},
		NormalizedCookies: map[string][]string{
			"pref":  {"' OR 1=1 --"},
			"theme": {"dark"},
			"bad":   {"%zz x"},
		},
	}
	views := ctx.CookieViews()
	for _, want := range []string{"%27+OR+1%3D1+--", "' OR 1=1 --", "dark", "%zz+x", "%zz x"} {
		if !slices.Contains(views, want) {
			t.Errorf("CookieViews() = %q, missing %q", views, want)
		}
	}
	if n := len(views); n != 5 {
		t.Errorf("CookieViews() returned %d views, want 5 (no duplicates): %q", n, views)
	}
}
