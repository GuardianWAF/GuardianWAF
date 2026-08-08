package openredirect

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func FuzzOpenRedirectDetector(f *testing.F) {
	seeds := []string{
		"https://evil.com",
		"//evil.com/path",
		"/dashboard",
		"javascript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"https://app.example.com/profile",
		"https://sub.example.com/dashboard",
		"https://localhost:8080/admin",
		"\\\\evil.com\\share",
		"",
		"https://evil.com\r\nSet-Cookie:stolen=1",
		"https://evil.com\tX-Injected:yes",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	d := NewDetector(true, 1.0)

	f.Fuzz(func(t *testing.T, target string) {
		// Build context manually to avoid http.NewRequest panics on
		// control characters.
		ctx := &engine.RequestContext{
			Request: &http.Request{
				Method: "GET",
				URL:    &url.URL{Path: "/", RawQuery: "redirect="},
				Host:   "app.example.com",
			},
			Path:            "/",
			QueryParams:     map[string][]string{"redirect": {target}},
			NormalizedQuery: map[string][]string{"redirect": {target}},
			Headers:         map[string][]string{},
			Cookies:         map[string]string{},
		}
		result := d.Process(ctx)
		// Must never panic. Score is 0 or positive.
		if result.Score < 0 {
			t.Fatalf("negative score: %d", result.Score)
		}
	})
}
