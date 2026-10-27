package engine

import (
	"slices"
	"testing"
)

func TestCustomHeaderViewsSkipsStructuredHeaders(t *testing.T) {
	ctx := &RequestContext{
		Headers: map[string][]string{
			"X-Api-Key":          {"k1"},
			"X-Original-Url":     {"/a%2fb"},
			"Authorization":      {"Bearer t"},
			"Cookie":             {"a=b"},
			"User-Agent":         {"ua"},
			"Referer":            {"https://r/"},
			"Sec-Fetch-Mode":     {"navigate"},
			"X-B3-Traceid":       {"abc"},
			"Content-Type":       {"text/plain"},
			"X-Forwarded-For":    {"1.2.3.4"},
			"X-Customer-Comment": {"same", "same"},
		},
		NormalizedHeaders: map[string][]string{
			"X-Original-Url": {"/a/b"},
			"X-Api-Key":      {"k1"},
		},
	}
	got := ctx.CustomHeaderViews()
	slices.Sort(got)
	want := []string{"/a%2fb", "/a/b", "k1", "same"}
	if !slices.Equal(got, want) {
		t.Fatalf("CustomHeaderViews() = %q, want %q", got, want)
	}
}
