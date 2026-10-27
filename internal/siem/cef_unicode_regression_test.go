package siem

import (
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"strings"
	"testing"
	"unicode/utf8"
)

func batchF26Name(s string) string {
	return strings.Split(EncodeCEF(engine.Event{Findings: []engine.Finding{{Description: s}}}, "fixture", "1"), "|")[5]
}
func TestCEFNameTruncationPreservesUnicode(t *testing.T) {
	for _, in := range []string{"short", strings.Repeat("a", 199), strings.Repeat("a", 200), strings.Repeat("a", 201), strings.Repeat("ğ", 101), strings.Repeat("界", 67), strings.Repeat("🙂", 51)} {
		want := in
		if len(in) > 200 {
			prefix := ""
			for _, r := range in {
				next := prefix + string(r)
				if len(next) > 197 {
					break
				}
				prefix = next
			}
			want = prefix + "..."
		}
		got := batchF26Name(in)
		if got != want || len(got) > 200 || !utf8.ValidString(got) {
			t.Fatalf("got %q want %q", got, want)
		}
	}
	if got := batchF26Name(""); got != "WAF Event" {
		t.Fatal(got)
	}
	t.Log("FIX VERIFIED")
}
