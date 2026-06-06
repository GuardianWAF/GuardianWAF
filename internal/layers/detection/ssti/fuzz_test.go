package ssti

import "testing"

func FuzzSSTIDetector(f *testing.F) {
	f.Add("{{7*7}}")
	f.Add("${T(java.lang.Runtime).getRuntime().exec('id')}")
	f.Add("{{config.__class__.__init__.__globals__}}")
	f.Add("{php}system('id');{/php}")
	f.Add("{{ username }}")
	f.Add("hello world")
	f.Add("")
	f.Add("{{{{{{{{")
	f.Add("${${${")
	f.Add("<%=*%>")
	f.Add(string([]byte{0, 1, 2, 255, 254}))

	f.Fuzz(func(t *testing.T, input string) {
		for _, fd := range Detect(input, "query") {
			if fd.Score < 0 {
				t.Errorf("negative score for %q: %d", input, fd.Score)
			}
		}
	})
}
