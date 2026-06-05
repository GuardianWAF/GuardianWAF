package engine

import "testing"

// FuzzRecoverDroppedQueryParams exercises the semicolon-query recovery parser
// with arbitrary raw query strings. It must never panic and must never corrupt
// pre-existing entries.
func FuzzRecoverDroppedQueryParams(f *testing.F) {
	f.Add("host=127.0.0.1;cat /etc/passwd")
	f.Add("a=1&b=2;3&c=4")
	f.Add("")
	f.Add(";;;;")
	f.Add("=")
	f.Add("k=%ZZ")
	f.Add("a;b;c;d=e")
	f.Add("%3B%3B%3B")
	f.Add(string([]byte{0, 1, 2, 255, 254}))

	f.Fuzz(func(t *testing.T, rawQuery string) {
		dst := map[string][]string{"existing": {"v"}}
		recoverDroppedQueryParams(dst, rawQuery)
		// The pre-existing entry must be preserved untouched.
		if got := dst["existing"]; len(got) != 1 || got[0] != "v" {
			t.Errorf("pre-existing entry corrupted: %v", got)
		}
	})
}
