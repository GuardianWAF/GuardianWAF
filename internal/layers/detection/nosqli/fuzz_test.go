package nosqli

import "testing"

func FuzzNoSQLiDetector(f *testing.F) {
	f.Add(`{"username":{"$ne":null}}`)
	f.Add("user[$ne]=admin")
	f.Add(`{"$where":"sleep(1000)"}`)
	f.Add(`{"price":{"$gt":100}}`)
	f.Add(`{"role":{"$in":["a","b"]}}`)
	f.Add("hello world")
	f.Add("")
	f.Add("$$$$[[[[")
	f.Add(`{"$ne":`)
	f.Add(string([]byte{0, 1, 2, 255, 254}))

	f.Fuzz(func(t *testing.T, input string) {
		for _, fd := range Detect(input, "query") {
			if fd.Score < 0 {
				t.Errorf("negative score for %q: %d", input, fd.Score)
			}
		}
	})
}
