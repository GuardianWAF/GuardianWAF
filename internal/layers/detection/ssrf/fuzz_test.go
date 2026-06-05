package ssrf

import "testing"

func FuzzSSRFDetector(f *testing.F) {
	f.Add("http://127.0.0.1:22/")
	f.Add("http://localhost/admin")
	f.Add("https://localhost.example.com/x")
	f.Add("http://169.254.169.254/latest/meta-data/")
	f.Add("http://[::1]:8080/")
	f.Add("https://api.example.com/v1/data")
	f.Add("http://0177.0.0.1")
	f.Add("")
	f.Add("file:///etc/passwd")
	f.Add("gopher://127.0.0.1:6379/_")
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
