package lfi

import "testing"

func FuzzLFIDetector(f *testing.F) {
	f.Add("../../../../etc/passwd")
	f.Add("..%2f..%2fetc%2fpasswd")
	f.Add("....//....//etc/passwd")
	f.Add("/etc/passwd")
	f.Add("php://filter/convert.base64-encode/resource=index")
	f.Add("..%c0%afetc/passwd")
	f.Add("C:\\windows\\win.ini")
	f.Add("report.pdf")
	f.Add("")
	f.Add("normal/path/to/file")
	f.Add("%00")
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
