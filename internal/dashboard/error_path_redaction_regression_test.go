package dashboard

import (
	"errors"
	"testing"
)

func TestSanitizeErrRedactsAllSupportedPaths(t *testing.T) {
	cases := map[string]string{
		"copy /tmp/one to /tmp/two failed":  "copy <redacted> to <redacted> failed",
		"copy /home/one to /var/two failed": "copy <redacted> to <redacted> failed",
		`open C:\local\file failed`:         "open <redacted> failed",
		`C:\local\file failed`:              "<redacted> failed",
		`copy C:\one to D:\two failed`:      "copy <redacted> to <redacted> failed",
		`open "C:\local\file" failed`:       `open "<redacted>" failed`,
		`open 'C:/local/file' failed`:       `open '<redacted>' failed`,
		`C:\`:                               "<redacted>",
		"":                                  "",
		"tenant not found":                  "tenant not found",
		"connection refused to http://localhost:8080": "connection refused to http://localhost:8080",
		"dial tcp: connection refused /api/v1/test":   "dial tcp: connection refused /api/v1/test",
		"relative/file.txt failed":                    "relative/file.txt failed",
	}
	for input, want := range cases {
		got := sanitizeErr(errors.New(input))
		if got != want {
			t.Errorf("%q: got %q want %q", input, got, want)
		}
	}
	if sanitizeErr(nil) != "" {
		t.Fatal("nil error changed")
	}
}
