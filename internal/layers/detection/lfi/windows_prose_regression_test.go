package lfi

import "testing"

func lfiScore(in string) int {
	total := 0
	for _, f := range Detect(in, "body") {
		total += f.Score
	}
	return total
}

// Regression: a drive path mentioned in prose scored 55 and blocked a
// support-forum post ("on Windows the path is C:\Users\me\AppData\...").
func TestWindowsDrivePathInProseOnlyLogs(t *testing.T) {
	for _, in := range []string{
		`On Windows the path is C:\Users\me\AppData\Local\App, on macOS it's ~/Library/Application Support/App.`,
		`Install it to D:\Games and restart.`,
	} {
		if got := lfiScore(in); got >= 50 {
			t.Errorf("prose scored %d, want < 50: %q", got, in)
		}
	}
	for _, in := range []string{
		`C:\Users\me\secrets.txt`,
		`  c:/boot.ini`,
		`=c:\temp\x`,
		`See C:\Windows\win.ini`,
		`read c:\windows\system32\config\sam please`,
	} {
		if got := lfiScore(in); got < 50 {
			t.Errorf("file target scored %d, want >= 50: %q", got, in)
		}
	}
}
