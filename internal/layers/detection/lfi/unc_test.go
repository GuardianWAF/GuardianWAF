package lfi

import "testing"

func lfiTotal(in string) int {
	t := 0
	for _, f := range Detect(in, "query") {
		t += f.Score
	}
	return t
}

func TestUNCPaths(t *testing.T) {
	for _, a := range []string{
		`\\::1\c$\users\default\ntuser.dat`,
		`//::1/c$/users/default/ntuser.dat`,
		`\\localhost\c$\windows\win.ini`,
		`\\10.0.0.5\admin$\system32`,
		`\\127.0.0.1\share\secret.txt`,
		`C:\Users\bob\NTUSER.DAT`,
	} {
		if got := lfiTotal(a); got < 50 {
			t.Errorf("Detect(%q) = %d, want >= 50", a, got)
		}
	}
	for _, b := range []string{
		`price is $5 per share`,
		`the c$ drive is a hidden share name`,
		`see //example.com/path for details`,
		`https://example.com/c$/docs`,
		`localhost is a hostname`,
		`ntuser means nothing here`,
	} {
		if got := lfiTotal(b); got >= 50 {
			t.Errorf("Detect(%q) = %d, want < 50", b, got)
		}
	}
}

func TestOverlongRawTraversal(t *testing.T) {
	for _, a := range []string{
		"\xc0\xae\xc0\xae\xc0\xaf\xc0\xae\xc0\xae\xc0\xafetc\xc0\xafpasswd",
		"..\xc0\xafetc\xc0\xafpasswd",
	} {
		if got := lfiTotal(a); got < 50 {
			t.Errorf("Detect(%q) = %d, want >= 50", a, got)
		}
	}
}
