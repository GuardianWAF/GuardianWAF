package lfi

import "testing"

// Regression: buildSensitivePathTrie inserted the Windows paths with their
// literal mixed case ("C:\Windows\system32\config\sam"), but the detector
// lowercases input before checkSensitivePaths — the trie's 'C' (0x43) child
// can never match the input's 'c' (0x63), so all 20 Windows sensitive-path
// entries were unreachable and never produced a finding.
func TestWindowsSensitivePathsReachable(t *testing.T) {
	// The detector lowercases before the trie lookup, so these are the exact
	// forms checkSensitivePaths receives.
	cases := []struct {
		input string
		desc  string
	}{
		{"c:\\windows\\system32\\config\\sam", "SAM hive"},
		{"c:\\windows\\win.ini", "win.ini"},
		{"c:\\inetpub\\wwwroot\\web.config", "web.config"},
		{"c:\\programdata\\mysql\\mysql server 5.7\\my.ini", "MySQL my.ini"},
		{"c:\\windows\\repair\\system", "registry repair system"},
		{"x/../c:\\windows\\system32\\drivers\\etc\\hosts", "hosts via traversal"},
	}

	for _, tc := range cases {
		findings := sensitiveTrie.checkWithTrie(tc.input, "query")
		if len(findings) == 0 {
			t.Fatalf("FAIL: no trie finding for %s (%s) — the Windows paths are unreachable in the case-sensitive trie", tc.desc, tc.input)
		}
	}
}
