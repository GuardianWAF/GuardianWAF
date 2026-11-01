package cmdi

import (
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// winCommands are Windows commands that are unambiguous when they follow a
// single '&' (cmd.exe's command separator). Commands that are also everyday
// words need a recognisable subcommand.
var winCommands = map[string]bool{
	"whoami": true, "ipconfig": true, "systeminfo": true, "tasklist": true,
	"taskkill": true, "certutil": true, "bitsadmin": true, "wmic": true,
	"schtasks": true, "mshta": true, "rundll32": true, "regsvr32": true,
	"cscript": true, "wscript": true, "netsh": true, "powershell": true,
	"pwsh": true, "cmd": true, "cmd.exe": true, "powershell.exe": true,
}

// winSubcommands lists the first argument that makes net, reg and sc a
// command rather than a word.
var winSubcommands = map[string]map[string]bool{
	"net": {"user": true, "localgroup": true, "use": true, "share": true, "accounts": true,
		"group": true, "view": true, "start": true, "stop": true, "session": true},
	"reg": {"query": true, "add": true, "delete": true, "save": true, "export": true},
	"sc":  {"query": true, "create": true, "start": true, "stop": true, "config": true},
}

// checkAmpersandCommand flags a single '&' followed by a Windows command, the
// cmd.exe form of ";id" ("& net user hacker P@ss /add"). The '&' must stand
// alone between spaces or start the value, so "AT&T", "R&D" and "&amp;" never
// match, and only unambiguous commands count, so "terms & conditions" and
// "Q & A" do not.
func checkAmpersandCommand(lower, location string) []engine.Finding {
	if !strings.Contains(lower, "&") {
		return nil
	}
	for i := 0; i < len(lower); i++ {
		if lower[i] != '&' {
			continue
		}
		if i > 0 && (lower[i-1] == '&' || (lower[i-1] != ' ' && lower[i-1] != '\t')) {
			continue
		}
		if i+1 >= len(lower) || lower[i+1] == '&' || lower[i+1] == '#' {
			continue
		}
		rest := strings.TrimSpace(lower[i+1:])
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		cmd := fields[0]
		hit := winCommands[cmd]
		if subs, ok := winSubcommands[cmd]; ok && len(fields) > 1 && subs[fields[1]] {
			hit = true
		}
		if hit {
			return []engine.Finding{makeFinding(70, engine.SeverityHigh,
				"Ampersand command separator with Windows command ("+cmd+")",
				extractContext(lower, "&"), location, 0.85)}
		}
	}
	return nil
}

// isProseSentence reports a sentence on both sides of a separator: at least two
// plain words before it, and the command position followed by at least two
// more plain words ("wget downloads files; ping checks reachability").
// Injection puts a host, a flag, a path or a variable there, never a sentence.
func isProseSentence(prefix, rest string) bool {
	return plainWords(prefix) >= 2 && plainWords(rest) >= 3
}

// plainWords counts the words of s when every word is only letters (with an
// optional apostrophe, hyphen or trailing comma or period); any other word makes
// the count zero.
func plainWords(s string) int {
	n := 0
	for _, w := range strings.Fields(s) {
		w = strings.TrimRight(w, ",.!?:")
		if w == "" {
			return 0
		}
		for i := 0; i < len(w); i++ {
			c := w[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '\'' || c == '-') {
				return 0
			}
		}
		n++
	}
	return n
}
