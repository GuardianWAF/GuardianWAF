package cmdi

// commandDatabase contains known OS commands that may indicate command injection.
var commandDatabase = map[string]bool{
	// File operations
	"cat":     true,
	"ls":      true,
	"dir":     true,
	"cp":      true,
	"mv":      true,
	"rm":      true,
	"mkdir":   true,
	"rmdir":   true,
	"touch":   true,
	"head":    true,
	"tail":    true,
	"more":    true,
	"less":    true,
	"wc":      true,
	"diff":    true,
	"sort":    true,
	"uniq":    true,
	"cut":     true,
	"tr":      true,
	"file":    true,
	"xxd":     true,
	"od":      true,
	"strings": true,

	// System info / recon
	"whoami":   true,
	"id":       true,
	"uname":    true,
	"hostname": true,
	"ifconfig": true,
	"ip":       true,
	"netstat":  true,
	"ss":       true,
	"ps":       true,
	"env":      true,
	"set":      true,
	"echo":     true,
	"printf":   true,
	"printenv": true,
	"uptime":   true,
	"w":        true,
	"last":     true,
	"df":       true,
	"mount":    true,

	// System control / destructive
	"reboot":    true,
	"shutdown":  true,
	"poweroff":  true,
	"halt":      true,
	"init":      true,
	"systemctl": true,
	"service":   true,
	"useradd":   true,
	"passwd":    true,

	// Network tools
	"wget":     true,
	"curl":     true,
	"nc":       true,
	"ncat":     true,
	"netcat":   true,
	"socat":    true,
	"telnet":   true,
	"ssh":      true,
	"scp":      true,
	"ftp":      true,
	"tftp":     true,
	"ping":     true,
	"nslookup": true,
	"dig":      true,
	"host":     true,

	// Interpreters / shells
	"python":     true,
	"python3":    true,
	"perl":       true,
	"ruby":       true,
	"php":        true,
	"node":       true,
	"bash":       true,
	"sh":         true,
	"zsh":        true,
	"dash":       true,
	"csh":        true,
	"ksh":        true,
	"cmd":        true,
	"powershell": true,
	"pwsh":       true,

	// Permission / process management
	"chmod":  true,
	"chown":  true,
	"chgrp":  true,
	"kill":   true,
	"pkill":  true,
	"nohup":  true,
	"sudo":   true,
	"su":     true,
	"chroot": true,

	// Archive / encoding
	"tar":     true,
	"zip":     true,
	"unzip":   true,
	"gzip":    true,
	"gunzip":  true,
	"base64":  true,
	"openssl": true,

	// Search / text processing
	"find":  true,
	"grep":  true,
	"awk":   true,
	"sed":   true,
	"xargs": true,
	"tee":   true,

	// Database clients
	"mysql":     true,
	"psql":      true,
	"sqlite3":   true,
	"mongo":     true,
	"redis-cli": true,

	// Other dangerous
	"crontab": true,
	"at":      true,
	"eval":    true,
	"exec":    true,
	"xterm":   true,
	"mknod":   true,
	"mkfifo":  true,
}

// reconCommands are commands typically used for system reconnaissance.
var reconCommands = map[string]bool{
	"id":       true,
	"whoami":   true,
	"uname":    true,
	"hostname": true,
	"ifconfig": true,
	"ip":       true,
	"netstat":  true,
	"ss":       true,
	"ps":       true,
	"env":      true,
	"printenv": true,
	"cat":      true,
	"ls":       true,
	"dir":      true,
	"df":       true,
}

// networkCommands are commands used for network operations (higher risk).
var networkCommands = map[string]bool{
	"nc":     true,
	"ncat":   true,
	"netcat": true,
	"socat":  true,
	"curl":   true,
	"wget":   true,
	"telnet": true,
	"ssh":    true,
	"scp":    true,
	"ftp":    true,
	"tftp":   true,
	"ping":   true,
}

// IsCommand returns true if the given word (lowercase) is a known OS command.
func IsCommand(cmd string) bool {
	return commandDatabase[cmd]
}

// isReconCommand returns true if the command is a recon command.
func isReconCommand(cmd string) bool {
	return reconCommands[cmd]
}

// isNetworkCommand returns true if the command is a network command.
func isNetworkCommand(cmd string) bool {
	return networkCommands[cmd]
}

// ambiguousCommands are entries in commandDatabase that are also ordinary
// English words, markdown/table artifacts, or one-to-two character tokens. On
// their own, after a shell metacharacter, they carry almost no signal: a
// markdown table row "| id | name |" and an attack "127.0.0.1;id" are the same
// shape to a substring matcher.
//
// This is the trade-off documented for M1 in docs/history/AUDIT.md, resolved
// the way that note recommends — keep detecting them, but score the
// uncorroborated case in the log range so a default block threshold does not
// trip on prose, while unambiguous commands (whoami, nc, wget, …) keep their
// blocking score. An attacker cannot make "id" unambiguous, so unlike a
// structural guard this cannot be evaded by reshaping the payload.
var ambiguousCommands = map[string]bool{
	"at": true, "cut": true, "dir": true, "echo": true, "env": true,
	"file": true, "find": true, "head": true, "id": true, "info": true,
	"ip": true, "kill": true, "last": true, "less": true, "link": true,
	"ls": true, "more": true, "od": true, "ps": true, "run": true,
	"set": true, "sort": true, "ss": true, "strings": true, "tail": true,
	"time": true, "tr": true, "uniq": true, "w": true, "wc": true,
	"who": true, "write": true, "cat": true, "test": true, "top": true,
	"type": true, "help": true, "history": true, "date": true, "free": true,
}

// isAmbiguousCommand reports whether cmd is a command name that doubles as an
// everyday word, so a bare occurrence should not by itself force a block.
func isAmbiguousCommand(cmd string) bool {
	return ambiguousCommands[cmd]
}

// ambiguousCommandScore is the score used for an uncorroborated ambiguous
// command. It sits above the default log threshold (25) and below the default
// block threshold (50), so the event is still recorded and still contributes to
// a request that has other signals, without blocking on its own.
const ambiguousCommandScore = 35
