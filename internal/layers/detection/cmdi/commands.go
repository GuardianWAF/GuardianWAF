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
