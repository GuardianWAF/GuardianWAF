package lfi

import "github.com/guardianwaf/guardianwaf/internal/engine"

// sensitivePathTrie is a prefix tree for O(k) sensitive path detection.
// Instead of O(n*m) linear scans through 48+ paths, we traverse the trie
// once per input character.
type sensitivePathTrie struct {
	root *trieNode
}

type trieNode struct {
	// score > 0 means this node is a terminal (sensitive path).
	// Higher score = higher severity.
	score       int
	description string
	children    [256]*trieNode // ASCII children only; inputs are lowercased ASCII
}

// buildSensitivePathTrie constructs a trie from the embedded path lists.
// Called once at init time, not per-request.
func buildSensitivePathTrie() *sensitivePathTrie {
	t := &sensitivePathTrie{root: &trieNode{}}
	var count int

	addPath := func(path string, score int, desc string) {
		node := t.root
		for i := range path {
			idx := int(path[i])
			if node.children[idx] == nil {
				node.children[idx] = &trieNode{}
			}
			node = node.children[idx]
		}
		if node.score == 0 {
			count++
		}
		node.score = score
		node.description = desc
	}

	// Critical paths (highest severity)
	addPath("/etc/passwd", 90, "Access to /etc/passwd detected")
	addPath("/etc/shadow", 95, "Access to /etc/shadow detected")
	addPath("/etc/master.passwd", 95, "Access to /etc/master.passwd detected")

	// /proc/self/ prefix group
	addPath("/proc/self/environ", 85, "Access to /proc/self/environ detected")
	addPath("/proc/self/cmdline", 85, "Access to /proc/self/cmdline detected")
	addPath("/proc/self/fd/0", 85, "Access to /proc/self/fd/0 detected")
	addPath("/proc/self/status", 85, "Access to /proc/self/status detected")
	addPath("/proc/self/mounts", 85, "Access to /proc/self/mounts detected")

	// /var/log/ prefix group
	addPath("/var/log/auth.log", 60, "Access to /var/log/auth.log detected")
	addPath("/var/log/syslog", 60, "Access to /var/log/syslog detected")
	addPath("/var/log/apache2/access.log", 60, "Access to /var/log/apache2/access.log detected")
	addPath("/var/log/apache2/error.log", 60, "Access to /var/log/apache2/error.log detected")
	addPath("/var/log/nginx/access.log", 60, "Access to /var/log/nginx/access.log detected")
	addPath("/var/log/nginx/error.log", 60, "Access to /var/log/nginx/error.log detected")

	// Remaining Linux paths
	linuxPaths := []string{
		"/etc/group",
		"/etc/hosts",
		"/etc/hostname",
		"/etc/resolv.conf",
		"/etc/issue",
		"/etc/motd",
		"/etc/crontab",
		"/etc/ssh/sshd_config",
		"/etc/ssh/ssh_config",
		"/etc/apache2/apache2.conf",
		"/etc/nginx/nginx.conf",
		"/etc/mysql/my.cnf",
		"/etc/php/php.ini",
		"/etc/fstab",
		"/etc/security/passwd",
		"/proc/version",
		"/proc/cpuinfo",
		"/proc/meminfo",
		"/proc/net/tcp",
	}
	for _, p := range linuxPaths {
		addPath(p, 55, "Access to sensitive Linux path: "+p)
	}

	// Windows paths
	windowsPaths := []string{
		`C:\Windows\system32\config\sam`,
		`C:\Windows\system32\config\system`,
		`C:\Windows\system32\config\software`,
		`C:\Windows\system32\drivers\etc\hosts`,
		`C:\Windows\win.ini`,
		`C:\Windows\system.ini`,
		`C:\Windows\debug\NetSetup.log`,
		`C:\Windows\repair\sam`,
		`C:\Windows\repair\system`,
		`C:\boot.ini`,
		`C:\inetpub\wwwroot\web.config`,
		`C:\inetpub\logs\LogFiles`,
		`C:\Windows\Panther\Unattend.xml`,
		`C:\Windows\Panther\unattended.xml`,
		`C:\Windows\system32\inetsrv\config\applicationHost.config`,
		`C:\xampp\apache\conf\httpd.conf`,
		`C:\xampp\php\php.ini`,
		`C:\ProgramData\MySQL\MySQL Server 5.7\my.ini`,
		`C:\Users\Administrator\NTUser.dat`,
		`C:\Windows\System32\config\RegBack\SAM`,
	}
	for _, p := range windowsPaths {
		addPath(p, 65, "Access to sensitive Windows path: "+p)
	}

	// macOS paths
	macosPaths := []string{
		"/etc/resolv.conf",
		"/etc/hosts",
		"/etc/apache2/httpd.conf",
		"/etc/php.ini",
	}
	for _, p := range macosPaths {
		addPath(p, 55, "Access to sensitive macOS path: "+p)
	}

	return t
}

// global trie — built once at init.
var sensitiveTrie = buildSensitivePathTrie()

// checkWithTrie traverses the trie once through the input string.
// When it lands on a terminal node, it records a finding.
// This is O(k) where k = len(input), vs the old O(n*m) linear scan.
// Each character causes a single array lookup (O(1)).
func (t *sensitivePathTrie) checkWithTrie(input, location string) []engine.Finding {
	var findings []engine.Finding
	node := t.root

	// Traverse as far as possible in the trie for each character.
	// When we reach a non-terminal, continue from root but remember the longest match.
	var lastMatch *trieNode
	var lastMatchEnd int

	for i := 0; i < len(input); i++ {
		idx := int(input[i])
		child := node.children[idx]
		if child == nil {
			// No further match; record the best match so far and restart from root.
			if lastMatch != nil {
				findings = append(findings, makeFinding(lastMatch.score, engine.SeverityHigh,
					lastMatch.description,
					extractContext(input, input[max(0, lastMatchEnd-len(lastMatch.description)):lastMatchEnd]),
					location, 0.75))
				lastMatch = nil
			}
			node = t.root
			// Try a fresh match starting at this character.
			if t.root.children[idx] != nil {
				node = t.root.children[idx]
				if node.score > 0 {
					lastMatch = node
					lastMatchEnd = i + 1
				}
			}
		} else {
			node = child
			if node.score > 0 {
				lastMatch = node
				lastMatchEnd = i + 1
			}
		}
	}

	// Final match at end of string.
	if lastMatch != nil {
		findings = append(findings, makeFinding(lastMatch.score, engine.SeverityHigh,
			lastMatch.description,
			extractContext(input, input[max(0, lastMatchEnd-len(lastMatch.description)):lastMatchEnd]),
			location, 0.75))
	}

	return findings
}
