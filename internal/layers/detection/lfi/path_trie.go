package lfi

import (
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

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
	path        string         // the full inserted path (for evidence extraction)
	children    [256]*trieNode // ASCII children only; inputs are lowercased ASCII
	// fail is the Aho-Corasick failure link: the longest proper suffix of
	// this node's path that is also a trie node. On divergence the walk
	// follows fail links instead of restarting from root at the NEXT
	// position, so embedded matches (e.g. /etc/passwd inside
	// /private/etc/passwd) are found regardless of shared prefixes.
	fail *trieNode
}

// buildSensitivePathTrie constructs a trie from the embedded path lists.
// Called once at init time, not per-request.
func buildSensitivePathTrie() *sensitivePathTrie {
	t := &sensitivePathTrie{root: &trieNode{}}

	addPath := func(path string, score int, desc string) {
		// The detector lowercases input before trie lookup; normalize the
		// inserted paths to match, or mixed-case entries (the Windows paths)
		// are unreachable.
		path = strings.ToLower(path)
		node := t.root
		for i := range path {
			idx := int(path[i])
			if node.children[idx] == nil {
				node.children[idx] = &trieNode{}
			}
			node = node.children[idx]
		}
		node.score = score
		node.description = desc
		node.path = path
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

	// macOS paths. The /private/etc/* forms of /etc/* need no separate
	// entries: the restart-at-root walk finds the embedded /etc/* suffix and
	// fires the Linux classification. These seven have no reachable embedded
	// suffix anywhere in the trie, so they are inserted explicitly
	// (round-2026-09-18-r15): the log tier mirrors the /var/log Linux
	// entries, the config/directory tier mirrors the Linux config entries.
	macosPaths := []string{
		"/etc/resolv.conf",
		"/etc/hosts",
		"/etc/apache2/httpd.conf",
		"/etc/php.ini",
	}
	for _, p := range macosPaths {
		addPath(p, 55, "Access to sensitive macOS path: "+p)
	}
	addPath("/private/var/log/system.log", 60, "Access to /private/var/log/system.log detected")
	addPath("/private/var/log/asl", 60, "Access to /private/var/log/asl detected")
	addPath("/var/log/system.log", 60, "Access to /var/log/system.log detected")
	addPath("/var/log/install.log", 60, "Access to /var/log/install.log detected")
	addPath("/Library/Logs/DiagnosticReports", 60, "Access to /Library/Logs/DiagnosticReports detected")
	addPath("/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist", 55, "Access to /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist detected")
	addPath("/Users/Shared", 55, "Access to /Users/Shared detected")

	// Failure links must be computed over the final trie; the trie is built
	// once at init and never mutated afterwards.
	t.buildFailureLinks()

	return t
}

// buildFailureLinks computes the Aho-Corasick failure links breadth-first.
// A depth-1 node fails to the root; a deeper node's fail link is the longest
// proper suffix of its path that is also a trie node, derived from the
// parent's already-computed link (BFS order guarantees parents are done
// first). Without these links a divergence mid-trie loses every embedded
// match starting at the intermediate positions — the naive restart skips
// them, which is exactly how inserting /private/var/log/system.log briefly
// broke the embedded /etc/passwd detection in /private/etc/passwd.
func (t *sensitivePathTrie) buildFailureLinks() {
	t.root.fail = t.root
	queue := []*trieNode{}
	for i := range t.root.children {
		if c := t.root.children[i]; c != nil {
			c.fail = t.root
			queue = append(queue, c)
		}
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for i := range n.children {
			c := n.children[i]
			if c == nil {
				continue
			}
			f := n.fail
			for f != t.root && f.children[i] == nil {
				f = f.fail
			}
			c.fail = f.children[i]
			if c.fail == nil || c.fail == c {
				c.fail = t.root
			}
			queue = append(queue, c)
		}
	}
}

// global trie — built once at init.
var sensitiveTrie = buildSensitivePathTrie()

// checkWithTrie walks the input once through the trie, following failure
// links on divergence (Aho-Corasick). Each position consumes one input byte;
// on mismatch the walk falls back to the longest proper suffix that is still
// a trie node and retries the SAME byte, so embedded matches survive shared
// prefixes. O(k) amortized. Terminals are reported when the walk lands on
// them; a pattern that is a proper suffix of a longer matched pattern would
// additionally require dictionary-chain following. Exactly one such pair
// exists (/var/log/system.log inside /private/var/log/system.log, both score
// 60): the shorter match is under-reported, dropping only a redundant
// same-score finding — detection is unaffected.
func (t *sensitivePathTrie) checkWithTrie(input, location string) []engine.Finding {
	var findings []engine.Finding
	node := t.root

	for i := 0; i < len(input); i++ {
		idx := int(input[i])
		for node != t.root && node.children[idx] == nil {
			if node.fail == nil {
				// Hand-built tries without failure links: fall back to the
				// legacy restart-at-root behavior so the walk stays usable
				// on any trie, not only ones that ran buildFailureLinks.
				node = t.root
				break
			}
			node = node.fail
		}
		if child := node.children[idx]; child != nil {
			node = child
		}
		if node.score > 0 {
			findings = append(findings, makeFinding(node.score, engine.SeverityHigh,
				node.description,
				extractContext(input, node.path),
				location, 0.75))
		}
	}

	return findings
}
