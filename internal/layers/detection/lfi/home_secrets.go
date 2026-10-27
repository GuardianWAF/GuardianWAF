package lfi

import (
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// homeSecretPaths are credential and history files under a user's home
// directory. Reading one hands an attacker keys, cloud credentials or past
// commands; none is ever a legitimate value of a file parameter.
var homeSecretPaths = []struct {
	path  string
	score int
}{
	{"/.ssh/id_rsa", 85},
	{"/.ssh/id_dsa", 85},
	{"/.ssh/id_ecdsa", 85},
	{"/.ssh/id_ed25519", 85},
	{"/.ssh/authorized_keys", 80},
	{"/.aws/credentials", 85},
	{"/.git-credentials", 85},
	{"/.docker/config.json", 80},
	{"/.kube/config", 80},
	{"/.netrc", 80},
	{"/.pgpass", 80},
	{"/.bash_history", 70},
	{"/.zsh_history", 70},
	{"/.mysql_history", 70},
	{"/.psql_history", 70},
}

// homeSecretProseScore is used when the path sits inside text ("copy your key
// to ~/.ssh/authorized_keys and retry"): developer posts quote these paths,
// so the mention is logged but does not block on its own.
const homeSecretProseScore = 25

// checkHomeSecrets flags credential/history files under a home directory.
// The full score applies when the path is the value itself (no whitespace
// before it: `/root/.ssh/id_rsa`, `~/.aws/credentials`, `../../.netrc`).
func checkHomeSecrets(lower, location string) []engine.Finding {
	best, bestScore := "", 0
	for _, s := range homeSecretPaths {
		idx := strings.Index(lower, s.path)
		if idx < 0 {
			continue
		}
		score := s.score
		if strings.ContainsAny(lower[:idx], " \t\r\n") {
			score = homeSecretProseScore
		}
		if score > bestScore {
			best, bestScore = s.path, score
		}
	}
	if bestScore == 0 {
		return nil
	}
	severity, confidence := engine.SeverityCritical, 0.9
	if bestScore == homeSecretProseScore {
		severity, confidence = engine.SeverityLow, 0.4
	}
	return []engine.Finding{makeFinding(bestScore, severity,
		"Access to home-directory credential or history file: "+best,
		extractContext(lower, best), location, confidence)}
}
