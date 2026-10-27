package lfi

import "testing"

func homeSecretScore(input string) int {
	total := 0
	for _, f := range Detect(input, "query") {
		total += f.Score
	}
	return total
}

// Regression: credential and history files under a home directory scored 0
// when requested by absolute path (no traversal), e.g. file=/root/.ssh/id_rsa.
func TestHomeSecretFilesBlocked(t *testing.T) {
	for _, s := range []string{
		"/root/.ssh/id_rsa",
		"/home/.ssh/authorized_keys",
		"/home/deploy/.ssh/id_ed25519",
		"/root/.bash_history",
		"~/.aws/credentials",
		"/home/app/.git-credentials",
		"/root/.kube/config",
		"/root/.docker/config.json",
		"../../../../home/www/.netrc",
		"/var/lib/postgresql/.pgpass",
		"/ROOT/.SSH/ID_RSA",
	} {
		if got := homeSecretScore(s); got < 50 {
			t.Errorf("%q scored %d, want at least the block threshold (50)", s, got)
		}
	}
}

// Developer prose that mentions the same paths only logs.
func TestHomeSecretPathsInProseOnlyLog(t *testing.T) {
	for _, s := range []string{
		"Add your public key to ~/.ssh/authorized_keys on the server",
		"aws configure stores keys in ~/.aws/credentials by default",
		"clear ~/.bash_history before imaging the VM",
	} {
		if got := homeSecretScore(s); got >= 50 {
			t.Errorf("%q scored %d, want below the block threshold (50)", s, got)
		}
	}
}
