package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCmdServe_ChallengeInitFailureExitsNonZero is the regression for the
// exit-code defect: cmdServe's challenge-service failure path did a bare
// `return` — unlike every sibling error path (config, env, validate, engine,
// cluster, dashboard, shutdown), which call osExit(1) — so
// `guardianwaf serve` exited with code 0 = success while its challenge
// subsystem failed to initialize. Supervisors configured with
// Restart=on-failure (systemd, Docker) never restart a clean exit, leaving
// the WAF down silently.
//
// Correct behavior: the challenge-failure path must request process exit 1,
// like all other cmdServe failure paths. difficulty -1 passes
// config.Validate (no range check there) and fails
// challenge.NewService's loud construction validation, so the test drives
// exactly the production failure path. The osExit stub returns so cmdServe
// unwinds immediately after the (captured) exit request; serving never
// starts.
func TestCmdServe_ChallengeInitFailureExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad-challenge.yaml")
	cfg := "listen: \"127.0.0.1:0\"\n" +
		"mode: enforce\n" +
		"waf:\n" +
		"  challenge:\n" +
		"    enabled: true\n" +
		"    difficulty: -1\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	var exitCode int
	var exited bool
	origExit := osExit
	osExit = func(code int) {
		exited = true
		exitCode = code
	}
	defer func() { osExit = origExit }()

	cmdServe([]string{"-c", cfgPath})

	if !exited {
		t.Fatal("cmdServe returned without requesting process exit on challenge-init failure")
	}
	if exitCode != 1 {
		t.Fatalf("challenge-init failure requested exit code %d, want 1", exitCode)
	}
}
