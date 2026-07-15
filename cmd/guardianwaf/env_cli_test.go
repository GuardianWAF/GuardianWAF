package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeEnvTestConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "guardianwaf.yaml")
	if err := os.WriteFile(path, []byte("mode: enforce\nlisten: ':8088'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunCheckRejectsInvalidEnvironmentOverride(t *testing.T) {
	t.Setenv("GWAF_TLS_ENABLED", "tru")

	_, err := runCheck(&CheckOptions{URL: "http://example.com/"})
	if err == nil || !strings.Contains(err.Error(), "GWAF_TLS_ENABLED") {
		t.Fatalf("runCheck() error = %v, want invalid GWAF_TLS_ENABLED error", err)
	}
}

func TestRunCheckRejectsSemanticallyInvalidConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardianwaf.yaml")
	if err := os.WriteFile(path, []byte("mode: typo\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := runCheck(&CheckOptions{ConfigPath: path, URL: "http://example.com/"})
	if err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("runCheck() error = %v, want invalid mode error", err)
	}
}

func TestValidateConfigFileRejectsInvalidEnvironmentOverride(t *testing.T) {
	t.Setenv("GWAF_EVENTS_MAX_EVENTS", "many")

	_, _, err := validateConfigFile(writeEnvTestConfig(t))
	if err == nil || !strings.Contains(err.Error(), "GWAF_EVENTS_MAX_EVENTS") {
		t.Fatalf("validateConfigFile() error = %v, want invalid GWAF_EVENTS_MAX_EVENTS error", err)
	}
}

func TestHealthcheckRejectsInvalidEnvironmentOverride(t *testing.T) {
	t.Setenv("GWAF_TRACING_SAMPLING_RATE", "half")

	if code := cmdHealthcheck(nil); code != 1 {
		t.Fatalf("cmdHealthcheck() code = %d, want 1", code)
	}
}

func TestServeRejectsInvalidEnvironmentOverride(t *testing.T) {
	t.Setenv("GWAF_DASHBOARD_ENABLED", "maybe")
	oldExit := osExit
	defer func() { osExit = oldExit }()
	exitCode := 0
	osExit = func(code int) { exitCode = code }

	cmdServe([]string{"-config", writeEnvTestConfig(t)})
	if exitCode != 1 {
		t.Fatalf("cmdServe() exit code = %d, want 1", exitCode)
	}
}

func TestSidecarRejectsInvalidEnvironmentOverride(t *testing.T) {
	t.Setenv("GWAF_DOCKER_ENABLED", "maybe")
	oldExit := osExit
	defer func() { osExit = oldExit }()
	exitCode := 0
	osExit = func(code int) { exitCode = code }

	cmdSidecar(nil)
	if exitCode != 1 {
		t.Fatalf("cmdSidecar() exit code = %d, want 1", exitCode)
	}
}

func TestAlertCommandRejectsInvalidEnvironmentOverride(t *testing.T) {
	t.Setenv("GWAF_ALERTING_ENABLED", "perhaps")
	oldExit := osExit
	defer func() { osExit = oldExit }()
	exitCode := 0
	osExit = func(code int) { exitCode = code }

	cmdTestAlert([]string{"-config", writeEnvTestConfig(t)})
	if exitCode != 1 {
		t.Fatalf("cmdTestAlert() exit code = %d, want 1", exitCode)
	}
}

func TestAlertCommandRejectsAllWithNoTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardianwaf.yaml")
	content := "mode: enforce\nalerting:\n  enabled: true\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	oldExit := osExit
	defer func() { osExit = oldExit }()
	exitCode := 0
	osExit = func(code int) { exitCode = code }

	cmdTestAlert([]string{"-config", path, "-all"})
	if exitCode != 1 {
		t.Fatalf("cmdTestAlert(-all) exit code = %d, want 1 with no configured targets", exitCode)
	}
}
