package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBuildPrerequisitesNodeEngineRanges(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Bash source-build prerequisite check")
	}
	script, err := filepath.Abs("../../scripts/check-prereqs.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		version  string
		accepted bool
	}{
		{"20.19.0", false}, {"22.22.0", false}, {"22.22.1", false}, {"22.22.2", true},
		{"23.0.0", false}, {"24.14.0", false}, {"24.15.0", true}, {"25.9.0", false}, {"26.0.0", true},
	} {
		t.Run(tc.version, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range map[string]string{"go": "printf 'go1.26.10\\n'", "node": "printf 'v" + tc.version + "\\n'", "npm": "printf '12.0.2\\n'"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", script)
			for _, e := range os.Environ() {
				if !strings.HasPrefix(e, "PATH=") {
					cmd.Env = append(cmd.Env, e)
				}
			}
			cmd.Env = append(cmd.Env, "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.accepted {
				t.Fatalf("Node %s accepted=%v want %v: %s", tc.version, err == nil, tc.accepted, out)
			}
		})
	}
}
