package main

import (
	"bytes"
	"os"
	"testing"
)

func TestMainEntrypointsStayInSyncAcrossBuildTags(t *testing.T) {
	http3Main, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read http3 main: %v", err)
	}
	defaultMain, err := os.ReadFile("main_default.go")
	if err != nil {
		t.Fatalf("read default main: %v", err)
	}

	http3Main = stripGoBuildLine(http3Main)
	defaultMain = stripGoBuildLine(defaultMain)

	if !bytes.Equal(http3Main, defaultMain) {
		t.Fatal("cmd/guardianwaf/main.go and main_default.go drifted; keep them identical except for the //go:build line until runtime assembly is refactored behind smaller adapters")
	}
}

func stripGoBuildLine(src []byte) []byte {
	lines := bytes.Split(src, []byte{'\n'})
	out := lines[:0]
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("//go:build ")) {
			continue
		}
		out = append(out, line)
	}
	return bytes.Join(out, []byte{'\n'})
}
