//go:build linux

package compliance

// TestAppendChainWithErrorReturnsNewlineWriteError lives behind a linux
// build tag: it measures pipe capacity via the SYS_FCNTL + F_GETPIPE_SZ
// fcntl pair, which exists only on Linux (undefined on Windows; macOS has
// no pipe-size fcntl). The remaining coverage tests in
// compliance_coverage_test.go are platform-neutral and run everywhere.

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

func TestAppendChainWithErrorReturnsNewlineWriteError(t *testing.T) {
	data := map[string]string{"k": strings.Repeat("x", 1024)}
	probe := NewEngine(config.ComplianceConfig{Enabled: true})
	probeEntry, err := probe.AppendChainWithError("event", data)
	if err != nil {
		t.Fatalf("probe AppendChainWithError: %v", err)
	}
	probeJSON, err := json.Marshal(probeEntry)
	if err != nil {
		t.Fatalf("probe Marshal: %v", err)
	}

	for _, delta := range []int{-8, -4, -2, -1, 0, 1, 2, 4, 8, 16} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe: %v", err)
		}

		pipeSize, _, errno := syscall.Syscall(syscall.SYS_FCNTL, w.Fd(), syscall.F_GETPIPE_SZ, 0)
		if errno != 0 {
			_ = r.Close()
			_ = w.Close()
			t.Fatalf("fcntl F_GETPIPE_SZ: %v", errno)
		}

		remaining := len(probeJSON) + delta
		if remaining <= 0 || remaining >= int(pipeSize) {
			_ = r.Close()
			_ = w.Close()
			continue
		}
		prefill := make([]byte, int(pipeSize)-remaining)
		if n, err := w.Write(prefill); err != nil || n != len(prefill) {
			_ = r.Close()
			_ = w.Close()
			t.Fatalf("prefill write = (%d, %v), want (%d, nil)", n, err, len(prefill))
		}

		e := NewEngine(config.ComplianceConfig{Enabled: true})
		e.file = w

		closeDone := make(chan struct{})
		go func() {
			time.Sleep(10 * time.Millisecond)
			_ = r.Close()
			close(closeDone)
		}()

		entry, err := e.AppendChainWithError("event", data)
		<-closeDone
		_ = w.Close()
		e.file = nil
		if errors.Is(err, syscall.EPIPE) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, os.ErrClosed) {
			if entry.Hash == "" {
				t.Fatal("expected computed entry hash")
			}
			if got := e.ChainLen(); got != 0 {
				t.Fatalf("chain length = %d, want 0 after newline write failure", got)
			}
			return
		}
	}

	t.Fatal("expected newline write failure")
}
