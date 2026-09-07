package engine

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression: RotatingFileWriter must recover from a transient rotation
// failure. rotate() closes the live handle before reopening; when the reopen
// fails (EMFILE/ENOSPC/EACCES — all transient in production), the writer used
// to keep the closed handle and an oversized size, so every later Write
// re-entered rotate() whose Close failed with "file already closed": the log
// sink was permanently bricked. The fix tolerates os.ErrClosed on entry and
// rolls back the live-file rename when the reopen fails.
//
// Trigger (no root): unlink the live file and make the directory read-only so
// rotation's reopen must create a file in an unwritable dir -> EACCES. Then
// restore; the writer must resume and rotate normally again.
func TestRotatingFileWriterRecoversAfterTransientRotationFailure(t *testing.T) {
	dir := t.TempDir()
	w, err := NewRotatingFileWriter(filepath.Join(dir, "app.log"), 1, 2, 0)
	if err != nil {
		t.Fatalf("NewRotatingFileWriter: %v", err)
	}
	defer w.Close()

	// Restore dir permissions on every exit path (incl. Skip) before the
	// t.TempDir cleanup defer runs (LIFO).
	dirLocked := false
	defer func() {
		if dirLocked {
			_ = os.Chmod(dir, 0o700)
		}
	}()

	junk := make([]byte, 64*1024)
	for i := 0; i < 18; i++ { // 18 * 64KB > 1MB: exercises a real rotation
		if _, err := w.Write(junk); err != nil {
			t.Fatalf("baseline write %d failed: %v", i, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "app.log.1")); err != nil {
		t.Fatalf("baseline rotation did not produce app.log.1: %v", err)
	}

	// Force rotation's reopen to fail.
	if err := os.Remove(filepath.Join(dir, "app.log")); err != nil {
		t.Fatalf("setup unlink: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("setup chmod: %v", err)
	}
	dirLocked = true

	var triggerErr error
	for i := 0; i < 20; i++ {
		if _, err := w.Write(junk); err != nil {
			triggerErr = err
			break
		}
	}
	if triggerErr == nil {
		t.Skipf("rotation-open failure could not be simulated (dir chmod not enforced?)")
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("restore chmod: %v", err)
	}
	dirLocked = false

	// The writer must resume within a few writes.
	probe := []byte("recovery-probe")
	recovered := false
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		n, err := w.Write(probe)
		if err == nil && n == len(probe) {
			recovered = true
			break
		}
		lastErr = err
	}
	if !recovered {
		t.Fatalf("writer permanently bricked after transient rotation failure; last error: %v", lastErr)
	}

	// Secondary branch: rotation machinery still works after recovery —
	// writing past maxSize again must shift a fresh backup into place.
	for i := 0; i < 18; i++ {
		if _, err := w.Write(junk); err != nil {
			t.Fatalf("post-recovery write %d failed: %v", i, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "app.log.1")); err != nil {
		t.Fatalf("post-recovery rotation did not produce app.log.1: %v", err)
	}
}
