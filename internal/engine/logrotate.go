package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// RotatingFileWriter writes to a file with automatic size-based rotation.
// It keeps a configurable number of rotated backups and removes old files
// beyond the age limit.
type RotatingFileWriter struct {
	mu         sync.Mutex
	path       string
	file       *os.File
	size       int64
	maxSize    int64 // bytes
	maxBackups int
	maxAge     time.Duration
}

// NewRotatingFileWriter creates a rotating writer.
// maxSize is in MB, maxBackups is the number of .1, .2, ... files to keep,
// maxAgeDays removes backups older than N days (0 = no age limit).
func NewRotatingFileWriter(path string, maxSizeMB, maxBackups, maxAgeDays int) (*RotatingFileWriter, error) {
	cleanPath, err := cleanRotatingLogPath(path)
	if err != nil {
		return nil, err
	}
	if maxBackups < 1 {
		maxBackups = 5
	}
	if maxSizeMB < 1 {
		maxSizeMB = 100
	}
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create log dir %s: %w", dir, err)
	}

	w := &RotatingFileWriter{
		path:       cleanPath,
		maxSize:    int64(maxSizeMB) * 1024 * 1024,
		maxBackups: maxBackups,
	}
	if maxAgeDays > 0 {
		w.maxAge = time.Duration(maxAgeDays) * 24 * time.Hour
	}

	f, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- operator-selected log sink is rejected on empty/NUL and cleaned before use.
	if err != nil {
		return nil, fmt.Errorf("open log file %s: %w", cleanPath, err)
	}
	w.file = f
	fi, _ := f.Stat()
	if fi != nil {
		w.size = fi.Size()
	}

	w.removeOldBackups()
	return w, nil
}

// Write writes data to the current log file, rotating if needed.
func (w *RotatingFileWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.size+int64(len(p)) > w.maxSize {
		if rotateErr := w.rotate(); rotateErr != nil {
			return 0, rotateErr
		}
	}

	n, err = w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// Close closes the current log file.
func (w *RotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

func (w *RotatingFileWriter) rotate() error {
	if err := w.file.Close(); err != nil {
		return err
	}

	// Shift backups: .N → delete, .N-1 → .N, ..., .1 → .2, current → .1
	for i := w.maxBackups; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", w.path, i)
		if i == w.maxBackups {
			os.Remove(src)
			continue
		}
		dst := fmt.Sprintf("%s.%d", w.path, i+1)
		os.Rename(src, dst)
	}
	os.Rename(w.path, fmt.Sprintf("%s.1", w.path))

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- w.path is normalized by NewRotatingFileWriter before storage.
	if err != nil {
		return err
	}
	w.file = f
	w.size = 0
	return nil
}

// removeOldBackups removes rotated files older than maxAge.
func (w *RotatingFileWriter) removeOldBackups() {
	if w.maxAge <= 0 {
		return
	}
	cutoff := time.Now().Add(-w.maxAge)
	pattern := filepath.Base(w.path) + ".*"
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(w.path), pattern))
	var backups []string
	for _, m := range matches {
		if m == w.path {
			continue
		}
		fi, err := os.Stat(m)
		if err != nil {
			continue
		}
		if fi.ModTime().Before(cutoff) {
			os.Remove(m)
		} else {
			backups = append(backups, m)
		}
	}
	// If still too many, remove oldest
	if len(backups) > w.maxBackups {
		sort.Strings(backups)
		for _, b := range backups[:len(backups)-w.maxBackups] {
			os.Remove(b)
		}
	}
}

// ParseLogOutput returns an io.Writer for the configured log output.
// "stdout" → os.Stdout, "stderr" → os.Stderr, anything else is treated as
// a file path with rotation enabled using the provided limits.
func ParseLogOutput(output string, maxSizeMB, maxBackups, maxAgeDays int) (WriteCloser, error) {
	switch strings.ToLower(output) {
	case "stdout":
		return nopWriteCloser{os.Stdout}, nil
	case "stderr", "":
		return nopWriteCloser{os.Stderr}, nil
	default:
		return NewRotatingFileWriter(output, maxSizeMB, maxBackups, maxAgeDays)
	}
}

func cleanRotatingLogPath(path string) (string, error) {
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("log file path contains NUL byte")
	}
	if path == "" {
		return "", fmt.Errorf("log file path must not be empty")
	}
	return filepath.Clean(path), nil
}

// WriteCloser combines io.Writer and io.Closer.
type WriteCloser interface {
	Write(p []byte) (n int, err error)
	Close() error
}

type nopWriteCloser struct {
	*os.File
}

// Close is intentionally a no-op. nopWriteCloser wraps the process-global
// os.Stdout / os.Stderr, which must NOT be closed — closing fd 1/2 breaks all
// subsequent writes (including the test framework's coverage report). Without
// this override the embedded *os.File.Close would be promoted and actually close
// the descriptor.
func (nopWriteCloser) Close() error { return nil }
