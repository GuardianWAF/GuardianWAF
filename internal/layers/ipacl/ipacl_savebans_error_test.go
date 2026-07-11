package ipacl

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type stubTempFile struct {
	name     string
	writeErr error
	closeErr error
	written  atomic.Bool
	closed   atomic.Bool
}

func (f *stubTempFile) Name() string { return f.name }

func (f *stubTempFile) Write(p []byte) (int, error) {
	f.written.Store(true)
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return len(p), nil
}

func (f *stubTempFile) Close() error {
	f.closed.Store(true)
	return f.closeErr
}

func TestSaveBans_ErrorBranches(t *testing.T) {
	cfg := Config{Enabled: true, AutoBan: AutoBanConfig{Enabled: true}}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	layer.AddAutoBan("1.2.3.4", "test", time.Hour)

	origMarshal := jsonMarshal
	origMkdirAll := mkdirAll
	origCreateTemp := createTemp
	origChmod := chmodFile
	origRename := renameFile
	origRemove := removeFile
	defer func() {
		jsonMarshal = origMarshal
		mkdirAll = origMkdirAll
		createTemp = origCreateTemp
		chmodFile = origChmod
		renameFile = origRename
		removeFile = origRemove
	}()

	t.Run("marshal error returns early", func(t *testing.T) {
		jsonMarshal = func(v any) ([]byte, error) { return nil, errors.New("marshal boom") }
		defer func() { jsonMarshal = origMarshal }()

		path := filepath.Join(t.TempDir(), "bans.json")
		layer.SaveBans(path)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected no file on marshal error, stat err=%v", err)
		}
	})

	t.Run("create temp error returns early", func(t *testing.T) {
		createTemp = func(dir, pattern string) (tempFile, error) { return nil, errors.New("temp boom") }
		defer func() { createTemp = origCreateTemp }()

		path := filepath.Join(t.TempDir(), "bans.json")
		layer.SaveBans(path)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected no file on create temp error, stat err=%v", err)
		}
	})

	t.Run("write error closes and removes temp", func(t *testing.T) {
		tmpDir := t.TempDir()
		tmpName := filepath.Join(tmpDir, "tmp.json")
		f := &stubTempFile{name: tmpName, writeErr: errors.New("write boom")}
		var removed string
		createTemp = func(dir, pattern string) (tempFile, error) { return f, nil }
		removeFile = func(name string) error { removed = name; return nil }
		defer func() {
			createTemp = origCreateTemp
			removeFile = origRemove
		}()

		layer.SaveBans(filepath.Join(tmpDir, "bans.json"))
		if !f.closed.Load() {
			t.Fatal("expected temp file to be closed on write error")
		}
		if removed != tmpName {
			t.Fatalf("expected temp file removal %q, got %q", tmpName, removed)
		}
	})

	t.Run("close error removes temp", func(t *testing.T) {
		tmpDir := t.TempDir()
		tmpName := filepath.Join(tmpDir, "tmp.json")
		f := &stubTempFile{name: tmpName, closeErr: errors.New("close boom")}
		var removed string
		createTemp = func(dir, pattern string) (tempFile, error) { return f, nil }
		removeFile = func(name string) error { removed = name; return nil }
		defer func() {
			createTemp = origCreateTemp
			removeFile = origRemove
		}()

		layer.SaveBans(filepath.Join(tmpDir, "bans.json"))
		if !f.written.Load() {
			t.Fatal("expected temp file write before close error")
		}
		if removed != tmpName {
			t.Fatalf("expected temp file removal %q, got %q", tmpName, removed)
		}
	})

	t.Run("chmod error removes temp", func(t *testing.T) {
		tmpDir := t.TempDir()
		tmpName := filepath.Join(tmpDir, "tmp.json")
		f := &stubTempFile{name: tmpName}
		var removed string
		createTemp = func(dir, pattern string) (tempFile, error) { return f, nil }
		chmodFile = func(name string, mode os.FileMode) error { return errors.New("chmod boom") }
		removeFile = func(name string) error { removed = name; return nil }
		defer func() {
			createTemp = origCreateTemp
			chmodFile = origChmod
			removeFile = origRemove
		}()

		layer.SaveBans(filepath.Join(tmpDir, "bans.json"))
		if removed != tmpName {
			t.Fatalf("expected temp file removal %q, got %q", tmpName, removed)
		}
	})

	t.Run("rename error removes temp", func(t *testing.T) {
		tmpDir := t.TempDir()
		tmpName := filepath.Join(tmpDir, "tmp.json")
		f := &stubTempFile{name: tmpName}
		var removed string
		createTemp = func(dir, pattern string) (tempFile, error) { return f, nil }
		chmodFile = func(name string, mode os.FileMode) error { return nil }
		renameFile = func(oldpath, newpath string) error { return errors.New("rename boom") }
		removeFile = func(name string) error { removed = name; return nil }
		defer func() {
			createTemp = origCreateTemp
			chmodFile = origChmod
			renameFile = origRename
			removeFile = origRemove
		}()

		layer.SaveBans(filepath.Join(tmpDir, "bans.json"))
		if removed != tmpName {
			t.Fatalf("expected temp file removal %q, got %q", tmpName, removed)
		}
	})
}
