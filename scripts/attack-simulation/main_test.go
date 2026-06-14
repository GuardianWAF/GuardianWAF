package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanAttackPayloadPath(t *testing.T) {
	dir := t.TempDir()
	dirty := filepath.Join(dir, "payloads", "..", "attacks.json")

	clean, err := cleanAttackPayloadPath(dirty)
	if err != nil {
		t.Fatalf("cleanAttackPayloadPath returned error: %v", err)
	}
	if clean != filepath.Clean(dirty) {
		t.Fatalf("cleanAttackPayloadPath = %q, want %q", clean, filepath.Clean(dirty))
	}

	if _, err := cleanAttackPayloadPath(""); err == nil {
		t.Fatal("expected empty path to be rejected")
	}
	if _, err := cleanAttackPayloadPath("bad\x00path"); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("expected NUL path rejection, got %v", err)
	}
}

func TestLoadPayloadsRejectsInvalidPath(t *testing.T) {
	payloads = nil

	if err := loadPayloads("bad\x00path"); err == nil {
		t.Fatal("expected invalid path error")
	}
	if len(payloads) != 0 {
		t.Fatalf("payloads appended after invalid path: %v", payloads)
	}
}

func TestLoadPayloadsCleansPath(t *testing.T) {
	payloads = nil
	t.Cleanup(func() { payloads = nil })

	dir := t.TempDir()
	path := filepath.Join(dir, "attacks.json")
	writeAttackPayloadFile(t, path, `{"xss":["<script>alert(1)</script>"],"creds":[{"email":"a@example.com","password":"secret"}]}`)

	dirty := filepath.Join(dir, "nested", "..", "attacks.json")
	if err := loadPayloads(dirty); err != nil {
		t.Fatalf("loadPayloads returned error: %v", err)
	}
	if len(payloads) != 2 {
		t.Fatalf("expected 2 payloads, got %d: %v", len(payloads), payloads)
	}
}

func writeAttackPayloadFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write attack payload file: %v", err)
	}
}
