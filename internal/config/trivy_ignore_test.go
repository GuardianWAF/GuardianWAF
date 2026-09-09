package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestTrivyIgnoreEntriesNotExpired enforces the EXPIRES dates documented in
// .trivyignore: an ignore entry is a temporary policy decision, not a
// permanent suppression. When a date passes, this test fails until the entry
// is re-evaluated and removed (or its expiry is consciously extended with
// fresh justification).
func TestTrivyIgnoreEntriesNotExpired(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", ".trivyignore"))
	if err != nil {
		t.Fatalf("reading .trivyignore: %v", err)
	}

	re := regexp.MustCompile(`^#\s*EXPIRES:\s*(\d{4}-\d{2}-\d{2})`)
	found := 0
	for _, line := range strings.Split(string(contents), "\n") {
		m := re.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		found++
		deadline, err := time.Parse("2006-01-02", m[1])
		if err != nil {
			t.Fatalf("unparseable EXPIRES date %q in .trivyignore: %v", m[1], err)
		}
		if time.Now().After(deadline) {
			t.Errorf(".trivyignore ignore entry expired on %s — re-scan the affected images (expect openssl >= 3.5.8-r0 for CVE-2026-14456) and remove the entry, or consciously extend the date with fresh justification", m[1])
		}
	}
	if found == 0 {
		t.Error(".trivyignore carries no EXPIRES date; every temporary ignore must document one")
	}
}
