package crs

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression: the from-file operators never read their argument file.
// "@pmf /path" dispatched to the inline-phrase evaluator with the PATH as
// the phrase list, and "@ipMatchF /path" was flattened to "@ipMatch" at
// parse time so the PATH was parsed as CIDRs. From-file rules silently
// never matched their intended contents.

func TestPmfFromFileReadsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "phrases.txt")
	phrases := "secret\npassword\nadmin123\n"
	if err := os.WriteFile(path, []byte(phrases), 0o600); err != nil {
		t.Fatalf("write phrases file: %v", err)
	}

	p := NewParser()
	op, err := p.parseOperator("@pmf " + path)
	if err != nil {
		t.Fatalf("parseOperator: %v", err)
	}

	oe := &OperatorEvaluator{}
	result, err := oe.Evaluate(op, "my password is admin123")
	if err != nil {
		t.Fatalf("FAIL: Evaluate(%q) returned error: %v", "my password is admin123", err)
	}
	if !result {
		t.Fatalf("FAIL: @pmf from file did not match a listed phrase (%q was treated as inline data, file never read)", path)
	}

	miss, err := oe.Evaluate(op, "nothing relevant here")
	if err != nil {
		t.Fatalf("FAIL: Evaluate negative control returned error: %v", miss)
	}
	if miss {
		t.Fatalf("FAIL: @pmf from file matched an unlisted value")
	}
}

func TestIpMatchFFromFileReadsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ips.txt")
	ips := "10.0.0.0/8\n192.168.1.1\n# comment line\n172.16.5.4\n"
	if err := os.WriteFile(path, []byte(ips), 0o600); err != nil {
		t.Fatalf("write ips file: %v", err)
	}

	p := NewParser()
	op, err := p.parseOperator("@ipMatchF " + path)
	if err != nil {
		t.Fatalf("parseOperator: %v", err)
	}
	if op.Type != "@ipMatchF" {
		t.Fatalf("FAIL: @ipMatchF was flattened to %q at parse time — the file-based type is lost", op.Type)
	}

	oe := &OperatorEvaluator{}
	result, err := oe.Evaluate(op, "10.5.5.5")
	if err != nil {
		t.Fatalf("FAIL: Evaluate(%q) returned error: %v", "10.5.5.5", err)
	}
	if !result {
		t.Fatalf("FAIL: @ipMatchF from file did not match a listed CIDR (%q was treated as inline data, file never read)", path)
	}

	exact, err := oe.Evaluate(op, "192.168.1.1")
	if err != nil {
		t.Fatalf("FAIL: Evaluate exact IP returned error: %v", exact)
	}
	if !exact {
		t.Fatalf("FAIL: @ipMatchF from file did not match a listed exact IP")
	}

	miss, err := oe.Evaluate(op, "8.8.8.8")
	if err != nil {
		t.Fatalf("FAIL: Evaluate negative control returned error: %v", miss)
	}
	if miss {
		t.Fatalf("FAIL: @ipMatchF from file matched an unlisted address")
	}
}
