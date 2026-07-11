package crs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestLoadRulesFilesystemFailures(t *testing.T) {
	dir := t.TempDir()
	layer := NewLayer(&Config{Enabled: true})

	layer.absPath = func(string) (string, error) { return "", errors.New("abs failed") }
	if err := layer.LoadRules(dir); err == nil || !strings.Contains(err.Error(), "abs failed") {
		t.Fatalf("LoadRules root Abs error = %v", err)
	}

	layer = NewLayer(&Config{Enabled: true})
	layer.walkDir = func(root string, fn fs.WalkDirFunc) error {
		return fn(root, nil, errors.New("walk failed"))
	}
	if err := layer.LoadRules(dir); err == nil || !strings.Contains(err.Error(), "walk failed") {
		t.Fatalf("LoadRules walk error = %v", err)
	}
}

func TestLoadRulesSkipsUnresolvableEntries(t *testing.T) {
	dir := t.TempDir()
	entryPath := filepath.Join(dir, "rule.conf")
	if err := os.WriteFile(entryPath, []byte(`SecAction "id:1,phase:1,pass"`), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		set  func(*Layer)
	}{
		{"entry absolute path", func(layer *Layer) {
			calls := 0
			layer.absPath = func(path string) (string, error) {
				calls++
				if calls == 1 {
					return filepath.Abs(path)
				}
				return "", errors.New("entry abs failed")
			}
		}},
		{"entry relative path", func(layer *Layer) {
			layer.relPath = func(string, string) (string, error) { return "", errors.New("rel failed") }
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			layer := NewLayer(&Config{Enabled: true})
			test.set(layer)
			layer.walkDir = func(root string, fn fs.WalkDirFunc) error {
				return fn(entryPath, entries[0], nil)
			}
			if err := layer.LoadRules(dir); err != nil {
				t.Fatalf("LoadRules: %v", err)
			}
			if len(layer.rules) != 0 {
				t.Fatalf("unexpected rules: %v", layer.rules)
			}
		})
	}
}

func TestLoadRuleFileFiltersParanoiaLevel(t *testing.T) {
	file := filepath.Join(t.TempDir(), "rule.conf")
	if err := os.WriteFile(file, []byte(`SecRule REQUEST_URI "@rx x" "id:1,phase:1,pass"`), 0o600); err != nil {
		t.Fatal(err)
	}
	layer := NewLayer(&Config{Enabled: true, ParanoiaLevel: 0})
	if err := layer.loadRuleFile(file); err != nil {
		t.Fatal(err)
	}
	if len(layer.rules) != 0 {
		t.Fatalf("expected paranoia filter to skip SecRule (PL=1>0), got %d rules", len(layer.rules))
	}
}

func TestParserRemainingEdges(t *testing.T) {
	p := NewParser()
	if _, err := p.ParseFile(`SecAction "phase:nope"`); err == nil {
		t.Fatal("expected SecAction parse error")
	}
	if _, err := NewParser().ParseFile(`SecRule REQUEST_URI "@rx x" "phase:nope"`); err == nil {
		t.Fatal("expected SecRule action parse error")
	}
	if _, err := NewParser().ParseFile(`SecRule REQUEST_URI "@rx x" "chain" REQUEST_METHOD "@eq GET"`); err != nil {
		t.Fatalf("valid chained rule could not parse: %v", err)
	}

	vars, err := p.parseVariables(" |REQUEST_URI")
	if err != nil || len(vars) != 1 {
		t.Fatalf("parseVariables empty part = %#v, %v", vars, err)
	}
	actions, err := p.parseActions(` ,msg:"quoted"`)
	if err != nil || actions.Msg != "quoted" {
		t.Fatalf("parseActions quoted value = %#v, %v", actions, err)
	}
}

func TestMatchWithDeadlineTimeout(t *testing.T) {
	re := regexp.MustCompile(`a`)
	if matches := matchWithDeadline(re, strings.Repeat("b", 1<<20), 0); matches != nil {
		t.Fatalf("expected timeout, got %v", matches)
	}
	if matches := matchWithDeadline(re, "a", time.Second); len(matches) != 1 {
		t.Fatalf("expected match, got %v", matches)
	}
}
