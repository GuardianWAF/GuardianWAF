package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGenerateDeepCopyTargetTransactional(t *testing.T) {
	work := t.TempDir()
	for _, name := range []string{"Makefile", "go.mod", "tools/deepcopy/main.go", "scripts/generate-deepcopy.sh"} {
		data, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(work, name)
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0755); err != nil {
			t.Fatal(err)
		}
	}
	configDir := filepath.Join(work, "internal", "config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(configDir, "config.go")
	output := filepath.Join(configDir, "deepcopy_generated.go")
	fixture := `package config
import (clock "time"; "strings")
type Fixture struct { Name string; Delays []clock.Duration; private map[string][]string; Hidden hidden; Value any }
type hidden struct { values []string }
func unusedByGenerator() string { return strings.TrimSpace(" ok ") }
`
	if err := os.WriteFile(source, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(wantSuccess bool) {
		t.Helper()
		cmd := exec.Command("make", "generate-deepcopy")
		cmd.Dir = work
		out, err := cmd.CombinedOutput()
		if (err == nil) != wantSuccess {
			t.Fatalf("generation success=%t: %v\n%s", wantSuccess, err, out)
		}
	}
	run(true)
	good, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	checks := `package config
import ("testing"; clock "time")
func TestGeneratedCopy(t *testing.T) {
 in := &Fixture{Name:"control", Delays:[]clock.Duration{1},private:map[string][]string{"key":{"original"}},Hidden:hidden{values:[]string{"original"}}}
 out := in.DeepCopy()
 out.Name="changed"
 if in.Name!="control" { t.Fatal("scalar control") }
 out.Delays[0]=2
 out.private["key"][0]="changed"
 out.Hidden.values[0]="changed"
 if in.Delays[0]!=1 || in.private["key"][0]!="original" || in.Hidden.values[0]!="original" { t.Fatal("mutable fields alias original") }
 if ((*Fixture)(nil)).DeepCopy()!=nil { t.Fatal("nil receiver") }
 empty:=(&Fixture{Delays:[]clock.Duration{},private:map[string][]string{}}).DeepCopy()
 if empty.Delays==nil || empty.private==nil { t.Fatal("empty collections became nil") }
 zero:=(&Fixture{}).DeepCopy()
 if zero.Delays!=nil || zero.private!=nil { t.Fatal("nil collections allocated") }
 for _, value := range []any{[]string{"original"}, []any{"original"}} {
  cloned := (&Fixture{Value:value}).DeepCopy()
  switch v:=cloned.Value.(type) {
  case []string: v[0]="changed"; if value.([]string)[0]!="original" { t.Fatal("string list alias") }
  case []any: v[0]="changed"; if value.([]any)[0]!="original" { t.Fatal("any list alias") }
  }
 }
}
`
	if err := os.WriteFile(filepath.Join(configDir, "copy_test.go"), []byte(checks), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "test", "-race", "-count=1", "./internal/config")
	cmd.Dir = work
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated package: %v\n%s", err, out)
	}
	run(true)
	repeated, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(good, repeated) {
		t.Fatalf("generation not reproducible: %v", err)
	}
	for _, bad := range []string{"package config\ntype Broken struct {", ""} {
		if bad == "" {
			if err := os.Remove(source); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(source, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		run(false)
		preserved, err := os.ReadFile(output)
		if err != nil || !bytes.Equal(good, preserved) {
			t.Fatalf("failed generation changed valid output: %v", err)
		}
	}
}
