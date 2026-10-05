package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGeneratorEmitsCompilableMethods(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "deepcopy-generator")
	if output, err := exec.Command("go", "build", "-o", binary, "main.go").CombinedOutput(); err != nil {
		t.Fatalf("building generator: %v\n%s", err, output)
	}
	for _, tc := range []struct {
		name, fields string
	}{
		{"scalar", "Name string"},
		{"slice", "Name string; Values []string"},
		{"pointer_slice", "Name string; Values []*int"},
		{"pointer_map", "Name string; Values map[string]*int"},
		{"nested_pointer", "Name string; Values []**int"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := "package fixture\nimport \"testing\"\ntype Fixture struct { " + tc.fields + " }\n"
			input := filepath.Join(dir, tc.name+"_input.go")
			if err := os.WriteFile(input, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			methods, err := exec.Command(binary, input).CombinedOutput()
			if err != nil {
				t.Fatalf("generating: %v\n%s", err, methods)
			}
			checks := `
func TestGeneratedMethod(t *testing.T) {
	if ((*Fixture)(nil)).DeepCopy() != nil { t.Fatal("nil receiver") }
	in := &Fixture{Name: "ordinary"}
	out := in.DeepCopy()
	if out == nil || out == in || out.Name != in.Name { t.Fatal("invalid scalar copy") }
}
`
			generated := filepath.Join(dir, tc.name+"_generated_test.go")
			if err := os.WriteFile(generated, []byte(source+string(methods)+checks), 0600); err != nil {
				t.Fatal(err)
			}
			if output, err := exec.Command("go", "test", "-race", "-count=1", generated).CombinedOutput(); err != nil {
				t.Fatalf("generated source: %v\n%s", err, output)
			}
		})
	}
}
