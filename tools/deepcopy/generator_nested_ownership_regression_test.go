package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func regressionGenerateOwnedCopy(t *testing.T, fields, check string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "generator")
	if out, err := exec.Command("go", "build", "-o", binary, "main.go").CombinedOutput(); err != nil {
		t.Fatalf("build generator: %v %s", err, out)
	}
	input := filepath.Join(dir, "input.go")
	source := "package fixture\nimport \"testing\"\n" + fields + "\n"
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	methods, err := exec.Command(binary, input).CombinedOutput()
	if err != nil {
		t.Fatalf("generate: %v %s", err, methods)
	}
	test := filepath.Join(dir, "generated_test.go")
	if err := os.WriteFile(test, []byte(source+string(methods)+check), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "test", "-race", "-count=1", "-v", test).CombinedOutput()
	return string(out), err
}

func TestGeneratorNestedOwnership(t *testing.T) {
	control, err := regressionGenerateOwnedCopy(t, "type Fixture struct { Values []string }", `func TestCopy(t *testing.T){in:=&Fixture{Values:[]string{"control"}};out:=in.DeepCopy();out.Values[0]="changed";if in.Values[0]!="control"{t.Fatal("control aliases")}}`)
	if err != nil {
		t.Fatal("unaffected flat-slice control failed", control)
	}
	t.Log("CONTROL: generated flat slice owns its values")
	out, err := regressionGenerateOwnedCopy(t, "type Child struct { Values []string };type Fixture struct { Children []Child }", `func TestCopy(t *testing.T){in:=&Fixture{Children:[]Child{{Values:[]string{"accepted"}}}};out:=in.DeepCopy();release:=make(chan struct{});done:=make(chan struct{});go func(){<-release;out.Children[0].Values[0]="copy changed";close(done)}();close(release);<-done;t.Logf("EXPECTED: original=accepted; ACTUAL: original=%s",in.Children[0].Values[0]);if in.Children[0].Values[0]!="accepted"{t.Fatal("PROBLEM CONFIRMED")}}`)
	t.Logf("EXPECTED: independent nested slice; ACTUAL: error=%v\n%s", err, out)
	if err != nil {
		t.Fatal("PROBLEM CONFIRMED")
	}
	if strings.Contains(out, "FAIL") {
		t.Fatal(out)
	}
	t.Log("FIX VERIFIED")
}

func TestGeneratorNestedOwnershipEdges(t *testing.T) {
	fields := `type Child struct { Values []string };type Fixture struct { Children []Child; Pointers []*Child; Map map[string]*Child; Nested map[string][]Child; Scalar *int; Grid [2][]string }`
	check := `
func TestCopy(t *testing.T) {
 in:=&Fixture{};out:=in.DeepCopy();if out.Children!=nil||out.Pointers!=nil||out.Map!=nil||out.Nested!=nil||out.Scalar!=nil {t.Fatal("nil shape changed")}
 in.Children=[]Child{};in.Map=map[string]*Child{};out=in.DeepCopy();if out.Children==nil||out.Map==nil {t.Fatal("empty shape changed")}
 n:=7;in=&Fixture{Children:[]Child{{Values:[]string{"child"}}},Pointers:[]*Child{{Values:[]string{"pointer"}},nil},Map:map[string]*Child{"yes":{Values:[]string{"map"}},"nil":nil},Nested:map[string][]Child{"key":{{Values:[]string{"nested"}}}},Scalar:&n,Grid:[2][]string{{"array"},nil}}
 out=in.DeepCopy();release:=make(chan struct{});done:=make(chan struct{});go func(){<-release;out.Children[0].Values[0]="changed";out.Pointers[0].Values[0]="changed";out.Map["yes"].Values[0]="changed";out.Nested["key"][0].Values[0]="changed";*out.Scalar=9;out.Grid[0][0]="changed";close(done)}();close(release);<-done
 if in.Children[0].Values[0]!="child"||in.Pointers[0].Values[0]!="pointer"||in.Map["yes"].Values[0]!="map"||in.Nested["key"][0].Values[0]!="nested"||n!=7||in.Grid[0][0]!="array" {t.Fatal("nested copy aliases original")}
 if out.Pointers[1]!=nil||out.Map["nil"]!=nil||out.Grid[1]!=nil {t.Fatal("nested nil changed")}
 again:=out.DeepCopy();again.Children[0].Values[0]="twice";if out.Children[0].Values[0]!="changed"{t.Fatal("repeated copy aliases")}
}
`
	out, err := regressionGenerateOwnedCopy(t, fields, check)
	if err != nil {
		t.Fatal(err, out)
	}
}
