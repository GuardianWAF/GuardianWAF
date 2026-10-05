package apivalidation

import (
	"bufio"
	"encoding/json"
	"strings"
	"testing"
)

func TestYAMLConversionPropagatesScannerErrors(t *testing.T) {
	for _, size := range []int{1, 12, bufio.MaxScanTokenSize - 64, bufio.MaxScanTokenSize, bufio.MaxScanTokenSize + 1} {
		description := strings.Repeat("x", size)
		input := []byte("title: ordinary\ndescription: " + description + "\nafter: retained\n")
		out, err := YAMLToJSON(input)
		if size >= bufio.MaxScanTokenSize {
			if err == nil || out != nil {
				t.Fatalf("size %d: expected scanner error without partial JSON, got %s, %v", size, out, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		var got map[string]any
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatal(err)
		}
		if got["description"] != description || got["after"] != "retained" || got["title"] != "ordinary" {
			t.Fatalf("size %d: incomplete document", size)
		}
	}
	if out, err := YAMLToJSON(nil); err == nil || out != nil {
		t.Fatalf("empty document: got %s, %v", out, err)
	}
	if out, err := YAMLToJSON([]byte("title: ordinary")); err != nil || string(out) != `{"title":"ordinary"}` {
		t.Fatalf("EOF without newline: got %s, %v", out, err)
	}
}
