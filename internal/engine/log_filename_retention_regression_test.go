package engine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLogRetentionUsesLiteralFilename(t *testing.T) {
	for _, name := range []string{"plain.log", "access[.log", "[access].log", "access].log"} {
		for _, limit := range []int{1, 2} {
			p := filepath.Join(t.TempDir(), name)
			for i := 1; i <= 3; i++ {
				if err := os.WriteFile(fmt.Sprintf("%s.%d", p, i), []byte("backup"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			w, err := NewRotatingFileWriter(p, 1, limit, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err = w.Close(); err != nil {
				t.Fatal(err)
			}
			for i := 1; i <= 3; i++ {
				_, err := os.Stat(fmt.Sprintf("%s.%d", p, i))
				if i <= limit && err != nil || i > limit && !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("%s generation %d limit %d: %v", name, i, limit, err)
				}
			}
		}
	}
	t.Log("FIX VERIFIED")
}
