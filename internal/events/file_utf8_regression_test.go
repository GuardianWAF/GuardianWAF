package events

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func fileUTF8Event(contentType string) engine.Event {
	ctx := &engine.RequestContext{
		Headers: map[string][]string{
			"User-Agent":   {"file-utf8-regression/1.0"},
			"Content-Type": {contentType},
		},
		StartTime: time.Unix(1_700_000_000, 0),
		Method:    "GET",
		Path:      "/file-utf8-regression",
	}
	return engine.NewEvent(ctx, 200)
}

func TestFileStoreWritesValidUTF8JSONForRequestMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	store, err := NewFileStore(path, 0)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cases := []struct {
		name        string
		contentType string
		want        string
	}{
		{name: "ASCII control", contentType: "application/json", want: "application/json"},
		{name: "valid Unicode is preserved", contentType: "text/π", want: "text/π"},
		{
			name:        "separate invalid byte runs are replaced",
			contentType: string([]byte{'t', 'e', 'x', 't', '/', 0xff, 'x', 0xfe}),
			want:        "text/�x�",
		},
	}
	for _, tc := range cases {
		if err := store.Store(fileUTF8Event(tc.contentType)); err != nil {
			t.Fatalf("Store(%s): %v", tc.name, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open JSONL: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for i, tc := range cases {
		if !scanner.Scan() {
			t.Fatalf("record %d (%s) missing: %v", i, tc.name, scanner.Err())
		}
		line := append([]byte(nil), scanner.Bytes()...)
		if !utf8.Valid(line) {
			t.Fatalf("record %d (%s) is not valid UTF-8: %q", i, tc.name, line)
		}
		var decoded struct {
			ContentType string `json:"content_type"`
		}
		if err := json.Unmarshal(line, &decoded); err != nil {
			t.Fatalf("record %d (%s) is not valid JSON: %v", i, tc.name, err)
		}
		if decoded.ContentType != tc.want {
			t.Errorf("record %d (%s) content_type = %q, want %q", i, tc.name, decoded.ContentType, tc.want)
		}
	}
	if scanner.Scan() {
		t.Fatalf("unexpected extra JSONL record: %q", scanner.Bytes())
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan JSONL: %v", err)
	}
}
