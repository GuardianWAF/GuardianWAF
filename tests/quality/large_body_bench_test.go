package quality

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// largeJSONBody returns a realistic ~150 KB JSON API payload: an array of
// records with prose, URLs, e-mail addresses and numbers.
func largeJSONBody() []byte {
	type item struct {
		ID      int      `json:"id"`
		Title   string   `json:"title"`
		Body    string   `json:"body"`
		Author  string   `json:"author"`
		URL     string   `json:"url"`
		Tags    []string `json:"tags"`
		Price   float64  `json:"price"`
		Visible bool     `json:"visible"`
	}
	prose := "Our quarterly update covers the new select menu, an improved update flow for orders, and the drop in latency " +
		"after moving the cache. Please review the attached notes and reply with any questions before Friday's meeting. "
	items := make([]item, 0, 300)
	for i := range 300 {
		items = append(items, item{
			ID:      i,
			Title:   fmt.Sprintf("Release notes for build %d", i),
			Body:    strings.Repeat(prose, 2),
			Author:  fmt.Sprintf("user%d@example.com", i),
			URL:     fmt.Sprintf("https://www.example.com/products/%d?ref=feed&page=%d", i, i%7),
			Tags:    []string{"news", "release", "q3"},
			Price:   float64(i) * 1.25,
			Visible: i%2 == 0,
		})
	}
	b, _ := json.Marshal(map[string]any{"items": items, "total": len(items)})
	return b
}

func benchmarkBody(b *testing.B, contentType string, body []byte) {
	eng := newPipeline(b)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := range b.N {
		req := httptest.NewRequest("POST", "/api/v1/items", bytes.NewReader(body))
		browserHeaders(req, i)
		req.Header.Set("Content-Type", contentType)
		if ev := eng.Check(req); ev.Score >= 50 {
			b.Fatalf("benign benchmark body scored %d: %v", ev.Score, ev.Findings)
		}
	}
}

func BenchmarkPipeline_LargeJSON(b *testing.B) {
	benchmarkBody(b, "application/json", largeJSONBody())
}

func BenchmarkPipeline_LargeForm(b *testing.B) {
	v := url.Values{}
	prose := "Thanks for the quick reply, the select menu works now and the update went fine. "
	for i := range 200 {
		v.Set(fmt.Sprintf("field%d", i), strings.Repeat(prose, 8))
	}
	benchmarkBody(b, "application/x-www-form-urlencoded", []byte(v.Encode()))
}

func BenchmarkPipeline_LargeText(b *testing.B) {
	prose := "Thanks for the quick reply, the select menu works now and the update went fine. "
	benchmarkBody(b, "text/plain", []byte(strings.Repeat(prose, 1800)))
}
