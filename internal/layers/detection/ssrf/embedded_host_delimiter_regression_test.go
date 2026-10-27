package ssrf

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// TestEmbeddedURLHostDelimiters is the F195 regression: the host extracted
// after a URL prefix used to end only at '/', '?', '#', ' ' or '"', so a
// private or encoded target embedded in XML, a single-quoted attribute, or a
// decoded form body ("url=http://10.0.0.5&x=1") carried the trailing markup
// into the "host", every IP parse failed, and the detector scored 0.
func TestEmbeddedURLHostDelimiters(t *testing.T) {
	d := NewDetector(true, 1.0)
	cases := []struct {
		body      string
		wantBlock bool
	}{
		{`<fetch><url>http://10.0.0.5</url></fetch>`, true},
		{`url=http://10.0.0.5&submit=1`, true},
		{`<img src='http://192.168.1.10'>`, true},
		{`<a>http://2130706433</a>`, true},
		{`x=http://10.0.0.5\admin`, true},
		{`<u>http://[fd00::1]</u>`, true},
		{`{"url":"http://10.0.0.5"}`, true},
		{`<fetch><url>http://8.8.8.8</url></fetch>`, false},
		{`url=http://example.com&submit=1`, false},
		{`<img src='https://cdn.example.com/a.png'>`, false},
	}
	for _, tc := range cases {
		ctx := &engine.RequestContext{BodyString: tc.body, Headers: map[string][]string{}}
		got := d.Process(ctx).Score
		if (got >= 50) != tc.wantBlock {
			t.Errorf("body %q: score=%d, wantBlock=%v", tc.body, got, tc.wantBlock)
		}
	}
}

// TestTrailingRootDotIPv4Host is the F196 regression: "10.0.0.5." (DNS root
// label) is the same address to WHATWG URL parsers, but the classifiers parsed
// the host with the dot attached and scored 0.
func TestTrailingRootDotIPv4Host(t *testing.T) {
	d := NewDetector(true, 1.0)
	cases := []struct {
		url       string
		wantBlock bool
	}{
		{"http://10.0.0.5./admin", true},
		{"http://127.0.0.2./", true},
		{"http://169.254.1.1./", true},
		{"http://2130706433./", true},
		{"http://0x7f000001./", true},
		{"http://10.0.0.5.:8080/", true},
		{"//10.0.0.5./x", true},
		{"http://8.8.8.8./", false},
		{"http://example.com./", false},
		{"http://10.0.0.5..example/", false},
	}
	for _, tc := range cases {
		ctx := &engine.RequestContext{QueryParams: map[string][]string{"url": {tc.url}}, Headers: map[string][]string{}}
		got := d.Process(ctx).Score
		if (got >= 50) != tc.wantBlock {
			t.Errorf("url %q: score=%d, wantBlock=%v", tc.url, got, tc.wantBlock)
		}
	}
}
