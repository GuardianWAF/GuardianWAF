package sanitizer

import (
	"encoding/base64"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Base64 values are opaque to every detector: the text they carry only exists
// after the backend decodes it, so "' OR 1=1--" sent as "JyBPUiAxPTEtLQ==" is
// invisible to all of them. The sanitizer finds values that decode to text and
// hands the text to the detection layer through ctx.DecodedViews.
//
// Only values that decode to text count. Random tokens, hashes, keys and
// binary uploads decode to bytes that are not text and are ignored, so no
// ordinary token is rescanned as an attack.
const (
	minWholeToken    = 8         // shortest value treated as base64 on its own
	minEmbeddedToken = 24        // shortest run inside other text
	maxToken         = 64 << 10  // longest value decoded
	maxViews         = 16        // views kept per request
	maxDecodedTotal  = 256 << 10 // decoded bytes kept per request
	maxRunsPerValue  = 8         // embedded runs tried per value
)

type decodeCollector struct {
	views     []engine.DecodedView
	total     int
	seen      map[string]struct{}
	normalize bool
}

func (c *decodeCollector) full() bool {
	return len(c.views) >= maxViews || c.total >= maxDecodedTotal
}

// scan looks for base64 text in one input: the whole value, or runs inside it.
func (c *decodeCollector) scan(source, s string) {
	if c.full() || len(s) < minWholeToken {
		return
	}
	if _, dup := c.seen[s]; dup {
		return
	}
	c.seen[s] = struct{}{}

	whole := strings.TrimSpace(s)
	if len(whole) <= maxToken && isBase64Token(whole) {
		if c.add(source, whole) {
			return
		}
	}
	// A '+' that arrived unescaped in a query string reads as a space.
	if strings.Count(whole, " ") > 0 && len(whole) <= maxToken && !strings.ContainsAny(whole, "\t\r\n") {
		if plus := strings.ReplaceAll(whole, " ", "+"); isBase64Token(plus) && c.add(source, plus) {
			return
		}
	}
	if len(s) < minEmbeddedToken {
		return
	}
	runs := 0
	for i := 0; i < len(s) && runs < maxRunsPerValue && !c.full(); {
		if !isBase64Byte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isBase64Byte(s[j]) {
			j++
		}
		if j-i >= minEmbeddedToken && j-i <= maxToken && (i > 0 || j < len(s)) {
			runs++
			c.add(source, s[i:j])
		}
		i = j
	}
}

// add decodes tok and records the text, then follows one more level of
// base64-in-base64. It reports whether tok decoded to text.
func (c *decodeCollector) add(source, tok string) bool {
	text, ok := decodeBase64Text(tok)
	if !ok {
		return false
	}
	for range 2 {
		if c.full() {
			return true
		}
		if _, dup := c.seen["\x00"+text]; dup {
			return true
		}
		c.seen["\x00"+text] = struct{}{}
		c.total += len(text)
		norm := text
		if c.normalize {
			norm = NormalizeAll(text)
		}
		c.views = append(c.views, engine.DecodedView{Source: "base64:" + source, Raw: text, Normalized: norm})
		next := strings.TrimSpace(text)
		if len(next) < minWholeToken || !isBase64Token(next) {
			break
		}
		inner, ok := decodeBase64Text(next)
		if !ok {
			break
		}
		text = inner
	}
	return true
}

func isBase64Byte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' ||
		b == '+' || b == '/' || b == '-' || b == '_' || b == '='
}

// isBase64Token reports a value made only of one base64 alphabet (standard or
// URL-safe, not mixed) with at most two trailing '=' padding bytes.
func isBase64Token(s string) bool {
	if len(s) < minWholeToken {
		return false
	}
	body := strings.TrimRight(s, "=")
	if len(s)-len(body) > 2 || len(body)%4 == 1 {
		return false
	}
	std, url := false, false
	for i := 0; i < len(body); i++ {
		switch b := body[i]; {
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		case b == '+' || b == '/':
			std = true
		case b == '-' || b == '_':
			url = true
		default:
			return false
		}
	}
	return !(std && url)
}

// decodeBase64Text decodes tok and returns the result only when it is text:
// valid UTF-8 with no control characters other than tab, CR and LF.
func decodeBase64Text(tok string) (string, bool) {
	body := strings.TrimRight(tok, "=")
	enc := base64.RawStdEncoding
	if strings.ContainsAny(body, "-_") {
		enc = base64.RawURLEncoding
	}
	raw, err := enc.DecodeString(body)
	if err != nil || len(raw) < 6 || !utf8.Valid(raw) {
		return "", false
	}
	// A short decode is text only if it is plain ASCII: the chance that random
	// bytes form a short valid multibyte string is too high to trust.
	if len(raw) < 12 {
		for _, b := range raw {
			if b >= 0x80 {
				return "", false
			}
		}
	}
	letters := 0
	for _, r := range string(raw) {
		switch {
		case r == '\t' || r == '\r' || r == '\n':
		case r < 0x20 || r == 0x7f || r == utf8.RuneError:
			return "", false
		}
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' {
			letters++
		}
	}
	// Text carries letters or syntax characters; digits and spaces alone are
	// not worth rescanning ("${7*7}" and "{{7*7}}" have no letters at all).
	if letters == 0 && !strings.ContainsAny(string(raw), "{}$<>'\"();|&`%/\\") {
		return "", false
	}
	return string(raw), true
}

// collectDecodedViews finds base64 text in the request inputs the detectors
// read. normalize mirrors the sanitizer's normalization setting.
func collectDecodedViews(ctx *engine.RequestContext, normalize bool) []engine.DecodedView {
	c := &decodeCollector{seen: make(map[string]struct{}), normalize: normalize}

	for seg := range strings.SplitSeq(ctx.Path, "/") {
		c.scan("path", seg)
	}
	for _, vs := range ctx.QueryParams {
		for _, v := range vs {
			c.scan("query", v)
		}
	}
	if !ctx.BodyBinary {
		if len(ctx.BodyFields) > 0 {
			for _, f := range ctx.BodyFields {
				c.scan("body", f)
			}
		} else if len(ctx.BodyString) <= maxFieldBodyBytes {
			c.scan("body", ctx.BodyString)
		}
	}
	for _, vs := range ctx.Cookies {
		for _, v := range vs {
			c.scan("cookie", v)
		}
	}
	for _, name := range []string{"User-Agent", "Referer"} {
		for _, v := range ctx.Headers[name] {
			c.scan("header", v)
		}
	}
	for _, v := range ctx.CustomHeaderViews() {
		c.scan("header", v)
	}
	c.addJoined(ctx)
	return c.views
}

// addJoined adds the whole query string and urlencoded form body as one text
// when an '&' is really the start of an HTML entity. A raw '&' splits a value
// into separate parameters, so "<svg/onload&equals;alert(1)>" reaches the
// detectors as pieces. Reflecting the raw query string is a known XSS vector,
// so the pieces are read back together. Ordinary "a=1&b=2" queries are left
// alone: joined, parameter names like select and from would read as SQL.
func (c *decodeCollector) addJoined(ctx *engine.RequestContext) {
	if i := strings.IndexByte(ctx.URI, '?'); i >= 0 {
		c.joined("query-string", ctx.URI[i+1:])
	}
	if isFormURLEncoded(ctx.ContentType) && len(ctx.BodyString) <= maxFieldBodyBytes {
		c.joined("body-string", ctx.BodyString)
	}
}

func (c *decodeCollector) joined(source, raw string) {
	if c.full() || len(raw) > maxToken || !hasEntityAmpersand(raw) {
		return
	}
	text := raw
	if d, err := url.QueryUnescape(raw); err == nil {
		text = d
	}
	norm := text
	if c.normalize {
		norm = NormalizeAll(text)
	}
	c.total += len(text)
	c.views = append(c.views, engine.DecodedView{Source: source, Raw: text, Normalized: norm})
}

// hasEntityAmpersand reports an '&' that opens an HTML entity: "&#...", or
// "&" plus 2-10 letters and ';' (also after one level of percent-encoding).
func hasEntityAmpersand(s string) bool {
	if strings.Contains(s, "%26") || strings.Contains(s, "%23") {
		if d, err := url.QueryUnescape(s); err == nil {
			s = d
		}
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '&' || i+1 >= len(s) {
			continue
		}
		if s[i+1] == '#' {
			return true
		}
		j := i + 1
		for j < len(s) && j-i <= 11 && (s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z') {
			j++
		}
		if j-i-1 >= 2 && j < len(s) && s[j] == ';' {
			return true
		}
	}
	return false
}
