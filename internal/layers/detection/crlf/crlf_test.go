package crlf

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func maxScore(f []engine.Finding) int {
	m := 0
	for _, x := range f {
		m = max(m, x.Score)
	}
	return m
}

func TestDetectsInjection(t *testing.T) {
	attacks := []string{
		"\nSet-Cookie:crlf=injection",
		"%0ASet-cookie:crlf=injection",
		"%0D%0ASet-cookie:crlf=injection",
		"%0A%0DSet-cookie:crlf=injection",
		"\r\nSet-Cookie: session=evil; Path=/",
		"index.html%0d%0aSet-Cookie:%20a=b",
		"/home\r\nLocation: https://evil.example/",
		"x\r\nContent-Type: text/html\r\nContent-Length: 20\r\n\r\n<html>pwn</html>",
		"x\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html",
		"嘊嘍Set-Cookie:crlf=injection", // U+560A U+560D truncate to LF CR
		"%250d%250aSet-Cookie:a=b",    // double encoded
		"user@example.com\r\nBcc: victim@example.net",
		"name\r\nCc: victim@example.net",
		"\nQUIT\n",
		"\nRCPT TO: test@evil.com\n",
		"a@b.c\r\nMAIL FROM:<x@evil.com>\r\nRCPT TO:<y@evil.com>\r\nDATA",
		"\nV100 CAPABILITY\nV101 FETCH 4791 BODY[]",
		"x\nA001 LOGIN user pass",
		`x\u000d\u000aSet-Cookie: a=b`,
	}
	for _, a := range attacks {
		if got := maxScore(Detect(a, "query")); got < 50 {
			t.Errorf("Detect(%q) score = %d, want >= 50", a, got)
		}
	}
}

func TestIgnoresOrdinaryText(t *testing.T) {
	benign := []string{
		"Set-Cookie: a=b",                                                  // no line break: not injected
		"Hello,\nThanks for the help.\nBest",                               // multi-line prose
		"Title: My day\nDate: today\nBody text",                            // ordinary key: value lines
		"name: Ada\nlocation: Berlin\nrole: dev",                           // "location" without a URL
		"Dear team,\n\nPlease review the draft.\n\nQUIT smoking by Friday", // QUIT not alone
		"line one\r\nline two\r\nline three",
		"to: everyone\nfrom: me",                      // mail header names without an address
		"Subject: lunch\nTo be or not to be",          // subject alone
		"100% sure\nnot 50%0 either",                  // stray percent
		"price 10%\nnext line",                        // percent then break
		"Step 1\nStep 2: run `curl -i`\nStep 3: done", // technical note
		"",
	}
	for _, b := range benign {
		if got := maxScore(Detect(b, "body")); got >= 50 {
			t.Errorf("Detect(%q) score = %d, want < 50", b, got)
		}
	}
}

func TestLongDocumentOnlyLogs(t *testing.T) {
	doc := "Pasted HTTP example:\nGET / HTTP/1.1\nHost: x\nAccept: */*\nContent-Type: application/json\nContent-Length: 12\n\n{\"a\":1}"
	if got := maxScore(Detect(doc, "body")); got >= 50 {
		t.Errorf("pasted HTTP example scored %d, want < 50", got)
	}
}

func TestSetCookieAlwaysBlocksEvenInLongText(t *testing.T) {
	doc := "a\nb\nc\nd\ne\nf\ng\nh\nSet-Cookie: x=y"
	if got := maxScore(Detect(doc, "body")); got < 50 {
		t.Errorf("injected Set-Cookie scored %d, want >= 50", got)
	}
}

func TestProcessScansViews(t *testing.T) {
	d := NewDetector(true, 1.0)
	ctx := &engine.RequestContext{
		QueryParams: map[string][]string{"next": {"/a\r\nSet-Cookie: x=y"}},
	}
	res := d.Process(ctx)
	if res.Score < 50 || len(res.Findings) == 0 {
		t.Fatalf("Process = score %d findings %d, want a block-level finding", res.Score, len(res.Findings))
	}
	if off := NewDetector(false, 1.0).Process(ctx); off.Score != 0 {
		t.Errorf("disabled detector scored %d", off.Score)
	}
}

func FuzzDetect(f *testing.F) {
	for _, s := range []string{"", "%", "%0", "%0d%0a", "\r\n", "a\r\nSet-Cookie:b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _ = Detect(s, "query") })
}
