package engine

import (
	"slices"
	"strings"
)

// headerScanSkip lists request headers the injection detectors do not scan
// as free text: ones each detector already handles (Cookie, Referer,
// User-Agent), protocol and framing headers whose syntax the sanitizer or
// smuggling detector validates, credentials with a fixed encoding, client-IP
// chains, and tracing/client-hint metadata. Everything else is
// application-defined and commonly read by the backend as data
// (X-Original-URL, X-Forwarded-Host, X-Api-Key, X-Tenant, ...), so it is
// scanned like a query parameter.
var headerScanSkip = map[string]bool{
	"Accept": true, "Accept-Charset": true, "Accept-Datetime": true,
	"Accept-Encoding": true, "Accept-Language": true, "Accept-Ranges": true,
	"Access-Control-Request-Headers": true, "Access-Control-Request-Method": true,
	"Authorization": true, "Proxy-Authorization": true,
	"Cache-Control": true, "Connection": true, "Content-Encoding": true,
	"Content-Length": true, "Content-Md5": true, "Content-Type": true,
	"Cookie": true, "Date": true, "Dnt": true, "Expect": true,
	"Forwarded": true, "Host": true, "If-Match": true,
	"If-Modified-Since": true, "If-None-Match": true, "If-Range": true,
	"If-Unmodified-Since": true, "Keep-Alive": true, "Max-Forwards": true,
	"Origin": true, "Pragma": true, "Priority": true, "Range": true,
	"Referer": true, "Te": true, "Trailer": true, "Transfer-Encoding": true,
	"Upgrade": true, "Upgrade-Insecure-Requests": true, "User-Agent": true,
	"Via": true, "Warning": true,
	"X-Forwarded-For": true, "X-Forwarded-Port": true, "X-Forwarded-Proto": true,
	"X-Real-Ip": true, "X-Client-Ip": true, "True-Client-Ip": true,
	"Cf-Connecting-Ip": true, "Cf-Ray": true, "Cf-Ipcountry": true, "Cf-Visitor": true,
	"X-Request-Id": true, "X-Correlation-Id": true, "X-Amzn-Trace-Id": true,
	"Traceparent": true, "Tracestate": true, "Baggage": true,
	"X-Requested-With": true, "Save-Data": true, "Device-Memory": true,
	"Downlink": true, "Ect": true, "Rtt": true, "Viewport-Width": true, //nolint:misspell // Ect is the Effective-Connection-Type client hint
	"Dpr": true, "Width": true, "Purpose": true,
}

// headerScanSkipPrefixes covers header families with the same properties:
// browser-controlled fetch metadata and client hints (Sec-*), and B3 trace
// propagation.
var headerScanSkipPrefixes = []string{"Sec-", "X-B3-"}

func scanHeader(name string) bool {
	if headerScanSkip[name] {
		return false
	}
	for _, p := range headerScanSkipPrefixes {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	return true
}

// CustomHeaderViews returns the raw and sanitizer-normalized values of the
// application-defined request headers (see headerScanSkip), deduplicated.
// Header names are canonical in ctx.Headers.
func (ctx *RequestContext) CustomHeaderViews() []string {
	// Requests carry a handful of custom headers, so a linear dedupe beats a
	// map; every text detector calls this once per request.
	var views []string
	add := func(v string) {
		if v != "" && !slices.Contains(views, v) {
			views = append(views, v)
		}
	}
	for name, vals := range ctx.Headers {
		if !scanHeader(name) {
			continue
		}
		for _, v := range vals {
			add(v)
		}
		for _, v := range ctx.NormalizedHeaders[name] {
			add(v)
		}
	}
	return views
}
