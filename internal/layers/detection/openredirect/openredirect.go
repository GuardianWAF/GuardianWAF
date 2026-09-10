// Package openredirect detects open-redirect attacks via untrusted
// redirect targets in query parameters and headers.
//
// An open redirect vulnerability exists when an application redirects users
// to a URL specified in a request parameter without validating that the
// target is safe. Attackers exploit this for credential phishing by crafting
// URLs that appear to originate from a trusted domain but actually redirect
// to an attacker-controlled site.
//
// Detection strategy:
//
//   - Inspect common redirect-parameter names (next, url, redirect, etc.)
//   - Also inspect the Location header
//   - Classify each value as internal (relative path, same-host absolute) or
//     external (different scheme/host)
//   - External and scheme-relative (//evil.com) values are flagged
//
// The detector reports but does not block by default; the engine's scoring
// and paranoia level determine whether the request is blocked.
package openredirect

import (
	"net/url"
	"strings"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/sanitizer"
)

// redirectParamNames lists the most commonly abused redirect parameter names.
// Keys are compared case-insensitively (lowercase after normalization).
var redirectParamNames = map[string]bool{
	"redirect":       true,
	"redirect_uri":   true,
	"redirecturl":    true,
	"redirect_to":    true,
	"return":         true,
	"returnurl":      true,
	"return_to":      true,
	"next":           true,
	"nexturl":        true,
	"target":         true,
	"destination":    true,
	"dest":           true,
	"goto":           true,
	"continue":       true,
	"callback":       true,
	"forward":        true,
	"redir":          true,
	"rurl":           true,
	"image_url":      true,
	"oauth_redirect": true,
	"ref":            true,
	"back":           true,
	"successurl":     true,
	"errorurl":       true,
	"checkout_url":   true,
	"return_path":    true,
	"origin":         true,
	"forward_url":    true,
	"redirect_path":  true,
	"location":       true,
}

// Detector implements engine.Detector for open-redirect attempts.
type Detector struct {
	enabled    bool
	multiplier float64
}

// NewDetector creates an open-redirect detector.
func NewDetector(enabled bool, multiplier float64) *Detector {
	return &Detector{enabled: enabled, multiplier: multiplier}
}

func (d *Detector) Name() string         { return "openredirect-detector" }
func (d *Detector) Order() int           { return 0 }
func (d *Detector) DetectorName() string { return "openredirect" }
func (d *Detector) Patterns() []string {
	return []string{
		"external-redirect",
		"scheme-relative-redirect",
		"protocol-relative-redirect",
		"control-char-redirect",
	}
}

// Process inspects query parameters and headers for redirect targets
// pointing to untrusted external hosts.
func (d *Detector) Process(ctx *engine.RequestContext) engine.LayerResult {
	start := time.Now()
	if !d.enabled {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}

	var findings []engine.Finding

	reqHost := hostname(ctx2Host(ctx))

	// Check query parameters (both raw and normalized forms).
	for param, values := range ctx.QueryParams {
		normParam := strings.ToLower(sanitizer.NormalizeAll(param))
		if !redirectParamNames[normParam] {
			continue
		}
		for _, val := range values {
			if f := d.checkValue(val, "query:"+param, reqHost); f != nil {
				findings = append(findings, *f)
			}
		}
	}
	for param, values := range ctx.NormalizedQuery {
		normParam := strings.ToLower(sanitizer.NormalizeAll(param))
		if !redirectParamNames[normParam] {
			continue
		}
		for _, val := range values {
			if f := d.checkValue(val, "nquery:"+param, reqHost); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	// Check redirect-target headers.
	//
	// Referer is deliberately NOT inspected. It is an inbound header stating
	// where the user came *from*; the application never redirects to it, so it
	// is not a redirect target. Treating it as one made an ordinary visitor
	// arriving from any external site look like an open-redirect attempt:
	// `Referer: https://www.google.com/` on host example.com scored 60 against
	// a block_threshold of 50, so every click-through from a search engine,
	// social link or partner site was answered with 403.
	for _, hdr := range []string{"Location"} {
		for _, val := range ctx.Headers[hdr] {
			if f := d.checkValue(val, "header:"+hdr, reqHost); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	score := 0
	action := engine.ActionPass
	for _, f := range findings {
		score += f.Score
	}
	if score > 0 {
		action = engine.ActionBlock
	}

	return engine.LayerResult{
		Action:   action,
		Findings: findings,
		Score:    score,
		Duration: time.Since(start),
	}
}

// checkValue evaluates a single redirect target value and returns a Finding
// if it represents an external or otherwise dangerous redirect.
func (d *Detector) checkValue(rawVal, location, reqHost string) *engine.Finding {
	val := strings.TrimSpace(rawVal)
	if val == "" {
		return nil
	}

	// Detect protocol-relative URLs (//evil.com/path). These bypass
	// simplistic "starts with http" checks while redirecting off-site.
	if strings.HasPrefix(val, "//") {
		host := val[2:]
		if idx := strings.IndexAny(host, "/?#"); idx >= 0 {
			host = host[:idx]
		}
		return &engine.Finding{
			DetectorName: "openredirect",
			Category:     "open-redirect",
			Severity:     engine.SeverityHigh,
			Score:        60,
			Description:  "protocol-relative redirect URL points to external host: " + host,
			MatchedValue: truncate(val, 200),
			Location:     location,
			Confidence:   0.95,
		}
	}

	// Detect backslash confusion. Browsers treat \ as / in special-scheme
	// URLs, but the rewrite is dangerous only when it produces an *authority*:
	// "\\evil.com" or "/\evil.com" become "//evil.com" (protocol-relative) and
	// "https:\\evil.com" becomes "https://evil.com". A single leading backslash
	// is just a path separator — "\evil.com" resolves to the same-origin path
	// "/evil.com" — so matching every leading-"/" form here reported path
	// segments as "external hosts" and blocked legitimate relative redirects
	// like "/settings\profile".
	if strings.Contains(val, `\`) {
		normalized := strings.ReplaceAll(val, `\`, "/")
		if strings.HasPrefix(normalized, "//") || strings.HasPrefix(normalized, "https://") || strings.HasPrefix(normalized, "http://") {
			host := normalized
			if strings.HasPrefix(host, "//") {
				host = host[2:]
			} else if strings.HasPrefix(host, "https://") {
				host = host[8:]
			} else {
				host = host[7:]
			}
			host = strings.TrimLeft(host, "/")
			// Strip scheme if present after normalization.
			if idx := strings.Index(host, "://"); idx >= 0 {
				host = host[idx+3:]
			}
			if idx := strings.IndexAny(host, "/?#"); idx >= 0 {
				host = host[:idx]
			}
			if host != "" && hostname(host) != "" {
				return &engine.Finding{
					DetectorName: "openredirect",
					Category:     "open-redirect",
					Severity:     engine.SeverityHigh,
					Score:        65,
					Description:  "backslash confusion in redirect URL resolves to external host: " + host,
					MatchedValue: truncate(val, 200),
					Location:     location,
					Confidence:   0.88,
				}
			}
		}
	}

	// Detect scheme-without-slash (e.g., "https:evil.com"). Browsers
	// resolve this to https://evil.com, bypassing checks that look for
	// "://". url.Parse sets scheme but leaves host empty (opaque).
	if idx := strings.Index(val, ":"); idx > 0 && idx < 15 {
		prefix := strings.ToLower(val[:idx])
		if (prefix == "http" || prefix == "https") && idx+1 < len(val) && val[idx+1] != '/' {
			rest := strings.TrimLeft(val[idx+1:], "/")
			restHost := rest
			if idx2 := strings.IndexAny(rest, "/?#"); idx2 >= 0 {
				restHost = rest[:idx2]
			}
			if restHost != "" {
				return &engine.Finding{
					DetectorName: "openredirect",
					Category:     "open-redirect",
					Severity:     engine.SeverityHigh,
					Score:        65,
					Description:  "scheme-without-slash redirect to external host: " + truncate(restHost, 100),
					MatchedValue: truncate(val, 200),
					Location:     location,
					Confidence:   0.85,
				}
			}
		}
	}

	// Detect embedded control characters used to spoof the URL parser:
	// \r\n to inject a fake Location header, and ASCII tab — the WHATWG URL
	// parser strips tab/LF/CR from URL input, so "jav\tascript:alert(1)" and
	// "ht\ttps://evil.com" are executable/external in a browser, while
	// url.Parse rejects the raw form ("invalid control character in URL"),
	// which would silently pass every check below. Leading/trailing tabs are
	// already trimmed above; only embedded ones reach this gate.
	if strings.ContainsAny(val, "\r\n\t\x00") {
		return &engine.Finding{
			DetectorName: "openredirect",
			Category:     "open-redirect",
			Severity:     engine.SeverityHigh,
			Score:        70,
			Description:  "redirect value contains control characters (CRLF, tab, or null)",
			MatchedValue: truncate(val, 200),
			Location:     location,
			Confidence:   0.97,
		}
	}

	// Parse as URL to evaluate the scheme and host.
	parsed, err := url.Parse(val)
	if err != nil || parsed == nil {
		return nil
	}

	scheme := strings.ToLower(parsed.Scheme)
	host := parsed.Hostname()

	// Relative paths (no scheme, no host) are internal — safe.
	if scheme == "" && host == "" {
		return nil
	}

	// Explicit http/https with a host — check against the request host.
	// DNS names are case-insensitive: compare case-insensitively, or
	// same-site redirects spelled in a different case (e.g. the app echoing
	// "Host: EXAMPLE.com") are false-positively blocked as external.
	if (scheme == "http" || scheme == "https") && host != "" {
		if !strings.EqualFold(host, reqHost) && !strings.HasSuffix(strings.ToLower(host), "."+strings.ToLower(reqHost)) {
			return &engine.Finding{
				DetectorName: "openredirect",
				Category:     "open-redirect",
				Severity:     engine.SeverityHigh,
				Score:        60,
				Description:  "external redirect target: " + truncate(host, 100),
				MatchedValue: truncate(val, 200),
				Location:     location,
				Confidence:   0.90,
			}
		}
		return nil
	}

	// Any other scheme with a host (e.g., javascript:, data:, file:) is
	// dangerous in a redirect context.
	if scheme != "" && host != "" {
		return &engine.Finding{
			DetectorName: "openredirect",
			Category:     "open-redirect",
			Severity:     engine.SeverityHigh,
			Score:        70,
			Description:  "redirect value uses non-HTTP scheme: " + scheme,
			MatchedValue: truncate(val, 200),
			Location:     location,
			Confidence:   0.92,
		}
	}

	// Schemes like javascript: or data: without a host are still dangerous.
	if scheme != "" {
		lowerVal := strings.ToLower(val)
		if strings.HasPrefix(lowerVal, "javascript:") || strings.HasPrefix(lowerVal, "data:") {
			return &engine.Finding{
				DetectorName: "openredirect",
				Category:     "open-redirect",
				Severity:     engine.SeverityHigh,
				Score:        80,
				Description:  "redirect value uses dangerous scheme: " + scheme,
				MatchedValue: truncate(val, 200),
				Location:     location,
				Confidence:   0.95,
			}
		}
	}

	return nil
}

// ctx2Host extracts the hostname from the RequestContext's Host field.
func ctx2Host(ctx *engine.RequestContext) string {
	if ctx.Request != nil {
		return ctx.Request.Host
	}
	return ""
}

// hostname returns the host portion (without port) of a host:port string.
func hostname(h string) string {
	// Bracketed IPv6 literal: the host is everything between the brackets;
	// anything after ']' is the port. The previous guard used the leading '['
	// only to skip colon-splitting, then relied on TrimSuffix("]") — a no-op
	// when a port follows, so "[2001:db8::1]:8443" came back as
	// "2001:db8::1]:8443" and checkValue misjudged every same-host absolute
	// redirect on such a vhost as external.
	if strings.HasPrefix(h, "[") {
		if end := strings.IndexByte(h, ']'); end >= 0 {
			return h[1:end]
		}
		// Malformed (no closing bracket): return what is there, as before.
		return strings.TrimPrefix(h, "[")
	}
	if idx := strings.LastIndexByte(h, ':'); idx >= 0 {
		return h[:idx]
	}
	return h
}

// truncate limits a string to maxLen characters, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
