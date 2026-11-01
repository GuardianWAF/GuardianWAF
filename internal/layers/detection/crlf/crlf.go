// Package crlf detects CR/LF injection: HTTP response splitting and header
// injection (an injected Set-Cookie, Location, status line or body), and
// SMTP/IMAP command or mail-header injection through a value that a backend
// forwards to a mail server.
//
// The sanitizer collapses line breaks to spaces, so this detector reads the
// raw views and decodes them itself with the line breaks kept.
package crlf

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Detector implements engine.Detector for CR/LF injection.
type Detector struct {
	enabled    bool
	multiplier float64
}

// NewDetector creates a new CR/LF injection detector.
func NewDetector(enabled bool, multiplier float64) *Detector {
	return &Detector{enabled: enabled, multiplier: multiplier}
}

// Name returns the layer name.
func (d *Detector) Name() string { return "crlf-detector" }

// Order returns the execution order of this detector (managed by the layer).
func (d *Detector) Order() int { return 0 }

// DetectorName returns the detector identifier.
func (d *Detector) DetectorName() string { return "crlf" }

// Patterns returns the attack pattern classes this detector recognizes.
func (d *Detector) Patterns() []string {
	return []string{
		"response-header-injection",
		"response-splitting",
		"smtp-command-injection",
		"imap-command-injection",
		"mail-header-injection",
	}
}

// Process scans the request context for CR/LF injection.
func (d *Detector) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !d.enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	var allFindings []engine.Finding
	seen := make(map[[2]string]struct{})
	scan := func(v, location string) {
		if v == "" {
			return
		}
		key := [2]string{location, v}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		allFindings = append(allFindings, Detect(v, location)...)
	}

	scan(ctx.Path, "path")
	scan(ctx.NormalizedPath, "path")
	for k, values := range ctx.QueryParams {
		scan(k, "query")
		for _, v := range values {
			scan(v, "query")
		}
	}
	for _, v := range ctx.BodyViews() {
		scan(v, "body")
	}
	for _, v := range ctx.CookieViews() {
		scan(v, "cookie")
	}
	for _, name := range []string{"User-Agent", "Referer"} {
		for _, v := range ctx.Headers[name] {
			scan(v, "header")
		}
	}
	for _, v := range ctx.CustomHeaderViews() {
		scan(v, "header")
	}

	engine.ApplyMultiplier(allFindings, d.multiplier)

	action := engine.ActionPass
	total := 0
	for _, f := range allFindings {
		total += f.Score
	}
	if total > 0 {
		action = engine.ActionLog
	}
	return engine.LayerResult{Action: action, Findings: allFindings, Score: total}
}

// maxScan bounds the work per value. Injection sits at the start of a field;
// a value past this size is a document, not a header or mail field.
const maxScan = 8 << 10

var (
	headerLine = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9-]{0,40}):[ \t]*(.*)$`)
	statusLine = regexp.MustCompile(`^HTTP/\d(?:\.\d)?[ \t]+\d{3}\b`)
	mimeType   = regexp.MustCompile(`^[A-Za-z]+/[A-Za-z0-9.+*-]+`)
	smtpArg    = regexp.MustCompile(`(?i)^(?:MAIL[ \t]+FROM|RCPT[ \t]+TO)[ \t]*:`)
	smtpHello  = regexp.MustCompile(`^(?:EHLO|HELO)[ \t]+\S`)
	smtpBare   = regexp.MustCompile(`^(?:QUIT|RSET|NOOP|DATA|STARTTLS)[ \t]*$`)
	smtpQuery  = regexp.MustCompile(`^(?:VRFY|EXPN)[ \t]+\S`)
	imapTagged = regexp.MustCompile(`^[A-Za-z]{1,3}\d{1,5}[ \t]+(?:CAPABILITY|FETCH|LOGIN|LIST|LSUB|SELECT|EXAMINE|STORE|LOGOUT|NOOP|AUTHENTICATE|STARTTLS|SEARCH|UID|APPEND|CREATE|DELETE)\b`)
	mailHeader = map[string]bool{"to": true, "cc": true, "bcc": true, "from": true, "reply-to": true}
)

// Detect scans a single input for CR/LF injection.
func Detect(input, location string) []engine.Finding {
	if len(input) > maxScan {
		input = input[:maxScan]
	}
	if !hasBreakSyntax(input) {
		return nil
	}
	lines := splitLines(decode(input))
	if len(lines) < 2 {
		return nil
	}

	// A value that is a short token followed by a break is the shape of a
	// field that should have been one line. A long multi-line value is
	// ordinary prose or a pasted document, so weaker signals only log there.
	injectionShaped := len(lines[0]) <= 64 && len(lines) <= 6

	var findings []engine.Finding
	add := func(score int, sev engine.Severity, desc, matched string) {
		findings = append(findings, makeFinding(score, sev, desc, matched, location, 0.85))
	}
	emptyBefore := false
	for _, line := range lines[1:] {
		if line == "" {
			emptyBefore = true
			continue
		}
		afterBlank := emptyBefore
		emptyBefore = false

		switch {
		case statusLine.MatchString(line):
			add(75, engine.SeverityHigh, "HTTP response splitting: status line injected via CR/LF", line)
		case afterBlank && len(lines) <= 8 && (line[0] == '<' || strings.HasPrefix(line, "HTTP/")):
			add(60, engine.SeverityHigh, "HTTP response splitting: body injected after a blank line", line)
		case smtpArg.MatchString(line):
			add(75, engine.SeverityHigh, "SMTP command injection via CR/LF", line)
		case smtpHello.MatchString(line), smtpQuery.MatchString(line):
			add(smtpScore(60, injectionShaped), engine.SeverityHigh, "SMTP command injection via CR/LF", line)
		case smtpBare.MatchString(line):
			add(smtpScore(55, injectionShaped), engine.SeverityHigh, "SMTP command injection via CR/LF", line)
		case imapTagged.MatchString(line):
			add(smtpScore(70, injectionShaped), engine.SeverityHigh, "IMAP command injection via CR/LF", line)
		default:
			if m := headerLine.FindStringSubmatch(line); m != nil {
				if score, desc := headerScore(strings.ToLower(m[1]), m[2], injectionShaped); score > 0 {
					sev := engine.SeverityHigh
					if score < 50 {
						sev = engine.SeverityLow
					}
					add(score, sev, desc, line)
				}
			}
		}
	}
	return dedupe(findings)
}

// smtpScore keeps a protocol-verb finding at full strength only when the
// value is shaped like an injected field; elsewhere it is a logged hint.
func smtpScore(score int, injectionShaped bool) int {
	if injectionShaped {
		return score
	}
	return 30
}

// headerScore scores an injected "Name: value" line. Only response-affecting
// and mail headers count, and only with a value shaped as that header takes.
func headerScore(name, value string, injectionShaped bool) (int, string) {
	switch name {
	case "set-cookie", "set-cookie2":
		return 75, "HTTP response header injection: Set-Cookie injected via CR/LF"
	case "location":
		if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "//") {
			return headerWeight(60, injectionShaped), "HTTP response header injection: Location injected via CR/LF"
		}
	case "content-type":
		if mimeType.MatchString(value) {
			return headerWeight(55, injectionShaped), "HTTP response header injection: Content-Type injected via CR/LF"
		}
	case "content-length":
		if value != "" && strings.Trim(value, "0123456789") == "" {
			return headerWeight(55, injectionShaped), "HTTP response header injection: Content-Length injected via CR/LF"
		}
	case "content-disposition", "content-security-policy", "strict-transport-security",
		"x-xss-protection", "access-control-allow-origin", "access-control-allow-credentials",
		"transfer-encoding":
		return headerWeight(55, injectionShaped), "HTTP response header injection via CR/LF: " + name
	case "refresh":
		if strings.Contains(strings.ToLower(value), "url=") {
			return headerWeight(60, injectionShaped), "HTTP response header injection: Refresh injected via CR/LF"
		}
	default:
		if mailHeader[name] && strings.Contains(value, "@") {
			return headerWeight(65, injectionShaped), "Mail header injection via CR/LF: " + name
		}
	}
	return 0, ""
}

func headerWeight(score int, injectionShaped bool) int {
	if injectionShaped {
		return score
	}
	return 30
}

func dedupe(in []engine.Finding) []engine.Finding {
	if len(in) < 2 {
		return in
	}
	best := make(map[string]int, len(in))
	out := in[:0:0]
	for _, f := range in {
		if i, ok := best[f.Description]; ok {
			if f.Score > out[i].Score {
				out[i] = f
			}
			continue
		}
		best[f.Description] = len(out)
		out = append(out, f)
	}
	return out
}

// hasBreakSyntax is the cheap pre-check: a real or encoded line break, or a
// rune that truncates to one.
func hasBreakSyntax(s string) bool {
	if strings.ContainsAny(s, "\r\n嘊嘍") {
		return true
	}
	if !strings.Contains(s, "%") && !strings.Contains(s, `\`) {
		return false
	}
	l := strings.ToLower(s)
	return strings.Contains(l, "%0a") || strings.Contains(l, "%0d") ||
		strings.Contains(l, "%250a") || strings.Contains(l, "%250d") ||
		strings.Contains(l, `\u000a`) || strings.Contains(l, `\u000d`) ||
		strings.Contains(l, `\x0a`) || strings.Contains(l, `\x0d`)
}

// decode percent-decodes s up to three rounds, tolerating malformed escapes,
// and maps the runes whose low byte is CR or LF (U+560D, U+560A) onto them:
// backends that truncate runes to bytes split headers on these. Line breaks
// are preserved.
func decode(s string) string {
	for range 3 {
		next := unescapeLoose(s)
		if next == s {
			break
		}
		s = next
	}
	s = strings.NewReplacer("嘍", "\r", "嘊", "\n",
		`\u000d`, "\r", `\u000a`, "\n", `\U000d`, "\r", `\U000a`, "\n",
		`\x0d`, "\r", `\x0a`, "\n").Replace(s)
	return s
}

// unescapeLoose decodes valid %XX escapes and leaves malformed ones as is.
func unescapeLoose(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if dec, err := url.PathUnescape(s[i : i+3]); err == nil && len(dec) == 1 {
				b.WriteString(dec)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// splitLines splits on CRLF, CR and LF.
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Split(s, "\n")
}

func makeFinding(score int, severity engine.Severity, desc, matched, location string, confidence float64) engine.Finding {
	if len(matched) > 200 {
		matched = matched[:197] + "..."
	}
	return engine.Finding{
		DetectorName: "crlf",
		Category:     "crlf",
		Severity:     severity,
		Score:        score,
		Description:  desc,
		MatchedValue: matched,
		Location:     location,
		Confidence:   confidence,
	}
}
