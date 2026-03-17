package sanitizer

import (
	"fmt"
	"strings"

	"github.com/ersinkoc/guardianwaf/internal/engine"
)

// SanitizerConfig holds configuration for the sanitizer layer.
type SanitizerConfig struct {
	MaxURLLength   int
	MaxHeaderSize  int
	MaxHeaderCount int
	MaxBodySize    int64
	MaxCookieSize  int
	AllowedMethods []string
	BlockNullBytes bool
	StripHopByHop  bool
}

// hopByHopHeaders are headers that should be stripped when proxying.
var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
}

// ValidateRequest checks the request against structural limits.
// Returns findings for each violation.
func ValidateRequest(ctx *engine.RequestContext, cfg SanitizerConfig) []engine.Finding {
	var findings []engine.Finding

	// URL length check
	if cfg.MaxURLLength > 0 && len(ctx.URI) > cfg.MaxURLLength {
		findings = append(findings, engine.Finding{
			DetectorName: "sanitizer",
			Category:     "sanitizer",
			Severity:     engine.SeverityHigh,
			Score:        40,
			Description:  fmt.Sprintf("URL length %d exceeds maximum %d", len(ctx.URI), cfg.MaxURLLength),
			MatchedValue: truncate(ctx.URI, 200),
			Location:     "uri",
			Confidence:   1.0,
		})
	}

	// Header count check
	if cfg.MaxHeaderCount > 0 && len(ctx.Headers) > cfg.MaxHeaderCount {
		findings = append(findings, engine.Finding{
			DetectorName: "sanitizer",
			Category:     "sanitizer",
			Severity:     engine.SeverityMedium,
			Score:        30,
			Description:  fmt.Sprintf("Header count %d exceeds maximum %d", len(ctx.Headers), cfg.MaxHeaderCount),
			Location:     "header",
			Confidence:   1.0,
		})
	}

	// Header size check (iterate all headers, sum sizes)
	if cfg.MaxHeaderSize > 0 {
		totalHeaderSize := 0
		for name, values := range ctx.Headers {
			totalHeaderSize += len(name)
			for _, v := range values {
				totalHeaderSize += len(v)
			}
		}
		if totalHeaderSize > cfg.MaxHeaderSize {
			findings = append(findings, engine.Finding{
				DetectorName: "sanitizer",
				Category:     "sanitizer",
				Severity:     engine.SeverityMedium,
				Score:        30,
				Description:  fmt.Sprintf("Total header size %d exceeds maximum %d", totalHeaderSize, cfg.MaxHeaderSize),
				Location:     "header",
				Confidence:   1.0,
			})
		}
	}

	// Body size check
	if cfg.MaxBodySize > 0 && int64(len(ctx.Body)) > cfg.MaxBodySize {
		findings = append(findings, engine.Finding{
			DetectorName: "sanitizer",
			Category:     "sanitizer",
			Severity:     engine.SeverityHigh,
			Score:        40,
			Description:  fmt.Sprintf("Body size %d exceeds maximum %d", len(ctx.Body), cfg.MaxBodySize),
			Location:     "body",
			Confidence:   1.0,
		})
	}

	// Cookie size check (iterate all cookies)
	if cfg.MaxCookieSize > 0 {
		for name, value := range ctx.Cookies {
			cookieSize := len(name) + len(value)
			if cookieSize > cfg.MaxCookieSize {
				findings = append(findings, engine.Finding{
					DetectorName: "sanitizer",
					Category:     "sanitizer",
					Severity:     engine.SeverityLow,
					Score:        20,
					Description:  fmt.Sprintf("Cookie '%s' size %d exceeds maximum %d", name, cookieSize, cfg.MaxCookieSize),
					MatchedValue: truncate(value, 200),
					Location:     "cookie",
					Confidence:   1.0,
				})
			}
		}
	}

	// HTTP method check (against AllowedMethods)
	if len(cfg.AllowedMethods) > 0 {
		allowed := false
		for _, m := range cfg.AllowedMethods {
			if strings.EqualFold(ctx.Method, m) {
				allowed = true
				break
			}
		}
		if !allowed {
			findings = append(findings, engine.Finding{
				DetectorName: "sanitizer",
				Category:     "sanitizer",
				Severity:     engine.SeverityHigh,
				Score:        50,
				Description:  fmt.Sprintf("HTTP method '%s' is not allowed", ctx.Method),
				MatchedValue: ctx.Method,
				Location:     "method",
				Confidence:   1.0,
			})
		}
	}

	// Null byte check (in URL, headers, body if BlockNullBytes)
	if cfg.BlockNullBytes {
		if containsNullByte(ctx.URI) {
			findings = append(findings, engine.Finding{
				DetectorName: "sanitizer",
				Category:     "sanitizer",
				Severity:     engine.SeverityHigh,
				Score:        60,
				Description:  "Null byte detected in URL",
				MatchedValue: truncate(ctx.URI, 200),
				Location:     "uri",
				Confidence:   1.0,
			})
		}

		for name, values := range ctx.Headers {
			for _, v := range values {
				if containsNullByte(v) {
					findings = append(findings, engine.Finding{
						DetectorName: "sanitizer",
						Category:     "sanitizer",
						Severity:     engine.SeverityHigh,
						Score:        60,
						Description:  fmt.Sprintf("Null byte detected in header '%s'", name),
						MatchedValue: truncate(v, 200),
						Location:     "header",
						Confidence:   1.0,
					})
				}
			}
		}

		if containsNullByte(ctx.BodyString) {
			findings = append(findings, engine.Finding{
				DetectorName: "sanitizer",
				Category:     "sanitizer",
				Severity:     engine.SeverityHigh,
				Score:        60,
				Description:  "Null byte detected in body",
				MatchedValue: truncate(ctx.BodyString, 200),
				Location:     "body",
				Confidence:   1.0,
			})
		}
	}

	return findings
}

// StripHopByHopHeaders removes hop-by-hop headers from the request context.
func StripHopByHopHeaders(ctx *engine.RequestContext) {
	for _, h := range hopByHopHeaders {
		delete(ctx.Headers, h)
	}
}

// containsNullByte checks for literal null bytes, %00 sequences, and \0 sequences.
func containsNullByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return true
		}
		if s[i] == '%' && i+2 < len(s) && s[i+1] == '0' && s[i+2] == '0' {
			return true
		}
	}
	return false
}

// truncate truncates a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
