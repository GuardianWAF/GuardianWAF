// Package smuggling detects HTTP request smuggling attempts.
//
// Request smuggling exploits differences in how frontend (WAF/proxy) and
// backend servers parse HTTP requests. An attacker sends ambiguous framing
// — conflicting Content-Length and Transfer-Encoding headers, duplicate
// headers, or obfuscated encoding values — to make the WAF and backend
// disagree on where one request ends and the next begins. The "second"
// request (smuggled past the WAF) executes on the backend without inspection.
//
// This detector inspects the parsed headers for the five smuggling vectors
// that survive Go's net/http parser:
//
//   - CL.TE / TE.CL: both Content-Length and Transfer-Encoding present
//   - CL.CL: duplicate Content-Length headers with different values
//   - TE.TE: Transfer-Encoding not exactly "chunked" (obfuscation)
//   - TE.TE: multiple Transfer-Encoding headers
//   - HTTP/1.0 + Transfer-Encoding (non-standard framing)
//
// Go's net/http rejects some of these at the transport level, but a WAF must
// assume the backend is a different implementation (nginx, Node, Apache) with
// different parsing quirks. Blocking at the WAF eliminates the ambiguity
// before it reaches the backend.
package smuggling

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Detector implements engine.Detector for HTTP request smuggling.
type Detector struct {
	enabled    bool
	multiplier float64
}

// NewDetector creates a smuggling detector.
func NewDetector(enabled bool, multiplier float64) *Detector {
	return &Detector{enabled: enabled, multiplier: multiplier}
}

func (d *Detector) Name() string         { return "smuggling-detector" }
func (d *Detector) Order() int           { return 0 }
func (d *Detector) DetectorName() string { return "smuggling" }
func (d *Detector) Patterns() []string {
	return []string{
		"cl-te-conflict",
		"te-cl-conflict",
		"duplicate-content-length",
		"obfuscated-transfer-encoding",
		"duplicate-transfer-encoding",
		"http10-transfer-encoding",
	}
}

// Process inspects request headers for smuggling indicators.
func (d *Detector) Process(ctx *engine.RequestContext) engine.LayerResult {
	start := time.Now()
	if !d.enabled {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}

	var findings []engine.Finding

	cl := ctx.Headers["Content-Length"]
	te := ctx.Headers["Transfer-Encoding"]

	hasCL := len(cl) > 0
	hasTE := len(te) > 0

	// --- Vector 1: CL + TE coexistence (CL.TE / TE.CL) ---
	if hasCL && hasTE {
		findings = append(findings, engine.Finding{
			DetectorName: "smuggling",
			Category:     "http-request-smuggling",
			Severity:     engine.SeverityCritical,
			Score:        100,
			Description:  "request carries both Content-Length and Transfer-Encoding headers — CL.TE or TE.CL smuggling vector",
			MatchedValue: "CL=" + strings.Join(cl, ",") + " TE=" + strings.Join(te, ","),
			Location:     "headers",
			Confidence:   0.99,
		})
	}

	// --- Vector 2: Duplicate Content-Length with different values ---
	if len(cl) > 1 {
		distinct := distinctInts(cl)
		if len(distinct) > 1 {
			findings = append(findings, engine.Finding{
				DetectorName: "smuggling",
				Category:     "http-request-smuggling",
				Severity:     engine.SeverityCritical,
				Score:        90,
				Description:  "duplicate Content-Length headers with different values — CL.CL smuggling vector",
				MatchedValue: strings.Join(cl, ","),
				Location:     "headers",
				Confidence:   0.97,
			})
		}
	}

	// --- Vector 3: Obfuscated Transfer-Encoding ---
	if hasTE {
		for _, v := range te {
			if !isExactChunked(v) {
				findings = append(findings, engine.Finding{
					DetectorName: "smuggling",
					Category:     "http-request-smuggling",
					Severity:     engine.SeverityCritical,
					Score:        85,
					Description:  "Transfer-Encoding header is not exactly 'chunked' — TE obfuscation smuggling vector",
					MatchedValue: v,
					Location:     "headers",
					Confidence:   0.95,
				})
				break
			}
		}
	}

	// --- Vector 4: Multiple Transfer-Encoding headers ---
	if len(te) > 1 {
		findings = append(findings, engine.Finding{
			DetectorName: "smuggling",
			Category:     "http-request-smuggling",
			Severity:     engine.SeverityHigh,
			Score:        70,
			Description:  "multiple Transfer-Encoding headers — duplicate TE smuggling vector",
			MatchedValue: strings.Join(te, ","),
			Location:     "headers",
			Confidence:   0.90,
		})
	}

	// --- Vector 5: Transfer-Encoding on HTTP/1.0 (non-standard) ---
	proto := ""
	if ctx.Request != nil {
		proto = ctx.Request.Proto
	}
	if hasTE && proto == "HTTP/1.0" {
		findings = append(findings, engine.Finding{
			DetectorName: "smuggling",
			Category:     "http-request-smuggling",
			Severity:     engine.SeverityMedium,
			Score:        40,
			Description:  "Transfer-Encoding header on HTTP/1.0 request — non-standard framing, potential smuggling",
			MatchedValue: proto + " TE=" + strings.Join(te, ","),
			Location:     "headers",
			Confidence:   0.75,
		})
	}

	score := 0
	for _, f := range findings {
		score += f.Score
	}
	if d.multiplier > 0 && d.multiplier != 1 {
		score = int(float64(score) * d.multiplier)
	}

	action := engine.ActionPass
	if len(findings) > 0 {
		action = engine.ActionLog
	}

	return engine.LayerResult{
		Action:   action,
		Findings: findings,
		Score:    score,
		Duration: time.Since(start),
	}
}

// isExactChunked returns true only if the TE value is "chunked" with no
// additional codings. RFC 7230 §4 allows "chunked" as the last coding, but
// anything else ("chunked, identity", "gzip, chunked", bare "identity") is
// either invalid or a smuggling obfuscation. We accept only bare "chunked"
// case-insensitively.
func isExactChunked(v string) bool {
	return strings.EqualFold(strings.TrimSpace(v), "chunked")
}

// distinctInts returns the count of distinct integer values in a header slice.
// Invalid values are treated as distinct from each other (they signal
// malformed framing).
func distinctInts(vals []string) []int {
	var result []int
	for _, v := range vals {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			// Malformed CL value — treat as unique to force a finding
			n = -1
		}
		if !slices.Contains(result, n) {
			result = append(result, n)
		}
	}
	return result
}
