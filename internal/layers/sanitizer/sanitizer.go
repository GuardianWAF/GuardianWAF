package sanitizer

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Layer implements the engine.Layer interface for request sanitization.
type Layer struct {
	config  Config
	enabled bool
	mu      sync.RWMutex
}

// NewLayer creates a new sanitizer layer with the given configuration.
func NewLayer(cfg *Config) *Layer {
	return &Layer{
		config:  *cfg,
		enabled: true,
	}
}

// Name returns "sanitizer".
func (l *Layer) Name() string { return "sanitizer" }
func (l *Layer) Order() int   { return engine.OrderSanitizer }

// InspectionBodyLimit publishes the request's effective size limit before
// the engine reads the body, using exactly the sanitizer's path view.
func (l *Layer) InspectionBodyLimit(path string, tenant *config.WAFConfig) int64 {
	if !l.config.SkipNormalization {
		path = NormalizeAll(path)
	}
	if tenant == nil {
		return l.config.effectiveMaxBodySize(path)
	}
	limit, matched := tenant.Sanitizer.MaxBodySize, 0
	for _, override := range tenant.Sanitizer.PathOverrides {
		if override.Path != "" && strings.HasPrefix(path, override.Path) && len(override.Path) > matched {
			limit, matched = override.MaxBodySize, len(override.Path)
		}
	}
	return limit
}

// SetEnabled enables or disables the sanitizer layer.
func (l *Layer) SetEnabled(enabled bool) {
	l.mu.Lock()
	l.enabled = enabled
	l.mu.Unlock()
}

// Process normalizes and validates the request.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	start := time.Now()

	// Check if sanitizer is enabled (tenant config takes precedence)
	l.mu.RLock()
	enabled := l.enabled
	l.mu.RUnlock()
	if ctx.TenantWAFConfig != nil && !ctx.TenantWAFConfig.Sanitizer.Enabled {
		enabled = false
	}
	if !enabled {
		return engine.LayerResult{Action: engine.ActionPass, Duration: time.Since(start)}
	}

	// Step 1: Normalize all inputs — gated by skip_normalization (the
	// layer view of normalize_encoding: false).
	//
	// With the gate on (normalize_encoding: false) the Normalized* fields
	// carry the RAW values unchanged — raw passthrough, never empty: ctx
	// fields are the shared detector view, and leaving them empty would
	// blind every downstream detector that reads them (the round-30
	// hop-by-hop lesson). Identical raw values dedup in the detectors'
	// both-forms scans, so coverage of unencoded payloads is unchanged;
	// percent/unicode-encoded payloads are accepted as-is — the documented
	// operator trade-off of the gate.
	if !l.config.SkipNormalization {
		ctx.NormalizedPath = NormalizeAll(ctx.Path)

		// Normalize query params
		ctx.NormalizedQuery = make(map[string][]string, len(ctx.QueryParams))
		for k, vs := range ctx.QueryParams {
			normalized := make([]string, len(vs))
			for i, v := range vs {
				normalized[i] = NormalizeAll(v)
			}
			ctx.NormalizedQuery[k] = normalized
		}

		// Normalize body.
		//
		// The engine reads only the effective per-path budget plus a sentinel.
		// Oversized bodies are rejected independently of their finding score;
		// the complete original stream is retained for monitor-mode forwarding.
		ctx.NormalizedBody = NormalizeAll(inspectionBody(ctx))
		if fields := bodyFields(ctx); fields != nil {
			ctx.BodyFields = fields
			ctx.NormalizedBodyFields = make([]string, len(fields))
			for i, f := range fields {
				ctx.NormalizedBodyFields[i] = NormalizeAll(f)
			}
		}

		// Normalize headers
		ctx.NormalizedHeaders = make(map[string][]string, len(ctx.Headers))
		for k, vs := range ctx.Headers {
			normalized := make([]string, len(vs))
			for i, v := range vs {
				normalized[i] = NormalizeAll(v)
			}
			ctx.NormalizedHeaders[k] = normalized
		}
	} else {
		ctx.NormalizedPath = ctx.Path
		ctx.NormalizedQuery = make(map[string][]string, len(ctx.QueryParams))
		for k, vs := range ctx.QueryParams {
			ctx.NormalizedQuery[k] = append([]string(nil), vs...)
		}
		ctx.NormalizedBody = inspectionBody(ctx)
		if fields := bodyFields(ctx); fields != nil {
			ctx.BodyFields = fields
			ctx.NormalizedBodyFields = append([]string(nil), fields...)
		}
		ctx.NormalizedHeaders = make(map[string][]string, len(ctx.Headers))
		for k, vs := range ctx.Headers {
			ctx.NormalizedHeaders[k] = append([]string(nil), vs...)
		}
	}

	ctx.BodyBinary = isBinaryMediaType(ctx.ContentType) && looksBinary(ctx.BodyString)

	// Step 2: Validate
	validationConfig := l.config
	validationConfig.MaxBodySize = l.InspectionBodyLimit(ctx.Path, ctx.TenantWAFConfig)
	validationConfig.PathOverrides = nil
	findings := ValidateRequest(ctx, validationConfig)

	// NOTE: hop-by-hop stripping (strip_hop_by_hop) previously mutated
	// ctx.Headers here. That blinded the order-400 smuggling detector (it
	// reads ctx.Headers["Transfer-Encoding"] for four of its five vectors)
	// while never affecting what the backend receives — the reverse proxy
	// forwards the original *http.Request and never reads ctx.Headers. The
	// mutation was removed; hop-by-hop removal toward the backend needs
	// proxy-forward-side wiring if it is ever wanted.

	// Determine action
	action := engine.ActionPass
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if maxBody := validationConfig.MaxBodySize; maxBody > 0 && int64(len(ctx.Body)) > maxBody {
		// A body limit is an inspection boundary, not a scoring hint: the
		// unread tail may contain an attack that no detector could inspect.
		action = engine.ActionBlock
		ctx.BodyLimitExceeded = true
	} else if totalScore >= 50 {
		action = engine.ActionBlock
	} else if len(findings) > 0 {
		action = engine.ActionLog
	}

	return engine.LayerResult{
		Action:   action,
		Findings: findings,
		Score:    totalScore,
		Duration: time.Since(start),
	}
}

// inspectionBody returns the body as detectors should see it. A
// application/x-www-form-urlencoded body is decoded with form rules ('+' is a
// space, each name and value percent-decoded) — the syntax of the content
// type itself, applied even when encoding normalization is off. Generic URL
// decoding leaves '+' in place, so "q=%27+OR+1%3D1+--" reached detectors as
// "'+OR+1=1+--" and classic payloads in every HTML form scored zero.
func inspectionBody(ctx *engine.RequestContext) string {
	if !isFormURLEncoded(ctx.ContentType) || ctx.BodyString == "" {
		return ctx.BodyString
	}
	pairs := strings.Split(ctx.BodyString, "&")
	for i, pair := range pairs {
		name, value, hasValue := strings.Cut(pair, "=")
		if n, err := url.QueryUnescape(name); err == nil {
			name = n
		}
		if v, err := url.QueryUnescape(value); err == nil {
			value = v
		}
		if hasValue {
			pairs[i] = name + "=" + value
		} else {
			pairs[i] = name
		}
	}
	return strings.Join(pairs, "&")
}

func isFormURLEncoded(contentType string) bool {
	mediaType, _, _ := strings.Cut(contentType, ";")
	return strings.EqualFold(strings.TrimSpace(mediaType), "application/x-www-form-urlencoded")
}

// looksBinary reports whether s holds binary data: a NUL byte or invalid
// UTF-8. Text sent under a binary media type is still inspected.
func looksBinary(s string) bool {
	return strings.IndexByte(s, 0) >= 0 || !utf8.ValidString(s)
}

// multipartBoundary returns the boundary of a multipart/form-data body.
func multipartBoundary(contentType string) (string, bool) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "multipart/form-data") || params["boundary"] == "" {
		return "", false
	}
	return params["boundary"], true
}

// multipartFields extracts field names, field values, raw upload filenames
// and textual upload contents from a multipart/form-data body. Binary
// uploads (invalid UTF-8 or NUL bytes) are skipped. Any parse error returns
// nil so the raw body is inspected instead.
func multipartFields(body, boundary string) []string {
	mr := multipart.NewReader(strings.NewReader(body), boundary)
	var fields []string
	for {
		part, err := mr.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil
		}
		// Read Content-Disposition directly: Part.FileName applies
		// filepath.Base, which would hide "../../etc/passwd" filenames.
		_, params, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		if err != nil {
			return nil
		}
		content, err := io.ReadAll(part)
		if err != nil {
			return nil
		}
		filename, isFile := params["filename"]
		for _, f := range []string{params["name"], filename} {
			if f != "" {
				fields = append(fields, f)
			}
		}
		if len(content) > 0 && (!isFile || utf8.Valid(content) && bytes.IndexByte(content, 0) < 0) {
			fields = append(fields, string(content))
		}
		if len(fields) > maxBodyFields {
			return nil
		}
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

// Bounds on structured-body field extraction. Bodies outside them fall back
// to whole-body inspection, so a large or deeply structured body is never
// inspected less than before.
const (
	maxFieldBodyBytes = 1 << 20
	maxBodyFields     = 10000
)

// bodyFields extracts the decoded string leaves of a JSON or urlencoded form
// body: keys/names and string values, with JSON escapes and form encoding
// resolved. Text detectors scan these individually, because the raw syntax
// both hides payloads ({"user":"admin' --"} reads as one closed string) and
// fabricates them (":"# heading" reads as a quote followed by a comment).
// Returns nil when the body is not structured or cannot be parsed.
func bodyFields(ctx *engine.RequestContext) []string {
	body := ctx.BodyString
	if body == "" || len(body) > maxFieldBodyBytes {
		return nil
	}
	if isFormURLEncoded(ctx.ContentType) {
		var fields []string
		for pair := range strings.SplitSeq(body, "&") {
			name, value, _ := strings.Cut(pair, "=")
			for _, part := range []string{name, value} {
				if decoded, err := url.QueryUnescape(part); err == nil {
					part = decoded
				}
				if part != "" {
					fields = append(fields, part)
				}
			}
			if len(fields) > maxBodyFields {
				return nil
			}
		}
		return fields
	}
	if boundary, ok := multipartBoundary(ctx.ContentType); ok {
		return multipartFields(body, boundary)
	}
	if !looksLikeJSON(ctx.ContentType, body) {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil || dec.More() {
		return nil
	}
	fields := make([]string, 0, 16)
	var walk func(v any) bool
	walk = func(v any) bool {
		switch t := v.(type) {
		case string:
			fields = append(fields, t)
		case map[string]any:
			for k, child := range t {
				fields = append(fields, k)
				if !walk(child) {
					return false
				}
			}
		case []any:
			for _, child := range t {
				if !walk(child) {
					return false
				}
			}
		}
		return len(fields) <= maxBodyFields
	}
	if !walk(doc) || len(fields) == 0 {
		return nil
	}
	return fields
}

// looksLikeJSON reports a JSON media type (application/json, *+json), or an
// unlabelled body that starts like a JSON document.
func looksLikeJSON(contentType, body string) bool {
	mediaType, _, _ := strings.Cut(strings.ToLower(contentType), ";")
	mediaType = strings.TrimSpace(mediaType)
	if mediaType == "application/json" || strings.HasSuffix(mediaType, "+json") {
		return true
	}
	trimmed := strings.TrimSpace(body)
	return trimmed != "" && (trimmed[0] == '{' || trimmed[0] == '[')
}
