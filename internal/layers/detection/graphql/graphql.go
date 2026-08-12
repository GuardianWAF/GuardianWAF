// Package graphql detects GraphQL query-depth, complexity, and introspection
// attacks.
//
// GraphQL APIs accept arbitrarily complex queries. A single HTTP request can
// nest selection sets dozens of levels deep or alias the same field hundreds
// of times, producing exponential server-side work. Without cost enforcement,
// one query can exhaust database connections, CPU, or memory.
//
// This detector is a lightweight brace-and-field counter — not a full GraphQL
// parser. It extracts the query string from three transport formats (raw
// application/graphql, JSON-wrapped, query parameter), strips comments and
// string literals, then measures:
//
//   - Maximum nesting depth (count of unclosed `{` at any point)
//   - Total field selections (every field reference, including aliases)
//   - Introspection fields (__schema, __type, __typename)
//   - Batch queries (JSON array of operations)
//
// The detector does NOT evaluate the query semantically (fragments, directives,
// variables are not expanded). This is intentional: the goal is to bound cost,
// not to validate the query. False positives on benign deep queries are
// controlled via configurable thresholds (maxDepth, maxComplexity).
package graphql

import (
	"encoding/json"
	"strings"
	"unicode"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Detector implements engine.Detector for GraphQL cost-based attacks.
type Detector struct {
	enabled            bool
	multiplier         float64
	maxDepth           int
	maxComplexity      int
	blockIntrospection bool
	allowEndpoints     map[string]bool
}

// NewDetector creates a GraphQL detector.
func NewDetector(enabled bool, multiplier float64, maxDepth, maxComplexity int, blockIntrospection bool, allowEndpoints []string) *Detector {
	allow := make(map[string]bool, len(allowEndpoints))
	for _, ep := range allowEndpoints {
		allow[ep] = true
	}
	return &Detector{
		enabled:            enabled,
		multiplier:         multiplier,
		maxDepth:           maxDepth,
		maxComplexity:      maxComplexity,
		blockIntrospection: blockIntrospection,
		allowEndpoints:     allow,
	}
}

func (d *Detector) Name() string         { return "graphql-detector" }
func (d *Detector) Order() int           { return 0 }
func (d *Detector) DetectorName() string { return "graphql" }
func (d *Detector) Patterns() []string {
	return []string{
		"depth-exceeded",
		"complexity-exceeded",
		"introspection-query",
		"batch-query-bomb",
	}
}

// Process inspects the request for GraphQL queries that exceed depth or
// complexity limits, or attempt introspection.
func (d *Detector) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !d.enabled {
		return engine.LayerResult{}
	}

	// Only inspect endpoints that look GraphQL-related. If an allowEndpoints
	// list is configured, restrict to those paths; otherwise sniff content type.
	if len(d.allowEndpoints) > 0 {
		if !d.allowEndpoints[ctx.NormalizedPath] && !d.allowEndpoints[ctx.Path] {
			return engine.LayerResult{}
		}
	}

	// Extract the query string from the request.
	queries := extractQueries(ctx)
	if len(queries) == 0 {
		return engine.LayerResult{}
	}

	var findings []engine.Finding
	batchCount := len(queries)

	for _, q := range queries {
		qFindings := d.analyzeQuery(q)
		findings = append(findings, qFindings...)
	}

	// Batch query bomb: multiple operations in one request.
	if batchCount > 1 {
		findings = append(findings, engine.Finding{
			DetectorName: "graphql",
			Category:     "graphql-batch-query-bomb",
			Severity:     engine.SeverityHigh,
			Score:        70,
			Description:  "Batch GraphQL query: multiple operations in a single request",
			MatchedValue: "",
			Location:     "body",
			Confidence:   0.8,
		})
	}

	score := 0
	for _, f := range findings {
		score += f.Score
	}
	score = int(float64(score) * d.multiplier)

	return engine.LayerResult{
		Score:    score,
		Findings: findings,
	}
}

// extractQueries pulls the GraphQL query string(s) from the request, handling
// three transport formats: raw application/graphql body, JSON-wrapped body,
// and query parameter.
func extractQueries(ctx *engine.RequestContext) []string {
	var queries []string

	// 1. Query parameter (GET requests or POST with query in URL).
	if rawQ, ok := ctx.QueryParams["query"]; ok && len(rawQ) > 0 && strings.TrimSpace(rawQ[0]) != "" {
		queries = append(queries, rawQ[0])
	}

	ct := strings.ToLower(ctx.ContentType)

	// 2. application/graphql — raw query in body. Some clients send the
	// query wrapped in a JSON object even with this content-type, so if
	// the body parses as JSON with a "query" field, extract that instead.
	if strings.Contains(ct, "application/graphql") {
		body := strings.TrimSpace(ctx.BodyString)
		if body == "" {
			body = strings.TrimSpace(ctx.NormalizedBody)
		}
		if body != "" {
			if q := tryExtractJSONQuery(body); q != "" {
				queries = append(queries, q)
			} else {
				queries = append(queries, body)
			}
		}
		return queries
	}

	// 3. application/json — may contain {"query": "..."} or a batch array.
	if strings.Contains(ct, "application/json") || strings.Contains(ct, "text/plain") {
		body := ctx.BodyString
		if body == "" {
			body = ctx.NormalizedBody
		}
		body = strings.TrimSpace(body)
		if body == "" {
			return queries
		}

		// Try batch first: [{"query":"..."}, ...].
		if body[0] == '[' {
			var batch []map[string]any
			if json.Unmarshal([]byte(body), &batch) == nil {
				for _, op := range batch {
					if q, ok := op["query"].(string); ok && strings.TrimSpace(q) != "" {
						queries = append(queries, q)
					}
				}
				return queries
			}
		}

		// Single operation: {"query": "..."}.
		if body[0] == '{' {
			var op map[string]any
			if json.Unmarshal([]byte(body), &op) == nil {
				if q, ok := op["query"].(string); ok && strings.TrimSpace(q) != "" {
					queries = append(queries, q)
				}
			}
		}
	}

	return queries
}

// tryExtractJSONQuery attempts to parse body as a JSON object and extract the
// "query" field. Returns empty string if body is not valid JSON or has no
// "query" field.
func tryExtractJSONQuery(body string) string {
	body = strings.TrimSpace(body)
	if body == "" || (body[0] != '{' && body[0] != '[') {
		return ""
	}
	// Single operation.
	var op map[string]any
	if json.Unmarshal([]byte(body), &op) == nil {
		if q, ok := op["query"].(string); ok {
			return q
		}
	}
	// Batch operation.
	var batch []map[string]any
	if json.Unmarshal([]byte(body), &batch) == nil && len(batch) > 0 {
		if q, ok := batch[0]["query"].(string); ok {
			return q
		}
	}
	return ""
}

// analyzeQuery measures a single GraphQL query string for depth, complexity,
// aliasing abuse, fragment cycles, and introspection.
func (d *Detector) analyzeQuery(query string) []engine.Finding {
	cleaned := stripCommentsAndStrings(query)
	depth, complexity := measureDepthComplexity(cleaned)

	var findings []engine.Finding

	// Depth check.
	if d.maxDepth > 0 && depth > d.maxDepth {
		findings = append(findings, engine.Finding{
			DetectorName: "graphql",
			Category:     "graphql-depth-exceeded",
			Severity:     engine.SeverityHigh,
			Score:        80,
			Description:  "GraphQL query nesting depth exceeds maximum",
			MatchedValue: "",
			Location:     "body",
			Confidence:   0.95,
		})
	}

	// Complexity check.
	if d.maxComplexity > 0 && complexity > d.maxComplexity {
		findings = append(findings, engine.Finding{
			DetectorName: "graphql",
			Category:     "graphql-complexity-exceeded",
			Severity:     engine.SeverityHigh,
			Score:        75,
			Description:  "GraphQL query field complexity exceeds maximum",
			MatchedValue: "",
			Location:     "body",
			Confidence:   0.9,
		})
	}

	// Aliasing abuse: the same field referenced via >10 aliases forces the
	// backend to resolve the field N times in a single request.
	if aliases := countAliases(cleaned); aliases > 10 {
		findings = append(findings, engine.Finding{
			DetectorName: "graphql",
			Category:     "graphql-aliasing-abuse",
			Severity:     engine.SeverityMedium,
			Score:        55,
			Description:  "GraphQL query uses excessive field aliasing",
			MatchedValue: "",
			Location:     "body",
			Confidence:   0.85,
		})
	}

	// Fragment cycle: a fragment that references itself (directly or
	// transitively) causes infinite recursion in the backend resolver.
	if detectFragmentCycle(cleaned) {
		findings = append(findings, engine.Finding{
			DetectorName: "graphql",
			Category:     "graphql-fragment-cycle",
			Severity:     engine.SeverityHigh,
			Score:        85,
			Description:  "GraphQL fragment cycle detected",
			MatchedValue: "",
			Location:     "body",
			Confidence:   0.9,
		})
	}

	// Introspection check.
	if d.blockIntrospection && hasIntrospection(cleaned) {
		findings = append(findings, engine.Finding{
			DetectorName: "graphql",
			Category:     "graphql-introspection-query",
			Severity:     engine.SeverityMedium,
			Score:        60,
			Description:  "GraphQL introspection query (schema disclosure)",
			MatchedValue: "",
			Location:     "body",
			Confidence:   0.95,
		})
	}

	return findings
}

// stripCommentsAndStrings removes GraphQL comments (#...) and string literals
// (including block strings """...""") so they don't confuse the brace counter.
func stripCommentsAndStrings(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		// Block string: """..."""
		if i+2 < len(s) && s[i] == '"' && s[i+1] == '"' && s[i+2] == '"' {
			i += 3
			for i+2 < len(s) {
				if s[i] == '"' && s[i+1] == '"' && s[i+2] == '"' {
					i += 3
					break
				}
				i++
			}
			b.WriteByte(' ') // preserve token boundary
			continue
		}
		// Single-line string: "..."
		if s[i] == '"' {
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				i++
			}
			if i < len(s) {
				i++ // closing quote
			}
			b.WriteByte(' ')
			continue
		}
		// Comment: #...
		if s[i] == '#' {
			for i < len(s) && s[i] != '\n' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// measureDepthComplexity returns (maxDepth, totalComplexity) for a cleaned
// GraphQL query. Depth counts the maximum nesting of `{ ... }` blocks.
// Complexity counts field selections: every identifier that is a field name
// (not a directive, argument, or type reference).
func measureDepthComplexity(s string) (int, int) {
	depth := 0
	parenDepth := 0
	maxDepth := 0
	complexity := 0

	runes := []rune(s)
	i := 0
	for i < len(runes) {
		ch := runes[i]

		switch ch {
		case '{':
			depth++
			if depth+parenDepth > maxDepth {
				maxDepth = depth + parenDepth
			}
			i++
		case '}':
			if depth > 0 {
				depth--
			}
			i++
		case '(':
			parenDepth++
			if depth+parenDepth > maxDepth {
				maxDepth = depth + parenDepth
			}
			i++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
			i++
		case '@':
			// Skip directives: advance to end of identifier.
			i++
			for i < len(runes) && isIdentPart(runes[i]) {
				i++
			}
		default:
			// Read an identifier.
			if isIdentStart(ch) {
				start := i
				i++
				for i < len(runes) && isIdentPart(runes[i]) {
					i++
				}
				ident := string(runes[start:i])

				// Skip GraphQL keywords that aren't field selections.
				// Only count fields inside {...} selection sets, not arguments
				// inside (...) — arguments are metadata, not resolvable fields.
				if !isGraphQLKeyword(ident) && depth > 0 && parenDepth == 0 {
					complexity++
				}
			} else {
				i++
			}
		}
	}

	return maxDepth, complexity
}

// hasIntrospection returns true if the cleaned query references any GraphQL
// introspection field.
func hasIntrospection(s string) bool {
	return strings.Contains(s, "__schema") ||
		strings.Contains(s, "__type") ||
		strings.Contains(s, "__typename")
}

var graphQLKeywords = map[string]bool{
	"query": true, "mutation": true, "subscription": true,
	"fragment": true, "on": true, "schema": true,
	"input": true, "type": true, "interface": true,
	"union": true, "enum": true, "scalar": true,
	"implements": true, "extends": true, "directive": true,
	"true": true, "false": true, "null": true,
}

func isGraphQLKeyword(s string) bool {
	return graphQLKeywords[s]
}

func isIdentStart(ch rune) bool {
	return ch == '_' || unicode.IsLetter(ch)
}

func isIdentPart(ch rune) bool {
	return ch == '_' || unicode.IsLetter(ch) || unicode.IsDigit(ch)
}

// countAliases returns the number of alias definitions (pattern `alias:field`).
// GraphQL aliasing lets a client request the same field multiple times under
// different names, forcing the backend to resolve it N times.
func countAliases(s string) int {
	count := 0
	runes := []rune(s)
	i := 0
	for i < len(runes) {
		// Look for ident:ident pattern (alias syntax).
		if isIdentStart(runes[i]) {
			i++
			for i < len(runes) && isIdentPart(runes[i]) {
				i++
			}
			if i < len(runes)-1 && runes[i] == ':' && runes[i+1] != ':' {
				// Skip whitespace after colon.
				j := i + 1
				for j < len(runes) && (runes[j] == ' ' || runes[j] == '\t') {
					j++
				}
				if j < len(runes) && isIdentStart(runes[j]) {
					count++
				}
			}
		} else {
			i++
		}
	}
	return count
}

// detectFragmentCycle returns true if the query contains fragment definitions
// that reference each other circularly (e.g. fragment A {...B} fragment B {...A}).
//
// The parser is a lightweight single-pass tokenizer that tracks brace depth to
// correctly identify fragment-definition boundaries and collect all fragment
// spread references (...Name) within each body — including spreads that appear
// after nested closing braces. The previous implementation used
// strings.Split(s, "}"), which broke fragment bodies at every "}" regardless of
// nesting depth, causing false negatives when a spread appeared after an inner
// selection-set close (e.g. fragment A on Q { user { name } ...B }).
//
// Input must already be cleaned via stripCommentsAndStrings so string literals
// and comments containing braces or "..." are eliminated.
func detectFragmentCycle(s string) bool {
	fragments := parseFragmentGraph(s)
	if len(fragments) == 0 {
		return false
	}

	// Check for cycles using three-color DFS (white/gray/black).
	// A node is gray while it is on the current recursion path; black once
	// fully explored. Encountering a gray node during traversal proves a cycle.
	// This correctly distinguishes a diamond (A→B→D, A→C→D — acyclic) from a
	// real cycle (A→B→A), which the old single-color DFS could not.
	const (
		white = 0 // unvisited
		gray  = 1 // on current DFS path
		black = 2 // fully explored, no cycle through it
	)
	color := make(map[string]int, len(fragments))
	for name := range fragments {
		color[name] = white
	}

	var dfs func(name string) bool
	dfs = func(name string) bool {
		color[name] = gray
		for _, ref := range fragments[name] {
			if color[ref] == gray {
				return true // back-edge → cycle
			}
			if color[ref] == white {
				if dfs(ref) {
					return true
				}
			}
			// black: already fully explored, skip
		}
		color[name] = black
		return false
	}

	for name := range fragments {
		if color[name] == white {
			if dfs(name) {
				return true
			}
		}
	}
	return false
}

// parseFragmentGraph tokenizes a cleaned GraphQL query and builds a directed
// graph of fragment-spread references. Each fragment definition produces an
// adjacency list of other named fragments it spreads. The parser tracks brace
// depth so that the body of a fragment is correctly delimited by its matching
// closing brace (depth 0), not by the first inner "}".
//
// Grammar recognized per fragment:
//
//	fragment Name on Type { ...body... }
//
// Within the body, every ...Name (fragment spread, excluding ...on) is an edge
// from the defining fragment to Name. Self-references (fragment A spreading
// ...A) are excluded since the GraphQL spec treats them as a parse error, not a
// runtime cycle.
func parseFragmentGraph(s string) map[string][]string {
	fragments := make(map[string][]string)
	runes := []rune(s)
	n := len(runes)
	i := 0

	for i < n {
		// Scan for the "fragment" keyword at the start of a token.
		if i+8 <= n && string(runes[i:i+8]) == "fragment" && (i == 0 || !isIdentPart(runes[i-1])) {
			// Skip "fragment"
			j := i + 8
			// Skip whitespace
			for j < n && (runes[j] == ' ' || runes[j] == '\t' || runes[j] == '\n' || runes[j] == '\r') {
				j++
			}
			// Read fragment name
			if j >= n || !isIdentStart(runes[j]) {
				i = j
				continue
			}
			nameStart := j
			j++
			for j < n && isIdentPart(runes[j]) {
				j++
			}
			fragName := string(runes[nameStart:j])

			// Skip "on" keyword and type condition (could be "on Type {")
			// Advance to the opening brace of the fragment body.
			braceStart := -1
			for j < n {
				if runes[j] == '{' {
					braceStart = j
					break
				}
				j++
			}
			if braceStart == -1 {
				i = j
				continue
			}

			// Walk the body tracking brace depth to find the matching close.
			j++ // past opening {
			depth := 1
			bodyStart := j
			for j < n && depth > 0 {
				switch runes[j] {
				case '{':
					depth++
				case '}':
					depth--
				}
				if depth > 0 {
					j++
				}
			}
			bodyEnd := j // position of matching }

			// Collect all ...Spread references within the body [bodyStart, bodyEnd).
			body := runes[bodyStart:bodyEnd]
			var refs []string
			for k := 0; k < len(body)-2; k++ {
				if body[k] == '.' && body[k+1] == '.' && body[k+2] == '.' {
					m := k + 3
					// Skip optional "on" keyword for type conditions (... on Type)
					for m < len(body) && (body[m] == ' ' || body[m] == '\t') {
						m++
					}
					if m < len(body) && isIdentStart(body[m]) {
						refStart := m
						for m < len(body) && isIdentPart(body[m]) {
							m++
						}
						ref := string(body[refStart:m])
						if ref != "on" && ref != fragName {
							refs = append(refs, ref)
						}
						k = m - 1
					}
				}
			}

			fragments[fragName] = refs
			i = j + 1 // past matching }
			continue
		}
		i++
	}

	return fragments
}
