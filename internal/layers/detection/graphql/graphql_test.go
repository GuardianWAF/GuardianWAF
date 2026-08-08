package graphql

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func makeCtx(contentType, path, rawQuery, body string) *engine.RequestContext {
	req, _ := http.NewRequest("POST", "http://example.com"+path+"?"+rawQuery, nil)
	ctx := &engine.RequestContext{
		Path:           path,
		NormalizedPath: path,
		Method:         "POST",
		ContentType:    contentType,
		BodyString:     body,
		NormalizedBody: body,
		QueryParams:    map[string][]string{},
		Headers:        map[string][]string{},
		Cookies:        map[string]string{},
	}
	if rawQuery != "" {
		vals, _ := url.ParseQuery(rawQuery)
		for k, vs := range vals {
			ctx.QueryParams[k] = vs
		}
	}
	ctx.Request = req
	return ctx
}

func TestDisabled(t *testing.T) {
	det := NewDetector(false, 1.0, 10, 1000, true, []string{"/graphql"})
	result := det.Process(makeCtx("application/json", "/graphql", "",
		`{"query":"{user{friends{user{friends{name}}}}}"}`))
	if result.Score != 0 {
		t.Errorf("disabled detector should return zero score, got %d", result.Score)
	}
}

func TestNonGraphQLEndpoint(t *testing.T) {
	det := NewDetector(true, 1.0, 10, 1000, true, []string{"/graphql"})
	result := det.Process(makeCtx("application/json", "/api/users", "",
		`{"query":"{user{friends{user{friends{name}}}}}"}`))
	if result.Score != 0 {
		t.Errorf("non-GraphQL endpoint should return zero score, got %d", result.Score)
	}
}

func TestDepthAttack_JSONWrapped(t *testing.T) {
	det := NewDetector(true, 1.0, 5, 1000, false, []string{"/graphql"})
	deepQuery := `{u{f{u{f{u{f{u{f{name}}}}}}}}}` // depth 8
	result := det.Process(makeCtx("application/json", "/graphql", "",
		`{"query":"`+deepQuery+`"}`))
	if result.Score == 0 {
		t.Errorf("depth attack not detected")
	}
	found := false
	for _, f := range result.Findings {
		if f.Category == "graphql-depth-exceeded" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected depth-exceeded finding, got %v", result.Findings)
	}
}

func TestDepthAttack_RawGraphQL(t *testing.T) {
	det := NewDetector(true, 1.0, 3, 1000, false, []string{"/graphql"})
	deepQuery := `{a{b{c{d{e{name}}}}}}` // depth 5
	result := det.Process(makeCtx("application/graphql", "/graphql", "", deepQuery))
	if result.Score == 0 {
		t.Errorf("raw GraphQL depth attack not detected")
	}
}

func TestDepthAttack_QueryParam(t *testing.T) {
	det := NewDetector(true, 1.0, 3, 1000, false, []string{"/graphql"})
	deepQuery := url.QueryEscape(`{a{b{c{d{name}}}}}`)
	result := det.Process(makeCtx("", "/graphql", "query="+deepQuery, ""))
	if result.Score == 0 {
		t.Errorf("query param depth attack not detected")
	}
}

func TestNormalQueryNotBlocked(t *testing.T) {
	det := NewDetector(true, 1.0, 10, 1000, false, []string{"/graphql"})
	query := `{user(id:"123"){name email posts{title}}}`
	result := det.Process(makeCtx("application/json", "/graphql", "",
		`{"query":"`+query+`"}`))
	if result.Score != 0 {
		t.Errorf("normal query should not trigger, got score=%d findings=%v", result.Score, result.Findings)
	}
}

func TestComplexityAttack(t *testing.T) {
	det := NewDetector(true, 1.0, 100, 10, false, []string{"/graphql"})
	// 15 fields in one selection set.
	query := `{a b c d e f g h i j k l m n o}`
	result := det.Process(makeCtx("application/graphql", "/graphql", "", query))
	found := false
	for _, f := range result.Findings {
		if f.Category == "graphql-complexity-exceeded" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected complexity-exceeded finding, got score=%d findings=%v", result.Score, result.Findings)
	}
}

func TestIntrospection(t *testing.T) {
	det := NewDetector(true, 1.0, 10, 1000, true, []string{"/graphql"})
	query := `{__schema{types{name}}}`
	result := det.Process(makeCtx("application/graphql", "/graphql", "", query))
	found := false
	for _, f := range result.Findings {
		if f.Category == "graphql-introspection-query" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected introspection finding, got score=%d findings=%v", result.Score, result.Findings)
	}
}

func TestIntrospectionAllowedWhenDisabled(t *testing.T) {
	det := NewDetector(true, 1.0, 10, 1000, false, []string{"/graphql"})
	query := `{__schema{types{name}}}`
	result := det.Process(makeCtx("application/graphql", "/graphql", "", query))
	for _, f := range result.Findings {
		if f.Category == "graphql-introspection-query" {
			t.Errorf("introspection should not be flagged when blockIntrospection=false")
		}
	}
}

func TestBatchQueryBomb(t *testing.T) {
	det := NewDetector(true, 1.0, 10, 1000, false, []string{"/graphql"})
	body := `[{"query":"{user{name}}"},{"query":"{user{email}}"},{"query":"{user{age}}"}]`
	result := det.Process(makeCtx("application/json", "/graphql", "", body))
	found := false
	for _, f := range result.Findings {
		if f.Category == "graphql-batch-query-bomb" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected batch-query-bomb finding, got score=%d findings=%v", result.Score, result.Findings)
	}
}

func TestCommentsAndStringsDontAffectDepth(t *testing.T) {
	// The string literal "}" should NOT be counted as a brace.
	query := `{user(name:"#not a comment"){name}}`
	det := NewDetector(true, 1.0, 3, 1000, false, []string{"/graphql"})
	result := det.Process(makeCtx("application/graphql", "/graphql", "", query))
	for _, f := range result.Findings {
		if f.Category == "graphql-depth-exceeded" {
			t.Errorf("string/comment content should not affect depth count")
		}
	}
}

func TestMeasureDepthComplexity(t *testing.T) {
	tests := []struct {
		query string
		wantD int
		wantC int
	}{
		{`{name}`, 1, 1},
		{`{a{b{c}}}`, 3, 3},
		{`{a b c}`, 1, 3},
		{`query { a { b { c { d { e } } } } }`, 5, 5},
		{`mutation($v:String!){create(input:$v){id}}`, 2, 2},
	}
	for _, tt := range tests {
		cleaned := stripCommentsAndStrings(tt.query)
		gotD, gotC := measureDepthComplexity(cleaned)
		if gotD != tt.wantD {
			t.Errorf("depth for %q = %d, want %d", tt.query, gotD, tt.wantD)
		}
		if gotC != tt.wantC {
			t.Errorf("complexity for %q = %d, want %d", tt.query, gotC, tt.wantC)
		}
	}
}

func TestHasIntrospection(t *testing.T) {
	if !hasIntrospection(`{__schema{types{name}}}`) {
		t.Errorf("__schema should be detected")
	}
	if !hasIntrospection(`{__type(name:"User"){name}}`) {
		t.Errorf("__type should be detected")
	}
	if !hasIntrospection(`{__typename}`) {
		t.Errorf("__typename should be detected")
	}
	if hasIntrospection(`{user{name}}`) {
		t.Errorf("normal query should not trigger introspection")
	}
}

func TestEmptyBody(t *testing.T) {
	det := NewDetector(true, 1.0, 10, 1000, true, []string{"/graphql"})
	result := det.Process(makeCtx("application/json", "/graphql", "", ""))
	if result.Score != 0 {
		t.Errorf("empty body should not trigger, got score=%d", result.Score)
	}
}

func TestMultiplier(t *testing.T) {
	det := NewDetector(true, 2.0, 1, 1000, false, []string{"/graphql"})
	query := `{a{b{c{name}}}}` // depth 4 > maxDepth 1
	result := det.Process(makeCtx("application/graphql", "/graphql", "", query))
	if result.Score != 160 { // 80 base * 2.0 multiplier
		t.Errorf("multiplier not applied correctly, got score=%d want=160", result.Score)
	}
}

func TestNoAllowEndpoints_SniffsContentType(t *testing.T) {
	det := NewDetector(true, 1.0, 1, 1000, false, nil) // no endpoint restriction
	query := `{a{b{c{name}}}}`
	result := det.Process(makeCtx("application/graphql", "/anywhere", "", query))
	if result.Score == 0 {
		t.Errorf("should detect when no endpoint restriction and content type is graphql")
	}
}

func TestStripCommentsAndStrings(t *testing.T) {
	input := `{a # comment with }
	{b}`
	cleaned := stripCommentsAndStrings(input)
	if strings.Contains(cleaned, "comment") {
		t.Errorf("comment not stripped: %q", cleaned)
	}
	// The } in the comment should not appear in the output.
	// The comment's "}" must NOT prematurely close the outer brace.
	// With the comment stripped, {b} nests inside {a} → depth 2.
	// If the comment brace leaked, depth would be 1 (outer closed too early).
	d, _ := measureDepthComplexity(cleaned)
	if d != 2 {
		t.Errorf("comment braces leaked: depth=%d for cleaned=%q (want 2)", d, cleaned)
	}
}
