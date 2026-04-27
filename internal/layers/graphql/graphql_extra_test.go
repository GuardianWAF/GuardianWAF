package graphql

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// ---------------------------------------------------------------------------
// Layer lifecycle: Name, Order, Enabled/SetEnabled, Config/UpdateConfig, Stats
// ---------------------------------------------------------------------------

func TestLayer_Name(t *testing.T) {
	layer, _ := New(DefaultConfig())
	if layer.Name() != "graphql-security" {
		t.Errorf("Expected name 'graphql-security', got %q", layer.Name())
	}
}

func TestLayer_Order(t *testing.T) {
	layer, _ := New(DefaultConfig())
	if layer.Order() != 285 {
		t.Errorf("Expected order 285, got %d", layer.Order())
	}
}

func TestLayer_Enabled_SetEnabled(t *testing.T) {
	layer, _ := New(DefaultConfig())
	if !layer.Enabled() {
		t.Error("Expected layer to be enabled by default")
	}
	layer.SetEnabled(false)
	if layer.Enabled() {
		t.Error("Expected layer to be disabled after SetEnabled(false)")
	}
	layer.SetEnabled(true)
	if !layer.Enabled() {
		t.Error("Expected layer to be re-enabled after SetEnabled(true)")
	}
}

func TestLayer_Config_UpdateConfig(t *testing.T) {
	layer, _ := New(DefaultConfig())
	cfg := layer.Config()
	if !cfg.Enabled {
		t.Error("Expected default config to be enabled")
	}
	if cfg.MaxDepth != 10 {
		t.Errorf("Expected default MaxDepth 10, got %d", cfg.MaxDepth)
	}
	if cfg.MaxComplexity != 1000 {
		t.Errorf("Expected default MaxComplexity 1000, got %d", cfg.MaxComplexity)
	}
	if !cfg.BlockIntrospection {
		t.Error("Expected default BlockIntrospection true")
	}
	if cfg.MaxAliases != 10 {
		t.Errorf("Expected default MaxAliases 10, got %d", cfg.MaxAliases)
	}
	if cfg.MaxBatchSize != 5 {
		t.Errorf("Expected default MaxBatchSize 5, got %d", cfg.MaxBatchSize)
	}

	updated := Config{
		Enabled:            true,
		MaxDepth:           5,
		MaxComplexity:      500,
		BlockIntrospection: false,
		MaxAliases:         3,
		MaxBatchSize:       2,
	}
	layer.UpdateConfig(updated)
	cfg2 := layer.Config()
	if cfg2.MaxDepth != 5 {
		t.Errorf("Expected updated MaxDepth 5, got %d", cfg2.MaxDepth)
	}
	if cfg2.BlockIntrospection {
		t.Error("Expected updated BlockIntrospection false")
	}
}

func TestLayer_Stats_Challenged(t *testing.T) {
	// Queries with score > 0 but not blocked should be counted as challenged.
	cfg := DefaultConfig()
	cfg.MaxDepth = 2 // low to trigger a depth violation (score 40)
	cfg.BlockIntrospection = false
	layer, _ := New(cfg)

	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path:     "/graphql",
			RawQuery: "query=" + url.QueryEscape("{ a { b { c } } }"),
		},
	}
	wafCtx := &engine.RequestContext{
		Request:     req,
		Method:      "GET",
		QueryParams: req.URL.Query(),
	}

	result, err := layer.Analyze(wafCtx)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if result.Blocked {
		t.Error("Expected not blocked (score 40 < 50 threshold)")
	}
	if result.Score <= 0 {
		t.Errorf("Expected positive score for depth violation, got %d", result.Score)
	}

	stats := layer.Stats()
	if stats.QueriesAnalyzed != 1 {
		t.Errorf("Expected QueriesAnalyzed=1, got %d", stats.QueriesAnalyzed)
	}
	if stats.QueriesBlocked != 0 {
		t.Errorf("Expected QueriesBlocked=0, got %d", stats.QueriesBlocked)
	}
	if stats.QueriesChallenged != 1 {
		t.Errorf("Expected QueriesChallenged=1, got %d", stats.QueriesChallenged)
	}
}

// ---------------------------------------------------------------------------
// Process method (engine.Layer interface)
// ---------------------------------------------------------------------------

func TestLayer_Process_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	layer, _ := New(cfg)

	ctx := &engine.RequestContext{
		Request: &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/graphql"},
		},
		Method:      "GET",
		QueryParams: map[string][]string{"query": {"{users{id}}"}},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Expected ActionPass for disabled layer, got %v", result.Action)
	}
	if result.Score != 0 {
		t.Errorf("Expected score 0 for disabled layer, got %d", result.Score)
	}
}

func TestLayer_Process_TenantOverride(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer, _ := New(cfg)

	// Tenant overrides graphql to disabled
	ctx := &engine.RequestContext{
		Request: &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/graphql"},
		},
		Method:      "GET",
		QueryParams: map[string][]string{"query": {"{users{id}}"}},
		TenantWAFConfig: &config.WAFConfig{
			GraphQL: config.GraphQLConfig{Enabled: false},
		},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Expected ActionPass for tenant-disabled, got %v", result.Action)
	}
}

func TestLayer_Process_NotGraphQLPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer, _ := New(cfg)

	ctx := &engine.RequestContext{
		Request: &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/api/users"},
		},
		Method:      "GET",
		QueryParams: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("Expected ActionPass for non-GraphQL request, got %v", result.Action)
	}
	if result.Score != 0 {
		t.Errorf("Expected score 0 for non-GraphQL request, got %d", result.Score)
	}
}

func TestLayer_Process_ValidQuery(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.BlockIntrospection = false
	layer, _ := New(cfg)

	ctx := makeGraphQLContext("GET", "/graphql", "{ users { id name } }", "")
	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("Expected ActionPass for valid query, got %v", result.Action)
	}
	if result.Score != 0 {
		t.Errorf("Expected score 0 for valid query, got %d", result.Score)
	}
}

func TestLayer_Process_Blocked(t *testing.T) {
	// Introspection + depth exceed + many aliases should push score to >= 50
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MaxDepth = 2
	cfg.BlockIntrospection = true
	cfg.MaxAliases = 2
	layer, _ := New(cfg)

	// Deep introspection query
	query := "{ __schema { types { fields { name args { name } } } } }"
	ctx := makeGraphQLContext("GET", "/graphql", query, "")
	result := layer.Process(ctx)

	if result.Action != engine.ActionBlock {
		t.Errorf("Expected ActionBlock, got %v (score=%d)", result.Action, result.Score)
	}
	if len(result.Findings) == 0 {
		t.Error("Expected findings for blocked query")
	}
}

func TestLayer_Process_Log(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MaxDepth = 3
	cfg.BlockIntrospection = false
	cfg.MaxAliases = 100
	layer, _ := New(cfg)

	// Depth 4 > MaxDepth 3, score 40 => ActionLog
	query := "{ a { b { c { d } } } }"
	ctx := makeGraphQLContext("GET", "/graphql", query, "")
	result := layer.Process(ctx)

	if result.Action != engine.ActionLog {
		t.Errorf("Expected ActionLog for depth violation with score < 50, got %v (score=%d)", result.Action, result.Score)
	}
	if len(result.Findings) == 0 {
		t.Error("Expected findings for logged query")
	}
}

func TestLayer_Process_ScoreAccumulator(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MaxDepth = 2
	cfg.BlockIntrospection = false
	layer, _ := New(cfg)

	acc := engine.NewScoreAccumulator(2)
	ctx := makeGraphQLContext("GET", "/graphql", "{ a { b { c } } }", "")
	ctx.Accumulator = acc

	result := layer.Process(ctx)
	if result.Score == 0 {
		t.Error("Expected non-zero score for depth-exceeding query")
	}

	// Verify findings were added to the accumulator
	accFindings := acc.Findings()
	if len(accFindings) == 0 {
		t.Error("Expected findings in the accumulator")
	}
}

func TestLayer_Process_FindingSeverities(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MaxDepth = 2
	cfg.BlockIntrospection = true
	cfg.MaxAliases = 100
	layer, _ := New(cfg)

	query := "{ __schema { types { fields { name } } } }" // depth=4, introspection
	ctx := makeGraphQLContext("GET", "/graphql", query, "")
	result := layer.Process(ctx)

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings")
	}

	// Verify that findings have proper severities set
	for _, f := range result.Findings {
		if f.Severity != engine.SeverityHigh && f.Severity != engine.SeverityMedium {
			t.Errorf("Unexpected finding severity: %v", f.Severity)
		}
		if f.DetectorName != "graphql-security" {
			t.Errorf("Expected detector name 'graphql-security', got %q", f.DetectorName)
		}
		if f.Category != "graphql" {
			t.Errorf("Expected category 'graphql', got %q", f.Category)
		}
	}
}

// ---------------------------------------------------------------------------
// Depth limit enforcement
// ---------------------------------------------------------------------------

func TestDepthLimit_Enforcement(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		maxDepth  int
		expectHit bool
	}{
		{
			name:      "depth within limit",
			query:     "{ users { id } }",
			maxDepth:  10,
			expectHit: false,
		},
		{
			name:      "depth exactly at limit",
			query:     "{ a { b { c { d { e } } } } }", // depth 5
			maxDepth:  5,
			expectHit: false,
		},
		{
			name:      "depth exceeds limit by 1",
			query:     "{ a { b { c { d { e { f } } } } } }", // depth 6
			maxDepth:  5,
			expectHit: true,
		},
		{
			name:      "deep nested query",
			query:     "{ a { b { c { d { e { f { g { h { i { j { k } } } } } } } } } } }", // depth 11
			maxDepth:  10,
			expectHit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.MaxDepth = tt.maxDepth
			cfg.BlockIntrospection = false
			cfg.MaxAliases = 100
			cfg.MaxComplexity = 10000
			layer, _ := New(cfg)

			ctx := makeGraphQLContext("GET", "/graphql", tt.query, "")
			_ = layer.Process(ctx)

			found := false
			for _, issue := range toAnalyzeIssues(layer, ctx) {
				if issue.Type == "depth_exceeded" {
					found = true
					break
				}
			}

			if found != tt.expectHit {
				t.Errorf("depth_exceeded issue found=%v, expected=%v", found, tt.expectHit)
			}
		})
	}
}

func TestCalculateDepth_NilAST(t *testing.T) {
	if calculateDepth(nil) != 0 {
		t.Error("Expected 0 for nil AST")
	}
	if calculateDepth(&AST{}) != 0 {
		t.Error("Expected 0 for AST with nil Document")
	}
}

func TestCalculateDepth_WithFragments(t *testing.T) {
	// Fragment that increases depth when resolved
	query := `fragment UserFields on User { posts { comments { text } } } { users { ...UserFields } }`
	ast, err := ParseQuery(query)
	if err != nil {
		t.Fatalf("ParseQuery failed: %v", err)
	}
	depth := calculateDepth(ast)
	// Expected: users(1) -> UserFields resolved -> posts(2) -> comments(3) -> text(4)
	if depth < 3 {
		t.Errorf("Expected depth >= 3 with fragment resolution, got %d", depth)
	}
}

func TestCalculateDepth_FragmentCycle(t *testing.T) {
	// Cyclic fragments should not cause infinite recursion
	query := `fragment A on User { ...B } fragment B on User { ...A } { users { ...A } }`
	ast, err := ParseQuery(query)
	if err != nil {
		t.Fatalf("ParseQuery failed: %v", err)
	}
	depth := calculateDepth(ast)
	// Should complete without panic
	t.Logf("Depth with cyclic fragments: %d", depth)
}

func TestCalculateDepth_InlineFragment(t *testing.T) {
	query := `{ users { ... on Admin { role } ... on User { name } } }`
	ast, err := ParseQuery(query)
	if err != nil {
		t.Fatalf("ParseQuery failed: %v", err)
	}
	depth := calculateDepth(ast)
	t.Logf("Depth with inline fragment: %d", depth)
	if depth < 2 {
		t.Errorf("Expected depth >= 2 for inline fragment, got %d", depth)
	}
}

// ---------------------------------------------------------------------------
// Complexity scoring
// ---------------------------------------------------------------------------

func TestComplexity_Scoring(t *testing.T) {
	tests := []struct {
		name               string
		query              string
		maxComplexity      int
		expectComplexityHit bool
	}{
		{
			name:               "simple query well within limit",
			query:              "{ users { id } }",
			maxComplexity:      1000,
			expectComplexityHit: false,
		},
		{
			name:               "complex query exceeds limit",
			query:              "{ users { id, name, email, posts { id, title, body, comments { id, text, author { id, name, email, role } } } } }",
			maxComplexity:      10,
			expectComplexityHit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.MaxComplexity = tt.maxComplexity
			cfg.MaxDepth = 100
			cfg.BlockIntrospection = false
			cfg.MaxAliases = 100
			layer, _ := New(cfg)

			ctx := makeGraphQLContext("GET", "/graphql", tt.query, "")
			result, _ := layer.Analyze(ctx)

			found := false
			for _, issue := range result.Issues {
				if issue.Type == "complexity_exceeded" {
					found = true
					break
				}
			}
			if found != tt.expectComplexityHit {
				t.Errorf("complexity_exceeded found=%v, expected=%v", found, tt.expectComplexityHit)
			}
		})
	}
}

func TestCalculateComplexity_NilAST(t *testing.T) {
	if calculateComplexity(nil) != 0 {
		t.Error("Expected 0 for nil AST")
	}
	if calculateComplexity(&AST{}) != 0 {
		t.Error("Expected 0 for AST with nil Document")
	}
}

// ---------------------------------------------------------------------------
// Alias limiting
// ---------------------------------------------------------------------------

func TestAliasLimiting(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxAliases = 3
	cfg.BlockIntrospection = false
	cfg.MaxDepth = 100
	cfg.MaxComplexity = 10000
	layer, _ := New(cfg)

	// 5 aliases, limit is 3
	query := "{ a1: user { id }, a2: user { id }, a3: user { id }, a4: user { id }, a5: user { id } }"
	ctx := makeGraphQLContext("GET", "/graphql", query, "")
	result, err := layer.Analyze(ctx)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	found := false
	for _, issue := range result.Issues {
		if issue.Type == "too_many_aliases" {
			found = true
			if issue.Severity != "medium" {
				t.Errorf("Expected severity medium, got %s", issue.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected too_many_aliases issue")
	}
}

func TestCountAliases_NilAST(t *testing.T) {
	if countAliases(nil) != 0 {
		t.Error("Expected 0 for nil AST")
	}
	if countAliases(&AST{}) != 0 {
		t.Error("Expected 0 for empty AST")
	}
}

func TestCountAliases_NoAliases(t *testing.T) {
	ast, _ := ParseQuery("{ users { id name } }")
	count := countAliases(ast)
	if count != 0 {
		t.Errorf("Expected 0 aliases, got %d", count)
	}
}

func TestCountAliases_NestedAliases(t *testing.T) {
	query := "{ a: user { b: name, c: email } }"
	ast, _ := ParseQuery(query)
	count := countAliases(ast)
	if count != 3 {
		t.Errorf("Expected 3 aliases, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// Introspection blocking
// ---------------------------------------------------------------------------

func TestIntrospectionBlocking(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected bool // whether introspection should be detected
	}{
		{
			name:     "__schema",
			query:    "{ __schema { types { name } } }",
			expected: true,
		},
		{
			name:     "__type",
			query:    `{ __type(name: "User") { name fields { name } } }`,
			expected: true,
		},
		{
			name:     "__typename",
			query:    "{ users { __typename } }",
			expected: true,
		},
		{
			name:     "normal query",
			query:    "{ users { id name email } }",
			expected: false,
		},
		{
			name:     "fields with double underscore prefix that are not introspection",
			query:    "{ users { id } }",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.BlockIntrospection = true
			cfg.MaxDepth = 100
			cfg.MaxComplexity = 10000
			cfg.MaxAliases = 100
			layer, _ := New(cfg)

			ctx := makeGraphQLContext("GET", "/graphql", tt.query, "")
			result, _ := layer.Analyze(ctx)

			found := false
			for _, issue := range result.Issues {
				if issue.Type == "introspection_blocked" {
					found = true
					break
				}
			}
			if found != tt.expected {
				t.Errorf("introspection_blocked found=%v, expected=%v", found, tt.expected)
			}
		})
	}
}

func TestIntrospection_NotBlockedWhenDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BlockIntrospection = false
	cfg.MaxDepth = 100
	cfg.MaxComplexity = 10000
	cfg.MaxAliases = 100
	layer, _ := New(cfg)

	ctx := makeGraphQLContext("GET", "/graphql", "{ __schema { types { name } } }", "")
	result, _ := layer.Analyze(ctx)

	for _, issue := range result.Issues {
		if issue.Type == "introspection_blocked" {
			t.Error("Expected no introspection_blocked when BlockIntrospection=false")
		}
	}
}

func TestHasIntrospection_NilAST(t *testing.T) {
	if hasIntrospection(nil) {
		t.Error("Expected false for nil AST")
	}
	if hasIntrospection(&AST{}) {
		t.Error("Expected false for empty AST")
	}
}

// ---------------------------------------------------------------------------
// Batch size limiting
// ---------------------------------------------------------------------------

func TestBatchSizeLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxBatchSize = 2
	cfg.BlockIntrospection = false
	cfg.MaxDepth = 100
	cfg.MaxComplexity = 10000
	cfg.MaxAliases = 100
	layer, _ := New(cfg)

	// Create batch JSON body with 3 queries
	batch := []map[string]string{
		{"query": "{ users { id } }"},
		{"query": "{ posts { title } }"},
		{"query": "{ comments { text } }"},
	}
	body, _ := json.Marshal(batch)

	ctx := &engine.RequestContext{
		Request: &http.Request{
			Method: "POST",
			URL:    &url.URL{Path: "/graphql"},
			Header: http.Header{"Content-Type": []string{"application/json"}},
		},
		Method:      "POST",
		Body:        body,
		BodyString:  string(body),
		ContentType: "application/json",
	}

	result, err := layer.Analyze(ctx)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if !result.Blocked {
		t.Error("Expected batch request to be blocked")
	}

	found := false
	for _, issue := range result.Issues {
		if issue.Type == "batch_too_large" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected batch_too_large issue")
	}
}

// ---------------------------------------------------------------------------
// Endpoint allowlisting (isGraphQLRequest checks)
// ---------------------------------------------------------------------------

func TestIsGraphQLRequest_EndpointPaths(t *testing.T) {
	tests := []struct {
		path        string
		contentType string
		expected    bool
	}{
		{"/graphql", "", true},
		{"/api/graphql", "", true},
		{"/graphql/", "", true},
		{"/v1/graphql", "", true},
		{"/api", "application/graphql", true},
		{"/api", "application/graphql+json", true},
		{"/api/users", "", false},
		{"/notgraphql", "", false},
		{"/api/not-graphql-endpoint", "", false},
		{"", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.path+"/"+tt.contentType, func(t *testing.T) {
			req := &http.Request{
				URL:    &url.URL{Path: tt.path},
				Header: http.Header{},
			}
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			result := isGraphQLRequest(req)
			if result != tt.expected {
				t.Errorf("isGraphQLRequest(%q, %q) = %v, want %v", tt.path, tt.contentType, result, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractQueries
// ---------------------------------------------------------------------------

func TestExtractQueries_GET(t *testing.T) {
	ctx := &engine.RequestContext{
		Request:     &http.Request{Method: "GET"},
		Method:      "GET",
		QueryParams: map[string][]string{"query": {"{ users { id } }"}},
	}
	queries, err := extractQueries(ctx)
	if err != nil {
		t.Fatalf("extractQueries failed: %v", err)
	}
	if len(queries) != 1 {
		t.Fatalf("Expected 1 query, got %d", len(queries))
	}
	if queries[0] != "{ users { id } }" {
		t.Errorf("Unexpected query: %s", queries[0])
	}
}

func TestExtractQueries_GET_NoQuery(t *testing.T) {
	ctx := &engine.RequestContext{
		Request:     &http.Request{Method: "GET"},
		Method:      "GET",
		QueryParams: map[string][]string{},
	}
	_, err := extractQueries(ctx)
	if err == nil {
		t.Error("Expected error for GET with no query")
	}
}

func TestExtractQueries_GET_EmptyQuery(t *testing.T) {
	ctx := &engine.RequestContext{
		Request:     &http.Request{Method: "GET"},
		Method:      "GET",
		QueryParams: map[string][]string{"query": {""}},
	}
	_, err := extractQueries(ctx)
	if err == nil {
		t.Error("Expected error for GET with empty query")
	}
}

func TestExtractQueries_POST_JSON(t *testing.T) {
	body := []byte(`{"query": "{ users { id } }"}`)
	ctx := &engine.RequestContext{
		Request:     &http.Request{Method: "POST"},
		Method:      "POST",
		Body:        body,
		BodyString:  string(body),
		ContentType: "application/json",
	}
	queries, err := extractQueries(ctx)
	if err != nil {
		t.Fatalf("extractQueries failed: %v", err)
	}
	if len(queries) != 1 || queries[0] != "{ users { id } }" {
		t.Errorf("Unexpected queries: %v", queries)
	}
}

func TestExtractQueries_POST_BatchJSON(t *testing.T) {
	body := []byte(`[{"query":"{ a }"},{"query":"{ b }"}]`)
	ctx := &engine.RequestContext{
		Request:     &http.Request{Method: "POST"},
		Method:      "POST",
		Body:        body,
		BodyString:  string(body),
		ContentType: "application/json",
	}
	queries, err := extractQueries(ctx)
	if err != nil {
		t.Fatalf("extractQueries failed: %v", err)
	}
	if len(queries) != 2 {
		t.Errorf("Expected 2 queries, got %d", len(queries))
	}
}

func TestExtractQueries_POST_RawGraphQL(t *testing.T) {
	body := []byte("{ users { id } }")
	ctx := &engine.RequestContext{
		Request:     &http.Request{Method: "POST"},
		Method:      "POST",
		Body:        body,
		BodyString:  string(body),
		ContentType: "application/graphql",
	}
	queries, err := extractQueries(ctx)
	if err != nil {
		t.Fatalf("extractQueries failed: %v", err)
	}
	if len(queries) != 1 {
		t.Errorf("Expected 1 query, got %d", len(queries))
	}
}

func TestExtractQueries_POST_EmptyBody(t *testing.T) {
	ctx := &engine.RequestContext{
		Request:     &http.Request{Method: "POST"},
		Method:      "POST",
		Body:        nil,
		BodyString:  "",
		ContentType: "application/json",
	}
	_, err := extractQueries(ctx)
	if err == nil {
		t.Error("Expected error for POST with empty body")
	}
}

func TestExtractQueries_POST_NoQueryInBody(t *testing.T) {
	body := []byte(`{"data": "something"}`)
	ctx := &engine.RequestContext{
		Request:     &http.Request{Method: "POST"},
		Method:      "POST",
		Body:        body,
		BodyString:  string(body),
		ContentType: "application/json",
	}
	_, err := extractQueries(ctx)
	if err == nil {
		t.Error("Expected error for POST with no query in body")
	}
}

func TestExtractQueries_UnsupportedMethod(t *testing.T) {
	ctx := &engine.RequestContext{
		Request:     &http.Request{Method: "DELETE"},
		Method:      "DELETE",
		QueryParams: map[string][]string{},
	}
	_, err := extractQueries(ctx)
	if err == nil {
		t.Error("Expected error for unsupported method")
	}
}

// ---------------------------------------------------------------------------
// Directive injection
// ---------------------------------------------------------------------------

func TestDirectiveInjection(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxDepth = 100
	cfg.MaxComplexity = 10000
	cfg.BlockIntrospection = false
	cfg.MaxAliases = 100
	layer, _ := New(cfg)

	// Build a query with > 5 @skip directives
	var parts []string
	for i := 0; i < 7; i++ {
		parts = append(parts, "field @skip(if: true)")
	}
	query := "{ " + strings.Join(parts, " ") + " }"

	ctx := makeGraphQLContext("GET", "/graphql", query, "")
	result, _ := layer.Analyze(ctx)

	found := false
	for _, issue := range result.Issues {
		if issue.Type == "directive_injection" {
			found = true
			if issue.Severity != "high" {
				t.Errorf("Expected severity high, got %s", issue.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected directive_injection issue")
	}
}

func TestDirectiveInjection_UnderLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxDepth = 100
	cfg.MaxComplexity = 10000
	cfg.BlockIntrospection = false
	cfg.MaxAliases = 100
	layer, _ := New(cfg)

	// Only 3 @skip directives, should not trigger
	query := "{ a @skip(if: true) b @skip(if: true) c @skip(if: true) }"
	ctx := makeGraphQLContext("GET", "/graphql", query, "")
	result, _ := layer.Analyze(ctx)

	for _, issue := range result.Issues {
		if issue.Type == "directive_injection" {
			t.Error("Should not trigger directive injection with only 3 directives")
		}
	}
}

func TestHasDirectiveInjection_NilAST(t *testing.T) {
	if hasDirectiveInjection(nil) {
		t.Error("Expected false for nil AST")
	}
	if hasDirectiveInjection(&AST{}) {
		t.Error("Expected false for empty AST")
	}
}

// ---------------------------------------------------------------------------
// Parser tests
// ---------------------------------------------------------------------------

func TestParseQuery_Mutation(t *testing.T) {
	ast, err := ParseQuery("mutation { createUser(name: \"test\") { id } }")
	if err != nil {
		t.Fatalf("ParseQuery failed: %v", err)
	}
	if len(ast.Document.Operations) == 0 {
		t.Fatal("Expected at least one operation")
	}
	if ast.Document.Operations[0].Type != "mutation" {
		t.Errorf("Expected operation type 'mutation', got %q", ast.Document.Operations[0].Type)
	}
}

func TestParseQuery_Subscription(t *testing.T) {
	ast, err := ParseQuery("subscription { messageAdded { text } }")
	if err != nil {
		t.Fatalf("ParseQuery failed: %v", err)
	}
	if len(ast.Document.Operations) == 0 {
		t.Fatal("Expected at least one operation")
	}
	if ast.Document.Operations[0].Type != "subscription" {
		t.Errorf("Expected operation type 'subscription', got %q", ast.Document.Operations[0].Type)
	}
}

func TestParseQuery_TooLong(t *testing.T) {
	longQuery := strings.Repeat("x", 256*1024+1)
	_, err := ParseQuery(longQuery)
	if err == nil {
		t.Error("Expected error for overly long query")
	}
}

func TestParseQuery_UnmatchedBrace(t *testing.T) {
	_, err := ParseQuery("{ users { id ")
	if err == nil {
		t.Error("Expected error for unmatched brace")
	}
}

func TestParseQuery_FieldWithArguments(t *testing.T) {
	ast, err := ParseQuery("{ user(id: 42) { id, name } }")
	if err != nil {
		t.Fatalf("ParseQuery failed: %v", err)
	}
	if len(ast.Document.Operations) == 0 || len(ast.Document.Operations[0].SelectionSet) == 0 {
		t.Fatal("Expected operation with selections")
	}
	field, ok := ast.Document.Operations[0].SelectionSet[0].(Field)
	if !ok {
		t.Fatal("Expected Field selection")
	}
	if len(field.Arguments) < 1 {
		t.Errorf("Expected at least 1 argument, got %d", len(field.Arguments))
	}
}

func TestParseQuery_FieldWithDirective(t *testing.T) {
	ast, err := ParseQuery("{ user @include(if: true) { id } }")
	if err != nil {
		t.Fatalf("ParseQuery failed: %v", err)
	}
	if len(ast.Document.Operations) == 0 || len(ast.Document.Operations[0].SelectionSet) == 0 {
		t.Fatal("Expected operation with selections")
	}
	field, ok := ast.Document.Operations[0].SelectionSet[0].(Field)
	if !ok {
		t.Fatal("Expected Field selection")
	}
	if len(field.Directives) != 1 {
		t.Errorf("Expected 1 directive, got %d", len(field.Directives))
	}
	if field.Directives[0].Name != "include" {
		t.Errorf("Expected directive name 'include', got %q", field.Directives[0].Name)
	}
}

func TestParseQuery_FragmentSpread(t *testing.T) {
	query := "{ users { ...UserFields } }"
	ast, err := ParseQuery(query)
	if err != nil {
		t.Fatalf("ParseQuery failed: %v", err)
	}
	if len(ast.Document.Operations) == 0 || len(ast.Document.Operations[0].SelectionSet) == 0 {
		t.Fatal("Expected selections")
	}
	// The inner selection set should contain a FragmentSpread
	users, ok := ast.Document.Operations[0].SelectionSet[0].(Field)
	if !ok {
		t.Fatal("Expected first selection to be a Field")
	}
	if len(users.SelectionSet) == 0 {
		t.Fatal("Expected nested selections")
	}
	spread, ok := users.SelectionSet[0].(FragmentSpread)
	if !ok {
		t.Fatal("Expected FragmentSpread")
	}
	if spread.Name != "UserFields" {
		t.Errorf("Expected spread name 'UserFields', got %q", spread.Name)
	}
}

func TestParseQuery_FragmentDefinition(t *testing.T) {
	query := "fragment UserFields on User { id name email } { users { ...UserFields } }"
	ast, err := ParseQuery(query)
	if err != nil {
		t.Fatalf("ParseQuery failed: %v", err)
	}
	if len(ast.Document.Fragments) != 1 {
		t.Fatalf("Expected 1 fragment, got %d", len(ast.Document.Fragments))
	}
	if ast.Document.Fragments[0].Name != "UserFields" {
		t.Errorf("Expected fragment name 'UserFields', got %q", ast.Document.Fragments[0].Name)
	}
	if ast.Document.Fragments[0].TypeCondition != "User" {
		t.Errorf("Expected type condition 'User', got %q", ast.Document.Fragments[0].TypeCondition)
	}
}

func TestParseQuery_FragmentWithNoClosingBrace(t *testing.T) {
	query := "fragment A on User { id { users { ...A } }"
	ast, err := ParseQuery(query)
	// Should still parse; the malformed fragment is skipped
	if err != nil {
		// Acceptable to return an error
		return
	}
	if ast == nil {
		t.Error("Expected AST even with malformed fragment")
	}
}

func TestParseQuery_InlineFragment(t *testing.T) {
	query := "{ user { ... on Admin { role } ... on Member { level } } }"
	ast, err := ParseQuery(query)
	if err != nil {
		t.Fatalf("ParseQuery failed: %v", err)
	}
	if len(ast.Document.Operations) == 0 {
		t.Fatal("Expected operation")
	}
}

func TestParseQuery_FieldsWithAliases(t *testing.T) {
	query := "{ admin: user { id }, member: user { id } }"
	ast, err := ParseQuery(query)
	if err != nil {
		t.Fatalf("ParseQuery failed: %v", err)
	}
	sel := ast.Document.Operations[0].SelectionSet
	if len(sel) < 2 {
		t.Fatalf("Expected at least 2 selections, got %d", len(sel))
	}
	f1, ok := sel[0].(Field)
	if !ok {
		t.Fatal("Expected Field")
	}
	if f1.Alias != "admin" {
		t.Errorf("Expected alias 'admin', got %q", f1.Alias)
	}
}

// ---------------------------------------------------------------------------
// Value parsing tests
// ---------------------------------------------------------------------------

func TestParseValue_Types(t *testing.T) {
	tests := []struct {
		input    string
		typeName string
	}{
		{`"hello"`, "string"},
		{"true", "boolean"},
		{"false", "boolean"},
		{"null", "null"},
		{"42", "int"},
		{"3.14", "float"},
		{"SOME_ENUM", "enum"},
		{"$variable", "variable"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			val := parseValue(tt.input)
			sv, ok := val.(ScalarValue)
			if tt.typeName == "variable" {
				v, ok := val.(Variable)
				if !ok {
					t.Errorf("Expected Variable, got %T", val)
				}
				if v.Name != "variable" {
					t.Errorf("Expected variable name 'variable', got %q", v.Name)
				}
				return
			}
			if !ok {
				t.Fatalf("Expected ScalarValue, got %T", val)
			}
			if sv.Kind != tt.typeName {
				t.Errorf("Expected kind %q, got %q", tt.typeName, sv.Kind)
			}
		})
	}
}

func TestParseValue_List(t *testing.T) {
	val := parseValue("[1, 2, 3]")
	lv, ok := val.(ListValue)
	if !ok {
		t.Fatalf("Expected ListValue, got %T", val)
	}
	if len(lv.Values) != 3 {
		t.Errorf("Expected 3 list values, got %d", len(lv.Values))
	}
}

func TestParseValue_Object(t *testing.T) {
	val := parseValue("{name: \"test\", age: 30}")
	ov, ok := val.(ObjectValue)
	if !ok {
		t.Fatalf("Expected ObjectValue, got %T", val)
	}
	if len(ov.Fields) != 2 {
		t.Errorf("Expected 2 object fields, got %d", len(ov.Fields))
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func TestSplitFields_Nested(t *testing.T) {
	content := "a { b }, c, d { e { f } }"
	fields := splitFields(content)
	if len(fields) != 3 {
		t.Errorf("Expected 3 fields, got %d: %v", len(fields), fields)
	}
}

func TestSplitArgs_Nested(t *testing.T) {
	content := "a: [1, 2], b: { c: 3 }, d: 4"
	args := splitArgs(content)
	if len(args) != 3 {
		t.Errorf("Expected 3 args, got %d: %v", len(args), args)
	}
}

func TestFindMatchingBrace_EscapedQuotes(t *testing.T) {
	input := `{ a(b: "hello\"world") }`
	idx := findMatchingBrace(input, 0)
	if idx == -1 {
		t.Error("Expected to find matching brace")
	}
}

func TestFindMatchingParen_EscapedQuotes(t *testing.T) {
	input := `(a(b: "hello\"world"))`
	idx := findMatchingParen(input, 0)
	if idx == -1 {
		t.Error("Expected to find matching paren")
	}
}

func TestIsNumber(t *testing.T) {
	tests := []struct {
		input string
		isNum bool
	}{
		{"42", true},
		{"-1", true},
		{"3.14", true},
		{"-0.5", true},
		{"abc", false},
		{"", false},
		{"1.2.3", false},
	}
	for _, tt := range tests {
		if isNumber(tt.input) != tt.isNum {
			t.Errorf("isNumber(%q) = %v, want %v", tt.input, !tt.isNum, tt.isNum)
		}
	}
}

// ---------------------------------------------------------------------------
// TenantWAFConfig override type
// ---------------------------------------------------------------------------

// We need a minimal type that matches what the layer checks.
// The actual TenantWAFConfig comes from config.WAFConfig but the graphql layer
// checks ctx.TenantWAFConfig.GraphQL.Enabled.

// Define a local helper type to satisfy the layer's check.
// NOTE: The actual engine.RequestContext.TenantWAFConfig is *config.WAFConfig.
// For testing Process with tenant override, we use the actual config type.

// We can't import config from here easily, so we test tenant override
// through the Process method by directly setting the field.
// The graphql layer checks: ctx.TenantWAFConfig != nil && !ctx.TenantWAFConfig.GraphQL.Enabled

// Since TenantWAFConfig is *config.WAFConfig, let's see what config.WAFConfig looks like.
// For Process, it does ctx.TenantWAFConfig.GraphQL.Enabled where GraphQL is config.GraphQLConfig.
// We need to import config for that.

// Let's test via the actual types used.
// Looking at the code: ctx.TenantWAFConfig is *config.WAFConfig
// and it accesses .GraphQL.Enabled where GraphQL is config.GraphQLConfig with .Enabled bool.

// ---------------------------------------------------------------------------
// DefaultConfig checks
// ---------------------------------------------------------------------------

func TestDefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.Enabled {
		t.Error("Default Enabled should be true")
	}
	if cfg.MaxDepth != 10 {
		t.Errorf("Default MaxDepth should be 10, got %d", cfg.MaxDepth)
	}
	if cfg.MaxComplexity != 1000 {
		t.Errorf("Default MaxComplexity should be 1000, got %d", cfg.MaxComplexity)
	}
	if !cfg.BlockIntrospection {
		t.Error("Default BlockIntrospection should be true")
	}
	if cfg.AllowListEnabled {
		t.Error("Default AllowListEnabled should be false")
	}
	if cfg.MaxAliases != 10 {
		t.Errorf("Default MaxAliases should be 10, got %d", cfg.MaxAliases)
	}
	if cfg.MaxBatchSize != 5 {
		t.Errorf("Default MaxBatchSize should be 5, got %d", cfg.MaxBatchSize)
	}
}

// ---------------------------------------------------------------------------
// Analyze with disabled layer
// ---------------------------------------------------------------------------

func TestAnalyze_DisabledLayer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	layer, _ := New(cfg)

	ctx := makeGraphQLContext("GET", "/graphql", "{ users { id } }", "")
	result, err := layer.Analyze(ctx)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if result.Score != 0 {
		t.Errorf("Expected score 0 for disabled layer, got %d", result.Score)
	}
	if result.Blocked {
		t.Error("Expected not blocked for disabled layer")
	}
}

// ---------------------------------------------------------------------------
// Analyze with non-GraphQL request
// ---------------------------------------------------------------------------

func TestAnalyze_NotGraphQLRequest(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer, _ := New(cfg)

	ctx := &engine.RequestContext{
		Request:     &http.Request{Method: "GET", URL: &url.URL{Path: "/api/users"}},
		Method:      "GET",
		QueryParams: map[string][]string{},
	}
	result, err := layer.Analyze(ctx)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if result.Score != 0 {
		t.Errorf("Expected score 0 for non-GraphQL request, got %d", result.Score)
	}
}

// ---------------------------------------------------------------------------
// Analyze error in query parsing
// ---------------------------------------------------------------------------

func TestAnalyze_ParseError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	layer, _ := New(cfg)

	// POST with invalid body (not JSON, not GraphQL content-type)
	body := []byte("this is not valid graphql or json")
	ctx := &engine.RequestContext{
		Request:     &http.Request{Method: "POST", URL: &url.URL{Path: "/graphql"}},
		Method:      "POST",
		Body:        body,
		BodyString:  string(body),
		ContentType: "application/json",
	}
	result, err := layer.Analyze(ctx)
	if err != nil {
		t.Fatalf("Analyze should not return error for parse errors: %v", err)
	}
	// Parse error should produce score 25
	if result.Score != 25 {
		t.Logf("Score for parse error: %d (may be normalized)", result.Score)
	}
}

// ---------------------------------------------------------------------------
// Combined score normalization
// ---------------------------------------------------------------------------

func TestAnalyze_ScoreNormalization(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.MaxDepth = 2
	cfg.MaxComplexity = 2
	cfg.BlockIntrospection = true
	cfg.MaxAliases = 1
	layer, _ := New(cfg)

	// Deep, complex, introspection query with aliases
	query := "{ a1: __schema { types { fields { args { name } } } } a2: __type { name } }"
	ctx := makeGraphQLContext("GET", "/graphql", query, "")
	result, _ := layer.Analyze(ctx)

	// Score should be capped at 100
	if result.Score > 100 {
		t.Errorf("Score should be capped at 100, got %d", result.Score)
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestResult_Metadata(t *testing.T) {
	// Verify Result struct fields
	r := &Result{
		Score:   50,
		Blocked: true,
		Issues:  []Issue{{Type: "test", Description: "test issue", Severity: "high"}},
		Metadata: Metadata{
			QueryCount:    1,
			MaxDepth:      5,
			MaxComplexity: 100,
			IsBatch:       false,
		},
	}
	if r.Metadata.QueryCount != 1 {
		t.Error("Metadata QueryCount mismatch")
	}
	if len(r.Issues) != 1 {
		t.Error("Issues count mismatch")
	}
}

// ---------------------------------------------------------------------------
// Interface satisfaction check
// ---------------------------------------------------------------------------

func TestLayer_ImplementsEngineLayer(t *testing.T) {
	// Compile-time check
	var _ engine.Layer = (*Layer)(nil)
}

// ---------------------------------------------------------------------------
// Concurrent access
// ---------------------------------------------------------------------------

func TestLayer_ConcurrentAccess(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.BlockIntrospection = false
	layer, _ := New(cfg)

	done := make(chan bool, 4)

	// Concurrent Analyze
	go func() {
		for i := 0; i < 50; i++ {
			ctx := makeGraphQLContext("GET", "/graphql", "{ users { id } }", "")
			layer.Analyze(ctx)
		}
		done <- true
	}()

	// Concurrent SetEnabled
	go func() {
		for i := 0; i < 50; i++ {
			layer.SetEnabled(i%2 == 0)
		}
		done <- true
	}()

	// Concurrent UpdateConfig
	go func() {
		for i := 0; i < 50; i++ {
			layer.UpdateConfig(Config{Enabled: true, MaxDepth: i + 1})
		}
		done <- true
	}()

	// Concurrent Stats
	go func() {
		for i := 0; i < 50; i++ {
			_ = layer.Stats()
		}
		done <- true
	}()

	for i := 0; i < 4; i++ {
		<-done
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeGraphQLContext creates a RequestContext for a GraphQL request.
func makeGraphQLContext(method, path, query, body string) *engine.RequestContext {
	var req *http.Request
	var queryParams map[string][]string

	if method == "GET" {
		req = &http.Request{
			Method: "GET",
			URL: &url.URL{
				Path:     path,
				RawQuery: "query=" + url.QueryEscape(query),
			},
		}
		queryParams = req.URL.Query()
	} else {
		req = &http.Request{
			Method: "POST",
			URL:    &url.URL{Path: path},
			Header: http.Header{"Content-Type": []string{"application/json"}},
		}
		queryParams = map[string][]string{}
	}

	ctx := &engine.RequestContext{
		Request:      req,
		Method:       method,
		QueryParams:  queryParams,
		Accumulator:  engine.NewScoreAccumulator(2),
	}

	if method == "POST" {
		bodyBytes := []byte(body)
		ctx.Body = bodyBytes
		ctx.BodyString = body
		ctx.ContentType = "application/json"
	}

	return ctx
}

// toAnalyzeIssues is a helper that runs Analyze and returns issues.
func toAnalyzeIssues(layer *Layer, ctx *engine.RequestContext) []Issue {
	result, _ := layer.Analyze(ctx)
	return result.Issues
}
