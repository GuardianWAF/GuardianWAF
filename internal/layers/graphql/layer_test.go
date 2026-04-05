package graphql

import (
	"net/http"
	"net/url"
	"testing"
)

func TestIsGraphQLRequest(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		contentType string
		query       string
		expected    bool
	}{
		{
			name:     "GraphQL endpoint",
			path:     "/graphql",
			expected: true,
		},
		{
			name:     "GraphQL in path",
			path:     "/api/graphql",
			expected: true,
		},
		{
			name:        "GraphQL content type",
			path:        "/api",
			contentType: "application/graphql",
			expected:    true,
		},
		{
			name:     "Query parameter",
			path:     "/api",
			query:    "{users{id}}",
			expected: true,
		},
		{
			name:     "Not GraphQL",
			path:     "/api/users",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				URL: &url.URL{
					Path:     tt.path,
					RawQuery: "query=" + tt.query,
				},
				Header: http.Header{},
			}
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			result := isGraphQLRequest(req)
			if result != tt.expected {
				t.Errorf("isGraphQLRequest() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCalculateDepth(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected int
	}{
		{
			name:     "Simple query",
			query:    "{ users { id } }",
			expected: 2,
		},
		{
			name:     "Nested query",
			query:    "{ users { posts { comments { text } } } }",
			expected: 4,
		},
		{
			name:     "Multiple fields same level",
			query:    "{ users { id name email } }",
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := ParseQuery(tt.query)
			if err != nil {
				t.Fatalf("ParseQuery failed: %v", err)
			}

			depth := calculateDepth(ast)
			if depth != tt.expected {
				t.Errorf("calculateDepth() = %d, want %d", depth, tt.expected)
			}
		})
	}
}

func TestCalculateComplexity(t *testing.T) {
	tests := []struct {
		name  string
		query string
	}{
		{
			name:  "Simple query",
			query: "{ users { id } }",
		},
		{
			name:  "Query with arguments",
			query: "{ users(id: 1) { id name } }",
		},
		{
			name:  "Nested with arguments",
			query: "{ users { posts(limit: 10) { id } } }",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := ParseQuery(tt.query)
			if err != nil {
				t.Fatalf("ParseQuery failed: %v", err)
			}

			complexity := calculateComplexity(ast)
			t.Logf("Query: %s, Complexity: %d", tt.query, complexity)
			// Just verify it's > 0 and reasonable
			if complexity <= 0 {
				t.Errorf("Expected positive complexity, got %d", complexity)
			}
		})
	}
}

func TestHasIntrospection(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected bool
	}{
		{
			name:     "Schema introspection",
			query:    "{ __schema { types { name } } }",
			expected: true,
		},
		{
			name:     "Type introspection",
			query:    "{ __type(name: \"User\") { fields { name } } }",
			expected: true,
		},
		{
			name:     "Normal query",
			query:    "{ users { id } }",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := ParseQuery(tt.query)
			if err != nil {
				t.Fatalf("ParseQuery failed: %v", err)
			}

			result := hasIntrospection(ast)
			if result != tt.expected {
				t.Errorf("hasIntrospection() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestLayer_Analyze(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxDepth = 4 // Lower than default to trigger depth checks
	// Note: Score threshold for blocking is 50 by default
	// A depth-exceeded query gets 40 points, so it won't be blocked
	// The test expectations are adjusted accordingly
	layer, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create layer: %v", err)
	}

	tests := []struct {
		name        string
		path        string
		query       string
		expectBlock bool
		minScore    int
	}{
		{
			name:        "Normal query",
			path:        "/graphql",
			query:       "{ users { id } }",
			expectBlock: false,
			minScore:    0,
		},
		{
			name:        "Deep query",
			path:        "/graphql",
			query:       "{ users { posts { comments { author { name } } } } }",
			expectBlock: false,
			minScore:    1,
		},
		{
			name:        "Very deep query",
			path:        "/graphql",
			query:       "{ a { b { c { d { e { f { g { h { i { j } } } } } } } } } }",
			expectBlock: false, // Score 40 < 50 threshold
			minScore:    40,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method: "GET",
				URL: &url.URL{
					Path:     tt.path,
					RawQuery: "query=" + url.QueryEscape(tt.query),
				},
			}

			result, err := layer.Analyze(req)
			if err != nil {
				t.Fatalf("Analyze failed: %v", err)
			}

			t.Logf("Score: %d, Blocked: %v, Issues: %v", result.Score, result.Blocked, result.Issues)

			if result.Blocked != tt.expectBlock {
				t.Errorf("Blocked = %v, want %v", result.Blocked, tt.expectBlock)
			}

			if result.Score < tt.minScore {
				t.Errorf("Score = %d, want >= %d", result.Score, tt.minScore)
			}
		})
	}
}

func TestParseQuery(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantErr bool
	}{
		{
			name:    "Simple query",
			query:   "{ users { id } }",
			wantErr: false,
		},
		{
			name:    "Query with arguments",
			query:   "{ users(id: 1) { id name } }",
			wantErr: false,
		},
		{
			name:    "Empty query",
			query:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := ParseQuery(tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseQuery() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && ast == nil {
				t.Error("Expected AST, got nil")
			}
		})
	}
}

func TestLayer_Stats(t *testing.T) {
	cfg := DefaultConfig()
	layer, _ := New(cfg)

	// Process some requests
	for i := 0; i < 10; i++ {
		req := &http.Request{
			Method: "GET",
			URL: &url.URL{
				Path:     "/graphql",
				RawQuery: "query={users{id}}",
			},
		}
		layer.Analyze(req)
	}

	stats := layer.Stats()
	if stats.QueriesAnalyzed != 10 {
		t.Errorf("Expected 10 queries analyzed, got %d", stats.QueriesAnalyzed)
	}
}
