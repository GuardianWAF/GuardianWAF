package graphql

import (
	"encoding/json"
	"testing"
)

// FuzzGraphQLDetector exercises the depth/complexity parser with arbitrary
// input to find panics or hangs. The parser must never crash on malformed
// GraphQL-like input.
func FuzzGraphQLDetector(f *testing.F) {
	seeds := []string{
		`{user{name}}`,
		`{"query":"{a{b{c}}}"}`,
		`{a b c}`,
		`{a # comment
		{b}}`,
		`{__schema{types{name}}}`,
		`[{},{},{}]`,
		`{`,
		`}`,
		`{{{{`,
		`{"query":"`,
		`""""block string"""}`,
		`#@directive(a:b)`,
		`query($v:String!){field(arg:$v){nested}}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		det := NewDetector(true, 1.0, 5, 100, true, []string{"/graphql"})

		// Must not panic as raw GraphQL body.
		_ = det.Process(makeCtx("application/graphql", "/graphql", "", raw))

		// Must not panic as JSON-wrapped body.
		jsonBody, _ := json.Marshal(map[string]string{"query": raw})
		_ = det.Process(makeCtx("application/json", "/graphql", "", string(jsonBody)))

		// Must not panic with raw input directly through the parser.
		cleaned := stripCommentsAndStrings(raw)
		_, _ = measureDepthComplexity(cleaned)
	})
}
