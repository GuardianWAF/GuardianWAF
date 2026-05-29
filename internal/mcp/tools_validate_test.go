package mcp

import "testing"

// TestToolDefinitionsMatchHandlers guards against tool-name drift: every tool
// advertised in AllTools() must have a registered handler and vice versa.
// Tool names are declared twice (schema + handler wiring), so a typo in either
// place would silently break a tool; this test fails fast on that mismatch.
func TestToolDefinitionsMatchHandlers(t *testing.T) {
	s := NewServer(nil, nil)
	s.RegisterAllTools()
	if err := s.ValidateTools(); err != nil {
		t.Fatal(err)
	}
}
