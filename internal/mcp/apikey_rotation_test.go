package mcp

import (
	"bufio"
	"encoding/json"
	"io"
	"testing"
)

// Regression tests: rotating the MCP API key via SetAPIKey must invalidate
// any session authenticated against the previous key. SetAPIKey used to swap
// s.apiKey while leaving the sticky s.authenticated flag armed, so a client
// authenticated under the old key retained full tools/call access with no
// credential at all — and re-initialize attempts presenting the OLD key were
// silently accepted (handleInitialize skips validation while checkAuth() is
// true). Key rotation was a no-op for already-authenticated sessions.

// stdioConv drives a Server over the real stdio JSON-RPC path with a
// synchronous two-pipe handshake: every send reads exactly one response, so
// the caller controls request/response interleaving deterministically (with a
// plain bytes.Buffer output, a mid-conversation SetAPIKey could race with the
// in-flight handling of an already-consumed request line).
type stdioConv struct {
	inW    *io.PipeWriter
	outR   *bufio.Reader
	outW   *io.PipeWriter
	runErr chan error
}

func startStdioServer(t *testing.T, srv *Server) *stdioConv {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	srv.reader = bufio.NewReader(inR)
	srv.writer = outW
	conv := &stdioConv{inW: inW, outR: bufio.NewReader(outR), outW: outW, runErr: make(chan error, 1)}
	go func() { conv.runErr <- srv.Run() }()
	t.Cleanup(func() {
		_ = inW.Close()
		_ = outW.Close()
		<-conv.runErr
	})
	return conv
}

// send writes one request and blocks until the matching response arrives.
func (c *stdioConv) send(t *testing.T, id int, method string, params map[string]any) JSONRPCResponse {
	t.Helper()
	line := sendRequest(id, method, params)
	if _, err := c.inW.Write([]byte(line)); err != nil {
		t.Fatalf("write request %d: %v", id, err)
	}
	raw, err := c.outR.ReadString('\n')
	if err != nil {
		t.Fatalf("read response %d: %v", id, err)
	}
	var resp JSONRPCResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("response %d not valid JSON: %v", id, err)
	}
	if got, ok := resp.ID.(float64); !ok || int(got) != id {
		t.Fatalf("response id %v does not match request id %d", resp.ID, id)
	}
	return resp
}

func TestAPIKeyRotationInvalidatesStaleSession(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetAPIKey("key-A")
	srv.RegisterTool("echo", func(params json.RawMessage) (any, error) {
		return map[string]any{"ok": true}, nil
	})
	conv := startStdioServer(t, srv)

	// Authenticate with key-A and confirm tool access.
	if resp := conv.send(t, 1, "initialize", map[string]any{"api_key": "key-A"}); resp.Error != nil {
		t.Fatalf("initialize with correct key rejected: %d %s", resp.Error.Code, resp.Error.Message)
	}
	if resp := conv.send(t, 2, "tools/call", map[string]any{"name": "echo", "arguments": map[string]any{}}); resp.Error != nil {
		t.Fatalf("tools/call rejected while properly authenticated: %d %s", resp.Error.Code, resp.Error.Message)
	}

	// Rotate the credential. The old session must die.
	srv.SetAPIKey("key-B")

	resp := conv.send(t, 3, "tools/call", map[string]any{"name": "echo", "arguments": map[string]any{}})
	if resp.Error == nil {
		t.Fatal("FAIL: tools/call succeeded after key rotation without presenting the new key — stale session retained access")
	}
	if resp.Error.Code != ErrCodeUnauthorized {
		t.Fatalf("expected %d after rotation, got %d %s", ErrCodeUnauthorized, resp.Error.Code, resp.Error.Message)
	}

	// Re-initialize with the OLD key must be rejected.
	resp = conv.send(t, 4, "initialize", map[string]any{"api_key": "key-A"})
	if resp.Error == nil {
		t.Fatal("FAIL: re-initialize with the OLD key was accepted after rotation")
	}
	if resp.Error.Code != ErrCodeUnauthorized {
		t.Fatalf("expected %d for old key, got %d %s", ErrCodeUnauthorized, resp.Error.Code, resp.Error.Message)
	}

	// Recovery: re-initialize with the NEW key restores access.
	if resp := conv.send(t, 5, "initialize", map[string]any{"api_key": "key-B"}); resp.Error != nil {
		t.Fatalf("initialize with new key rejected: %d %s", resp.Error.Code, resp.Error.Message)
	}
	if resp := conv.send(t, 6, "tools/call", map[string]any{"name": "echo", "arguments": map[string]any{}}); resp.Error != nil {
		t.Fatalf("tools/call rejected after re-authenticating with the new key: %d %s", resp.Error.Code, resp.Error.Message)
	}
}

// Re-setting the identical key is not a credential change and must not
// de-authenticate an already-valid session.
func TestSetAPIKeySameValueKeepsSession(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetAPIKey("key-A")
	srv.RegisterTool("echo", func(params json.RawMessage) (any, error) {
		return map[string]any{"ok": true}, nil
	})
	conv := startStdioServer(t, srv)

	if resp := conv.send(t, 1, "initialize", map[string]any{"api_key": "key-A"}); resp.Error != nil {
		t.Fatalf("initialize rejected: %d %s", resp.Error.Code, resp.Error.Message)
	}
	srv.SetAPIKey("key-A")
	if resp := conv.send(t, 2, "tools/call", map[string]any{"name": "echo", "arguments": map[string]any{}}); resp.Error != nil {
		t.Fatalf("identical re-set de-authenticated a valid session: %d %s", resp.Error.Code, resp.Error.Message)
	}
}

// Unit pin on the root cause: the sticky authenticated flag is valid only for
// the credential it was established against.
func TestSetAPIKeyRotationClearsAuthenticatedFlag(t *testing.T) {
	srv := NewServer(nil, nil)
	srv.SetAPIKey("a")
	srv.markAuthenticated()
	if !srv.checkAuth() {
		t.Fatal("precondition: session should be authenticated")
	}
	srv.SetAPIKey("b")
	if srv.checkAuth() {
		t.Fatal("FAIL: authenticated flag survived a key rotation")
	}
	// Idempotent set must not clear an established session.
	srv.SetAPIKey("b")
	srv.markAuthenticated()
	srv.SetAPIKey("b")
	if !srv.checkAuth() {
		t.Fatal("identical re-set de-authenticated the session")
	}
}
