package acme

// Regression (bug-hunt round 70): signedPost returned 400 problem responses
// with a CONSUMED body. isBadNonceResponse drained the body of any 400 to
// inspect its problem type; for a non-badNonce problem signedPost handed the
// response back with nothing left to read, so completeAuthorization and
// pollCertificate failed with "unexpected end of JSON input" and
// Register/createOrder/finalizeOrder reported empty details — the CA's
// problem document was destroyed exactly where an operator needs it.
//
// signedPost now reads the 400 body exactly once, buffers it, replays once on
// badNonce (the round-30 contract, exercised end-to-end by
// TestSignedPost_RetriesOnBadNonce), and restores the body for every other
// problem document so the caller sees the CA's type and detail.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSignedPost_Preserves400ProblemBody(t *testing.T) {
	var baseURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`,
			baseURL+"/nonce", baseURL+"/account", baseURL+"/order")
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-proof-1")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/problem", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.Header().Set("Replay-Nonce", "nonce-proof-2")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"slow down"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	baseURL = srv.URL

	c := NewClient(srv.URL + "/directory")
	if err := c.Init(nil); err != nil {
		t.Fatalf("Init: %v", err)
	}

	resp, err := c.signedPost(srv.URL+"/problem", map[string]any{}, false)
	if err != nil {
		t.Fatalf("signedPost: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	body, err := readACMEResponse(resp.Body)
	if err != nil {
		t.Fatalf("reading 400 problem body: %v", err)
	}
	var problem struct {
		Type   string `json:"type"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(body, &problem); err != nil {
		t.Fatalf("signedPost returned the 400 with a consumed body — caller reads %q (%v); the CA's problem document was destroyed", string(body), err)
	}
	if problem.Type != "urn:ietf:params:acme:error:rateLimited" || problem.Detail != "slow down" {
		t.Fatalf("problem document corrupted: type=%q detail=%q", problem.Type, problem.Detail)
	}
}
