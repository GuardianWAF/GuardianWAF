package acme

// Regression (bug-hunt round 72): completeAuthorization ignored the
// challenge-POST status code. A CA rejection (400 problem document) on the
// challenge trigger POST was silently ignored, and the request fell into the
// authorization poll — 30 x acmePollInterval (60s default) for an
// authorization that can never become valid because the CA never accepted
// the trigger — ending in a generic "authorization poll timeout" instead of
// the CA's problem document. A non-2xx challenge response now fails fast
// with the problem detail (readable since the round-70 signedPost fix);
// a 2xx proceeds to the poll (normal asynchronous validation).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCompleteAuthorization_FailsFastOnChallengeRejection(t *testing.T) {
	var baseURL string
	challengeHits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`,
			baseURL+"/nonce", baseURL+"/account", baseURL+"/order")
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-r72")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/authz", func(w http.ResponseWriter, _ *http.Request) {
		// Permanently pending: the CA never accepted the challenge trigger,
		// so polling can never observe "valid".
		authz := map[string]any{
			"status":     "pending",
			"identifier": map[string]string{"type": "dns", "value": "round72.example.com"},
			"challenges": []map[string]string{
				{"type": "http-01", "url": baseURL + "/challenge", "token": "token"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authz)
	})
	mux.HandleFunc("/challenge", func(w http.ResponseWriter, _ *http.Request) {
		challengeHits++
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many challenges"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	baseURL = srv.URL

	c := NewClient(srv.URL + "/directory")
	if err := c.Init(nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
	c.pollTimeout = 3 * time.Second // bounds the pre-fix poll; post-fix it is never reached

	start := time.Now()
	err := c.completeAuthorization(srv.URL+"/authz", NewHTTP01Handler())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("challenge POST was rejected with 400 but completeAuthorization returned nil")
	}
	if !strings.Contains(err.Error(), "challenge request failed") || !strings.Contains(err.Error(), "rateLimited") {
		t.Fatalf("expected the CA's problem document to surface (challenge request failed + rateLimited), got %q after %v", err, elapsed)
	}
	if elapsed > time.Second {
		t.Fatalf("completeAuthorization burned %v in the authorization poll for an already-rejected challenge", elapsed)
	}
	if challengeHits != 1 {
		t.Fatalf("expected exactly 1 challenge POST, got %d", challengeHits)
	}
}

// Boundary: a 2xx challenge response must keep entering the authorization
// poll — the fix only diverts non-2xx rejections; normal asynchronous
// validation is unchanged.
func TestCompleteAuthorization_ChallengeAcceptedStillPolls(t *testing.T) {
	var baseURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`,
			baseURL+"/nonce", baseURL+"/account", baseURL+"/order")
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-r72b")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/authz", func(w http.ResponseWriter, _ *http.Request) {
		authz := map[string]any{
			"status":     "pending",
			"identifier": map[string]string{"type": "dns", "value": "polling.example.com"},
			"challenges": []map[string]string{
				{"type": "http-01", "url": baseURL + "/challenge", "token": "token"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authz)
	})
	mux.HandleFunc("/challenge", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	baseURL = srv.URL

	c := NewClient(srv.URL + "/directory")
	if err := c.Init(nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
	c.pollTimeout = 300 * time.Millisecond // authorization stays pending, so the poll must time out

	err := c.completeAuthorization(srv.URL+"/authz", NewHTTP01Handler())
	if err == nil {
		t.Fatal("expected the authorization poll to run and time out for a pending authorization")
	}
	if !strings.Contains(err.Error(), "poll timeout") {
		t.Fatalf("expected the poll to run after an accepted challenge, got: %v", err)
	}
}
