package acme

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// Regression (bug-hunt round 30): signedPost never retried on 400
// urn:ietf:params:acme:error:badNonce. The nonce pool persists for the
// Client's lifetime (one Client per process, held by CertDiskStore across
// 12h-tick renewals), so pooled nonces are guaranteed stale by the first
// renewal after an idle period: the first signed POST pops a dead nonce, the
// CA answers 400 badNonce, and the whole ObtainCertificate/Register aborted —
// a logged renewal failure that self-healed only at the NEXT tick. RFC 8555
// §6.5 requires fetching a fresh nonce and retrying.
//
// The fix splits the retry into signedPost: on a badNonce problem document
// the rejected response is discarded, a fresh nonce is fetched from the
// newNonce endpoint (bypassing the pool), and the request is replayed once.
//
// Deterministic: the harness CA rejects exactly the FIRST account POST with
// 400/badNonce and accepts subsequent POSTs, so pre-fix Register fails and
// post-fix it recovers. The distinct-nonce assertion proves a fresh-nonce
// retry rather than a blind replay of the rejected request.

func TestSignedPost_RetriesOnBadNonce(t *testing.T) {
	var accountPOSTs atomic.Int64
	var nonceSeq atomic.Int64
	var badNonceSent atomic.Bool
	seenNonces := make(map[string]bool)
	lockCh := make(chan struct{}, 1)

	var baseURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		// The client fetches the directory from the configured URL itself.
		// Absolute URLs are required by validateEndpoint's origin
		// confinement, exactly like a real ACME directory.
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"newNonce":%q,"newAccount":%q,"newOrder":%q}`,
			baseURL+"/nonce", baseURL+"/account", baseURL+"/order")
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", nonceSeq.Add(1)))
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/account", func(w http.ResponseWriter, r *http.Request) {
		// Extract the JWS protected header's nonce to verify the retry
		// carries a fresh value instead of replaying the rejected one.
		var jws struct {
			Protected string `json:"protected"`
		}
		_ = json.NewDecoder(r.Body).Decode(&jws)
		var protected struct {
			Nonce string `json:"nonce"`
		}
		if raw, err := base64.RawURLEncoding.DecodeString(jws.Protected); err == nil {
			_ = json.Unmarshal(raw, &protected)
		}
		lockCh <- struct{}{}
		seenNonces[protected.Nonce] = true
		<-lockCh

		accountPOSTs.Add(1)
		if badNonceSent.CompareAndSwap(false, true) {
			// First POST: reject the pooled nonce like a real CA after a
			// nonce rotation, and hand out a fresh nonce.
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", nonceSeq.Add(1)))
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"type":"urn:ietf:params:acme:error:badNonce","detail":"nonce expired"}`)
			return
		}
		w.Header().Set("Location", baseURL+"/account/1")
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", nonceSeq.Add(1)))
		w.WriteHeader(http.StatusCreated)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	baseURL = srv.URL

	client := NewClient(srv.URL)
	if err := client.Init(nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := client.Register("recovery@example.com"); err != nil {
		t.Fatalf("FAIL: Register aborted on 400 badNonce (%v) — signedPost must fetch a fresh nonce and retry once (RFC 8555 §6.5)", err)
	}

	if posts := accountPOSTs.Load(); posts < 2 {
		t.Fatalf("expected the badNonce retry to reach the server a second time, got %d POSTs", posts)
	}
	if nonces := len(seenNonces); nonces < 2 {
		t.Fatalf("retry reused the rejected nonce (saw %d distinct nonces) — a blind replay is not a fresh-nonce retry", nonces)
	}
}
