package challenge

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type challengeErrorReader struct{}

func (challengeErrorReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func withChallengeEntropy(t *testing.T, read func([]byte) (int, error), reader io.Reader) {
	t.Helper()
	oldRead, oldReader := randomRead, randomReader
	randomRead, randomReader = read, reader
	t.Cleanup(func() { randomRead, randomReader = oldRead, oldReader })
}

func TestEntropyFailurePaths(t *testing.T) {
	fail := func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

	t.Run("default config", func(t *testing.T) {
		withChallengeEntropy(t, fail, challengeErrorReader{})
		if _, err := DefaultConfigE(); err == nil {
			t.Fatal("expected entropy error")
		}
	})
	t.Run("new service and layer", func(t *testing.T) {
		withChallengeEntropy(t, fail, challengeErrorReader{})
		if _, err := NewService(Config{}); err == nil {
			t.Fatal("expected entropy error")
		}
		if _, err := NewLayer(&Config{Enabled: true}); err == nil {
			t.Fatal("expected layer entropy error")
		}
	})
	t.Run("challenge fallback succeeds", func(t *testing.T) {
		withChallengeEntropy(t, fail, strings.NewReader("0123456789abcdef"))
		svc := &Service{}
		if got, err := svc.generateChallenge(); err != nil || len(got) != 32 {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("challenge fallback fails", func(t *testing.T) {
		withChallengeEntropy(t, fail, challengeErrorReader{})
		svc := &Service{}
		if _, err := svc.generateChallenge(); err == nil {
			t.Fatal("expected fallback error")
		}
	})
	t.Run("challenge page failure", func(t *testing.T) {
		withChallengeEntropy(t, fail, challengeErrorReader{})
		svc := &Service{}
		w := httptest.NewRecorder()
		svc.ServeChallengePage(w, httptest.NewRequest(http.MethodGet, "/", nil))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d", w.Code)
		}
	})
}
