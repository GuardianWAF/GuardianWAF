package alerting

import (
	"net/http"
	"testing"
)

func TestManagerHTTPClientValidHTTPSRedirectAllowed(t *testing.T) {
	prev := allowWebhookPrivate.Load()
	allowWebhookPrivate.Store(false)
	defer allowWebhookPrivate.Store(prev)

	m := NewManager(nil)
	defer m.Close()

	req, err := http.NewRequest(http.MethodPost, "https://example.com/webhook", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := m.httpClient.CheckRedirect(req, nil); err != nil {
		t.Fatalf("expected valid HTTPS redirect to be allowed, got %v", err)
	}
}
