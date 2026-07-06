package alerting

import (
	"net/http"
	"testing"
)

func TestSend_DirectBadURLIncrementsFailed(t *testing.T) {
	m := NewManager(nil)
	before := m.GetStats().Failed

	m.send(&WebhookTarget{Name: "bad", URL: "http://\x00invalid", Type: "generic"}, &Alert{Action: "block"})

	after := m.GetStats().Failed
	if after != before+1 {
		t.Fatalf("failed count = %d, want %d", after, before+1)
	}
}

func TestManagerHTTPClientAllowsRedirectWhenPrivateTargetsEnabled(t *testing.T) {
	prev := allowWebhookPrivate.Load()
	allowWebhookPrivate.Store(true)
	defer allowWebhookPrivate.Store(prev)

	m := NewManager(nil)
	defer m.Close()

	req, err := http.NewRequest(http.MethodPost, "https://127.0.0.1/webhook", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := m.httpClient.CheckRedirect(req, nil); err != nil {
		t.Fatalf("expected redirect to be allowed, got %v", err)
	}
}

func TestDispatchReturnsClosedWhenManagerClosing(t *testing.T) {
	m := NewManager(nil)
	m.closing.Store(true)

	if got := m.dispatch(func() {}); got != dispatchClosed {
		t.Fatalf("dispatch result = %v, want %v", got, dispatchClosed)
	}
}

func TestValidateHostNotPrivate_AllowsPublicIP(t *testing.T) {
	if err := validateHostNotPrivate("8.8.8.8"); err != nil {
		t.Fatalf("expected public IP to be allowed, got %v", err)
	}
}

