package clientside

// Regression (round 2026-09-24-r22-wire-regression): the engine composition
// of the response transforms — the clientside hook (Magecart/agent-injection)
// and the DLP hook (response masking, added round 2026-09-24-r21) — must work
// with BOTH layers enabled in one pipeline: the agent is injected AND the PII
// is masked in the same response.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/dlp"
)

type r22NopEventStore struct{}

func (r22NopEventStore) Store(event engine.Event) error { return nil }
func (r22NopEventStore) Close() error                   { return nil }

type r22NopEventBus struct{}

func (r22NopEventBus) Subscribe(ch chan<- engine.Event) {}
func (r22NopEventBus) Publish(event engine.Event)       {}
func (r22NopEventBus) Close()                           {}

func TestBothLayersCompose_AgentInjectedAndCardMasked(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Events.Storage = "memory"
	eng, err := engine.NewEngine(cfg, r22NopEventStore{}, r22NopEventBus{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { eng.Close() })

	clientCfg := DefaultConfig()
	clientCfg.Enabled = true
	clientCfg.Mode = "monitor"
	clientCfg.AgentInjection.Enabled = true
	eng.AddLayer(engine.OrderedLayer{Layer: NewLayer(clientCfg), Order: engine.OrderClientSide})

	dlpCfg := &dlp.Config{
		Enabled:      true,
		ScanResponse: true,
		MaskResponse: true,
		MaxBodySize:  1024 * 1024,
		Patterns:     []string{"credit_card"},
	}
	eng.AddLayer(engine.OrderedLayer{Layer: dlp.NewLayer(dlpCfg), Order: engine.OrderDLP})

	card := "4111111111111111"
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head></head><body>{"refund_to":"` + card + `"}</body></html>`))
	})
	mw := httptest.NewServer(eng.Middleware(next))
	t.Cleanup(mw.Close)

	resp, err := http.Get(mw.URL + "/checkout")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	got := string(body)

	if !strings.Contains(got, agentMarker) {
		t.Fatalf("agent not injected (clientside transform missing): %q", got)
	}
	if strings.Contains(got, card) {
		t.Fatalf("raw card leaked (dlp transform missing): %q", got)
	}
}
