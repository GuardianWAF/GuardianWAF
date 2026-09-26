package dashboard

// Regression: API-validation schema uploads must be CWD-independent.
//
// History: apiValidationAdapter.LoadSchema staged uploads via
// os.CreateTemp(".", ...) — CWD-relative. A 2026-09-14-era sweep listed the
// CWD staging as a nit; a later CORRECTION reclassified it not-a-bug on the
// grounds that the layer's readFile confines schema reads to the working
// directory, so CWD staging "is exactly what makes uploads work" — while
// also noting that uploads then fail by design on read-only working
// directories. This round replaced that tradeoff outright: SchemaSource
// gained an inline Content field (parsed directly by LoadSchema, no
// filesystem staging at all), so uploads work regardless of the process CWD
// while config-file-declared schema paths remain confined by readFile's
// working-directory guard.

import (
	"os"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/apivalidation"
)

const avCwdSchemaDoc = `{"openapi":"3.0.0","info":{"title":"av-cwd-probe","version":"1.0"},"paths":{"/av-cwd":{"get":{"responses":{"200":{"description":"ok"}}}}}}`

type avCwdMockEventStore struct{}

func (avCwdMockEventStore) Store(event engine.Event) error { return nil }
func (avCwdMockEventStore) Close() error                   { return nil }

type avCwdMockEventBus struct{}

func (avCwdMockEventBus) Subscribe(ch chan<- engine.Event) {}
func (avCwdMockEventBus) Publish(event engine.Event)       {}
func (avCwdMockEventBus) Close()                           {}

func newAVCwdAdapter(t *testing.T) APIValidationLayerInterface {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.WAF.APIValidation.Enabled = true
	e, err := engine.NewEngine(cfg, avCwdMockEventStore{}, avCwdMockEventBus{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	layer := apivalidation.NewLayer(&apivalidation.Config{Enabled: true})
	e.AddLayer(engine.OrderedLayer{Layer: layer, Order: engine.OrderAPIValidation})

	h := NewAPIValidationHandler(&Dashboard{engine: e})
	adapter := h.getAPIValidationLayer()
	if adapter == nil {
		t.Fatal("api validation layer not resolvable (harness broken)")
	}
	return adapter
}

// TestAPIValidationUploadWorksinReadOnlyCWD: a schema upload must succeed
// with a read-only working directory — inline content is parsed directly and
// touches no filesystem path.
func TestAPIValidationUploadWorksinReadOnlyCWD(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root bypasses directory permission checks")
	}

	adapter := newAVCwdAdapter(t)

	ro := t.TempDir()
	if err := os.Chmod(ro, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Chdir(ro)

	if err := adapter.LoadSchema(&APISchemaInfo{Name: "av-ro-cwd", Content: avCwdSchemaDoc, Format: "openapi"}); err != nil {
		t.Fatalf("FAIL: schema upload failed under a read-only working directory — uploads must be CWD-independent: %v", err)
	}

	// The upload must actually land in the layer (proves the schema parsed
	// and registered, not merely that no error surfaced).
	if adapter.GetSchema("av-ro-cwd") == nil {
		t.Fatalf("upload reported success but the schema is not resolvable via GetSchema")
	}
}

// TestAPIValidationUploadWorksInWritableCWD: control — the same upload in a
// normal writable working directory.
func TestAPIValidationUploadWorksInWritableCWD(t *testing.T) {
	adapter := newAVCwdAdapter(t)
	t.Chdir(t.TempDir())

	if err := adapter.LoadSchema(&APISchemaInfo{Name: "av-writable", Content: avCwdSchemaDoc, Format: "openapi"}); err != nil {
		t.Fatalf("control: LoadSchema failed in a writable CWD: %v", err)
	}
	if adapter.GetSchema("av-writable") == nil {
		t.Fatalf("control: uploaded schema not resolvable via GetSchema")
	}
}

// TestAPIValidationUploadYAMLContent: the inline path keeps the YAML
// detection branch of the loader (content is parsed, not assumed JSON).
func TestAPIValidationUploadYAMLContent(t *testing.T) {
	adapter := newAVCwdAdapter(t)

	yamlDoc := "openapi: 3.0.0\ninfo:\n  title: av-cwd-yaml\n  version: \"1.0\"\npaths:\n  /av-yaml:\n    get:\n      responses:\n        '200':\n          description: ok\n"
	if err := adapter.LoadSchema(&APISchemaInfo{Name: "av-cwd-yaml", Content: yamlDoc, Format: "openapi"}); err != nil {
		t.Fatalf("YAML upload: %v", err)
	}
	if adapter.GetSchema("av-cwd-yaml") == nil {
		t.Fatalf("YAML-uploaded schema not resolvable via GetSchema")
	}
}
