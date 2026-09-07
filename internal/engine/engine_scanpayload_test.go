package engine

import (
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

// scanPayloadTestLayer is a minimal detector-style layer: it reports a
// finding (through ctx.Accumulator, like real detectors) when the scanned
// payload contains "evil". In-package on purpose — importing detector
// packages from engine tests creates import cycles.
type scanPayloadTestLayer struct{}

func (scanPayloadTestLayer) Name() string { return "scan-test" }
func (scanPayloadTestLayer) Order() int   { return 400 }
func (scanPayloadTestLayer) Process(ctx *RequestContext) LayerResult {
	if strings.Contains(ctx.BodyString, "evil") {
		f := Finding{DetectorName: "scan-test", Score: 90}
		ctx.Accumulator.Add(&f)
		return LayerResult{Action: ActionLog, Findings: []Finding{f}, Score: 90}
	}
	return LayerResult{Action: ActionPass}
}

// newScanPayloadEngine builds a minimal engine with the test layer, mirroring
// the serve-mode pipeline that websocket_runtime.go scans frames through.
// Uses the package's mock event store/bus (importing internal/events here
// would create an import cycle in the in-package test).
func newScanPayloadEngine(t *testing.T) *Engine {
	t.Helper()
	cfg := &config.Config{}
	cfg.WAF.Detection.Threshold.Block = 50
	cfg.WAF.Detection.Threshold.Log = 25
	e, err := NewEngine(cfg, newMockEventStore(), newMockEventBus())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	e.AddLayer(OrderedLayer{Layer: scanPayloadTestLayer{}, Order: 400})
	return e
}

// TestScanPayload_FlagsAndBlocksMaliciousFrame pins the ScanPayload contract:
// a WebSocket frame scanned through the production path
// (websocket_runtime.go injects Engine.ScanPayload as the websocket layer's
// CheckPayload) must be flagged and blocked. ScanPayload previously built its
// RequestContext without a ScoreAccumulator, so pipeline.Execute's
// unconditional ctx.Accumulator dereference panicked on EVERY call.
func TestScanPayload_FlagsAndBlocksMaliciousFrame(t *testing.T) {
	e := newScanPayloadEngine(t)

	score, block := e.ScanPayload("203.0.113.7", "/ws", "evil payload")
	if !block {
		t.Fatalf("malicious frame not blocked (score=%d)", score)
	}
	if score <= 0 {
		t.Fatalf("malicious frame score = %d; want > 0", score)
	}
}

// TestScanPayload_BenignFrameScansClean covers the secondary branch: a benign
// frame must scan clean (pass) without panicking.
func TestScanPayload_BenignFrameScansClean(t *testing.T) {
	e := newScanPayloadEngine(t)

	score, block := e.ScanPayload("203.0.113.7", "/ws", "hello world")
	if block {
		t.Fatalf("benign frame blocked (score=%d)", score)
	}
	if score != 0 {
		t.Fatalf("benign frame score = %d; want 0", score)
	}
}

// TestScanPayload_EmptyPayload covers the degenerate boundary: an empty frame
// must scan clean without panicking.
func TestScanPayload_EmptyPayload(t *testing.T) {
	e := newScanPayloadEngine(t)

	if _, block := e.ScanPayload("203.0.113.7", "/ws", ""); block {
		t.Fatal("empty frame blocked")
	}
}
