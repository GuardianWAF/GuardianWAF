package engine

import (
	"sync"
	"testing"
	"time"
)

// --- Mock layers for testing ---

// passLayer always passes with score 0
type passLayer struct{ name string }

func (l *passLayer) Name() string { return l.name }
func (l *passLayer) Process(ctx *RequestContext) LayerResult {
	return LayerResult{Action: ActionPass}
}

// scoreLayer returns configurable findings with a score
type scoreLayer struct {
	name     string
	score    int
	category string
}

func (l *scoreLayer) Name() string { return l.name }
func (l *scoreLayer) Process(ctx *RequestContext) LayerResult {
	return LayerResult{
		Action: ActionLog,
		Findings: []Finding{{
			DetectorName: l.name,
			Category:     l.category,
			Score:        l.score,
			Severity:     SeverityMedium,
			Description:  "test finding",
			Location:     "query",
		}},
		Score: l.score,
	}
}

// blockLayer always blocks
type blockLayer struct{ name string }

func (l *blockLayer) Name() string { return l.name }
func (l *blockLayer) Process(ctx *RequestContext) LayerResult {
	return LayerResult{
		Action: ActionBlock,
		Findings: []Finding{{
			DetectorName: l.name,
			Score:        100,
			Severity:     SeverityCritical,
		}},
		Score: 100,
	}
}

// mockDetector implements Detector interface for exclusion testing
type mockDetector struct {
	name    string
	detName string
	score   int
}

func (d *mockDetector) Name() string         { return d.name }
func (d *mockDetector) DetectorName() string  { return d.detName }
func (d *mockDetector) Patterns() []string    { return nil }
func (d *mockDetector) Process(ctx *RequestContext) LayerResult {
	return LayerResult{
		Action:   ActionLog,
		Findings: []Finding{{DetectorName: d.detName, Score: d.score, Severity: SeverityHigh}},
		Score:    d.score,
	}
}

// slowLayer adds configurable delay
type slowLayer struct {
	name  string
	delay time.Duration
}

func (l *slowLayer) Name() string { return l.name }
func (l *slowLayer) Process(ctx *RequestContext) LayerResult {
	time.Sleep(l.delay)
	return LayerResult{Action: ActionPass}
}

// trackingLayer records whether it was called
type trackingLayer struct {
	name   string
	called bool
}

func (l *trackingLayer) Name() string { return l.name }
func (l *trackingLayer) Process(ctx *RequestContext) LayerResult {
	l.called = true
	return LayerResult{Action: ActionPass}
}

// testContext creates a RequestContext for testing
func testContext() *RequestContext {
	return &RequestContext{
		Path:        "/test",
		Method:      "GET",
		Accumulator: NewScoreAccumulator(2), // paranoia level 2 = 1.0x multiplier
		Metadata:    make(map[string]any),
	}
}

func TestPipeline_SinglePass(t *testing.T) {
	p := NewPipeline(OrderedLayer{
		Layer: &passLayer{name: "pass1"},
		Order: 100,
	})

	ctx := testContext()
	result := p.Execute(ctx)

	if result.Action != ActionPass {
		t.Errorf("expected ActionPass, got %v", result.Action)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
	if result.TotalScore != 0 {
		t.Errorf("expected score 0, got %d", result.TotalScore)
	}
}

func TestPipeline_SingleBlock(t *testing.T) {
	p := NewPipeline(OrderedLayer{
		Layer: &blockLayer{name: "blocker"},
		Order: 100,
	})

	ctx := testContext()
	result := p.Execute(ctx)

	if result.Action != ActionBlock {
		t.Errorf("expected ActionBlock, got %v", result.Action)
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.TotalScore != 100 {
		t.Errorf("expected score 100, got %d", result.TotalScore)
	}
}

func TestPipeline_ScoreAccumulation(t *testing.T) {
	p := NewPipeline(
		OrderedLayer{Layer: &scoreLayer{name: "sqli", score: 30, category: "sqli"}, Order: 100},
		OrderedLayer{Layer: &scoreLayer{name: "xss", score: 20, category: "xss"}, Order: 200},
		OrderedLayer{Layer: &scoreLayer{name: "lfi", score: 15, category: "lfi"}, Order: 300},
	)

	ctx := testContext() // multiplier 1.0x
	result := p.Execute(ctx)

	expectedScore := 30 + 20 + 15 // = 65
	if result.TotalScore != expectedScore {
		t.Errorf("expected score %d, got %d", expectedScore, result.TotalScore)
	}
	if len(result.Findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(result.Findings))
	}
	if result.Action != ActionLog {
		t.Errorf("expected ActionLog, got %v", result.Action)
	}
}

func TestPipeline_EarlyReturnOnBlock(t *testing.T) {
	tracker := &trackingLayer{name: "after-block"}
	p := NewPipeline(
		OrderedLayer{Layer: &passLayer{name: "first"}, Order: 100},
		OrderedLayer{Layer: &blockLayer{name: "blocker"}, Order: 200},
		OrderedLayer{Layer: tracker, Order: 300},
	)

	ctx := testContext()
	result := p.Execute(ctx)

	if result.Action != ActionBlock {
		t.Errorf("expected ActionBlock, got %v", result.Action)
	}
	if tracker.called {
		t.Error("layer after block should not have been called")
	}
	// Should have timing for first two layers, but not the third
	if _, ok := result.LayerTiming["first"]; !ok {
		t.Error("expected timing for 'first' layer")
	}
	if _, ok := result.LayerTiming["blocker"]; !ok {
		t.Error("expected timing for 'blocker' layer")
	}
	if _, ok := result.LayerTiming["after-block"]; ok {
		t.Error("should not have timing for 'after-block' layer")
	}
}

func TestPipeline_LayerOrdering(t *testing.T) {
	// Create pipeline with layers in reverse order of their Order field
	p := NewPipeline(
		OrderedLayer{Layer: &passLayer{name: "third"}, Order: 300},
		OrderedLayer{Layer: &passLayer{name: "first"}, Order: 100},
		OrderedLayer{Layer: &passLayer{name: "second"}, Order: 200},
	)

	// Verify Layers() returns them sorted by Order
	layers := p.Layers()
	if len(layers) != 3 {
		t.Fatalf("expected 3 layers, got %d", len(layers))
	}
	if layers[0].Order != 100 {
		t.Errorf("first layer order should be 100, got %d", layers[0].Order)
	}
	if layers[1].Order != 200 {
		t.Errorf("second layer order should be 200, got %d", layers[1].Order)
	}
	if layers[2].Order != 300 {
		t.Errorf("third layer order should be 300, got %d", layers[2].Order)
	}
	if layers[0].Layer.Name() != "first" {
		t.Errorf("first layer should be 'first', got %q", layers[0].Layer.Name())
	}
	if layers[1].Layer.Name() != "second" {
		t.Errorf("second layer should be 'second', got %q", layers[1].Layer.Name())
	}
	if layers[2].Layer.Name() != "third" {
		t.Errorf("third layer should be 'third', got %q", layers[2].Layer.Name())
	}
}

func TestPipeline_Exclusions(t *testing.T) {
	sqli := &mockDetector{name: "sqli-layer", detName: "sqli", score: 50}
	xss := &mockDetector{name: "xss-layer", detName: "xss", score: 40}

	p := NewPipeline(
		OrderedLayer{Layer: sqli, Order: 100},
		OrderedLayer{Layer: xss, Order: 200},
	)

	// Exclude sqli for /api/webhook paths
	p.SetExclusions([]Exclusion{
		{PathPrefix: "/api/webhook", Detectors: []string{"sqli"}},
	})

	// Test with matching path - sqli should be skipped
	ctx := testContext()
	ctx.Path = "/api/webhook/stripe"
	result := p.Execute(ctx)

	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding (only xss), got %d", len(result.Findings))
	}
	if len(result.Findings) == 1 && result.Findings[0].DetectorName != "xss" {
		t.Errorf("expected xss finding, got %q", result.Findings[0].DetectorName)
	}
	if result.TotalScore != 40 {
		t.Errorf("expected score 40 (only xss), got %d", result.TotalScore)
	}

	// Test with non-matching path - both should run
	ctx2 := testContext()
	ctx2.Path = "/other/path"
	result2 := p.Execute(ctx2)

	if len(result2.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result2.Findings))
	}
	if result2.TotalScore != 90 {
		t.Errorf("expected score 90, got %d", result2.TotalScore)
	}
}

func TestPipeline_LayerTiming(t *testing.T) {
	p := NewPipeline(
		OrderedLayer{Layer: &slowLayer{name: "slow1", delay: 10 * time.Millisecond}, Order: 100},
		OrderedLayer{Layer: &passLayer{name: "fast1"}, Order: 200},
	)

	ctx := testContext()
	result := p.Execute(ctx)

	slow1Time, ok := result.LayerTiming["slow1"]
	if !ok {
		t.Fatal("missing timing for 'slow1'")
	}
	if slow1Time < 10*time.Millisecond {
		t.Errorf("slow1 timing too short: %v", slow1Time)
	}

	fast1Time, ok := result.LayerTiming["fast1"]
	if !ok {
		t.Fatal("missing timing for 'fast1'")
	}
	if fast1Time > 5*time.Millisecond {
		t.Errorf("fast1 timing unexpectedly long: %v", fast1Time)
	}
}

func TestPipeline_TotalDuration(t *testing.T) {
	p := NewPipeline(
		OrderedLayer{Layer: &slowLayer{name: "s1", delay: 10 * time.Millisecond}, Order: 100},
		OrderedLayer{Layer: &slowLayer{name: "s2", delay: 10 * time.Millisecond}, Order: 200},
	)

	ctx := testContext()
	result := p.Execute(ctx)

	if result.Duration < 20*time.Millisecond {
		t.Errorf("total duration %v should be >= 20ms (sum of layer delays)", result.Duration)
	}

	// Total duration should be >= sum of individual layer timings
	var sumLayerTimes time.Duration
	for _, d := range result.LayerTiming {
		sumLayerTimes += d
	}
	if result.Duration < sumLayerTimes {
		t.Errorf("total duration %v should be >= sum of layer timings %v", result.Duration, sumLayerTimes)
	}
}

func TestPipeline_EmptyPipeline(t *testing.T) {
	p := NewPipeline()

	ctx := testContext()
	result := p.Execute(ctx)

	if result.Action != ActionPass {
		t.Errorf("expected ActionPass for empty pipeline, got %v", result.Action)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
	if result.TotalScore != 0 {
		t.Errorf("expected score 0, got %d", result.TotalScore)
	}
	if result.Duration < 0 {
		t.Error("duration should not be negative")
	}
}

func TestPipeline_ConcurrentExecution(t *testing.T) {
	p := NewPipeline(
		OrderedLayer{Layer: &scoreLayer{name: "sqli", score: 25, category: "sqli"}, Order: 100},
		OrderedLayer{Layer: &passLayer{name: "sanitizer"}, Order: 200},
		OrderedLayer{Layer: &scoreLayer{name: "xss", score: 15, category: "xss"}, Order: 300},
	)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errors := make(chan string, goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			ctx := testContext()
			result := p.Execute(ctx)

			if result.Action != ActionLog {
				errors <- "expected ActionLog"
				return
			}
			if result.TotalScore != 40 {
				errors <- "expected score 40"
				return
			}
			if len(result.Findings) != 2 {
				errors <- "expected 2 findings"
				return
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

func TestPipeline_AddLayer(t *testing.T) {
	p := NewPipeline(
		OrderedLayer{Layer: &passLayer{name: "first"}, Order: 100},
	)

	// Verify initial state
	if len(p.Layers()) != 1 {
		t.Fatalf("expected 1 layer, got %d", len(p.Layers()))
	}

	// Add a new layer
	p.AddLayer(OrderedLayer{Layer: &scoreLayer{name: "added", score: 50, category: "test"}, Order: 200})

	// Verify layer was added
	layers := p.Layers()
	if len(layers) != 2 {
		t.Fatalf("expected 2 layers, got %d", len(layers))
	}
	if layers[1].Layer.Name() != "added" {
		t.Errorf("second layer should be 'added', got %q", layers[1].Layer.Name())
	}

	// Verify added layer participates in execution
	ctx := testContext()
	result := p.Execute(ctx)
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding from added layer, got %d", len(result.Findings))
	}
	if result.TotalScore != 50 {
		t.Errorf("expected score 50, got %d", result.TotalScore)
	}
}

func TestPipeline_ContextActionUpdated(t *testing.T) {
	// Test ActionPass
	t.Run("pass", func(t *testing.T) {
		p := NewPipeline(
			OrderedLayer{Layer: &passLayer{name: "p"}, Order: 100},
		)
		ctx := testContext()
		p.Execute(ctx)
		if ctx.Action != ActionPass {
			t.Errorf("expected ctx.Action=ActionPass, got %v", ctx.Action)
		}
	})

	// Test ActionBlock
	t.Run("block", func(t *testing.T) {
		p := NewPipeline(
			OrderedLayer{Layer: &blockLayer{name: "b"}, Order: 100},
		)
		ctx := testContext()
		p.Execute(ctx)
		if ctx.Action != ActionBlock {
			t.Errorf("expected ctx.Action=ActionBlock, got %v", ctx.Action)
		}
	})

	// Test ActionLog
	t.Run("log", func(t *testing.T) {
		p := NewPipeline(
			OrderedLayer{Layer: &scoreLayer{name: "s", score: 10, category: "test"}, Order: 100},
		)
		ctx := testContext()
		p.Execute(ctx)
		if ctx.Action != ActionLog {
			t.Errorf("expected ctx.Action=ActionLog, got %v", ctx.Action)
		}
	})

	// Test ActionChallenge
	t.Run("challenge", func(t *testing.T) {
		challengeLayer := &challengeMockLayer{name: "chal"}
		p := NewPipeline(
			OrderedLayer{Layer: challengeLayer, Order: 100},
		)
		ctx := testContext()
		p.Execute(ctx)
		if ctx.Action != ActionChallenge {
			t.Errorf("expected ctx.Action=ActionChallenge, got %v", ctx.Action)
		}
	})
}

// challengeMockLayer returns ActionChallenge
type challengeMockLayer struct{ name string }

func (l *challengeMockLayer) Name() string { return l.name }
func (l *challengeMockLayer) Process(ctx *RequestContext) LayerResult {
	return LayerResult{Action: ActionChallenge}
}
