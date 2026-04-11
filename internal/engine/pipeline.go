package engine

import (
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// timingMapPool reuses map[string]time.Duration across requests.
var timingMapPool = sync.Pool{
	New: func() any {
		return make(map[string]time.Duration, 16)
	},
}

// PipelineResult holds the outcome of running all layers.
type PipelineResult struct {
	Action      Action
	Findings    []Finding
	TotalScore  int
	LayerTiming map[string]time.Duration // layer name -> duration
	Duration    time.Duration            // total pipeline duration
}

// Exclusion defines a path-based detector exclusion.
type Exclusion struct {
	PathPrefix string   // path prefix to match (e.g., "/api/webhook")
	Detectors  []string // detector names to skip (e.g., ["sqli", "xss"])
}

// Pipeline holds an ordered list of layers and executes them sequentially.
type Pipeline struct {
	mu         sync.RWMutex
	layers     []OrderedLayer
	exclusions []Exclusion
}

// NewPipeline creates a pipeline from the given ordered layers.
// Layers are sorted by their Order field.
func NewPipeline(layers ...OrderedLayer) *Pipeline {
	p := &Pipeline{
		layers: make([]OrderedLayer, len(layers)),
	}
	copy(p.layers, layers)
	sort.Slice(p.layers, func(i, j int) bool {
		return p.layers[i].Order < p.layers[j].Order
	})
	return p
}

// SetExclusions sets path-based detector exclusions.
func (p *Pipeline) SetExclusions(exclusions []Exclusion) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.exclusions = exclusions
}

// Execute runs each layer in order against the request context.
// If any layer returns ActionBlock, execution stops immediately.
// Findings and scores are accumulated across all layers.
func (p *Pipeline) Execute(ctx *RequestContext) PipelineResult {
	p.mu.RLock()
	layers := p.layers
	exclusions := p.exclusions
	p.mu.RUnlock()

	start := time.Now()
	timing := timingMapPool.Get().(map[string]time.Duration)
	for k := range timing {
		delete(timing, k)
	}
	result := PipelineResult{
		Action: ActionPass,
	}

	for _, ol := range layers {
		layer := ol.Layer

		// Check if this layer should be skipped due to exclusions
		if shouldSkip(layer, ctx.Path, exclusions) {
			continue
		}

		layerStart := time.Now()
		lr := layer.Process(ctx)
		elapsed := time.Since(layerStart)
		timing[layer.Name()] = elapsed

		// Accumulate findings
		if len(lr.Findings) > 0 {
			result.Findings = append(result.Findings, lr.Findings...)
			ctx.Accumulator.AddMultiple(lr.Findings)
		}

		// Check action
		switch lr.Action {
		case ActionBlock:
			result.Action = ActionBlock
			result.TotalScore = ctx.Accumulator.Total()
			result.Duration = time.Since(start)
			ctx.Action = ActionBlock
			// Copy timing data and return pooled map
			timingCopy := make(map[string]time.Duration, len(timing))
			for k, v := range timing {
				timingCopy[k] = v
			}
			timingMapPool.Put(timing)
			result.LayerTiming = timingCopy
			return result // early return
		case ActionLog:
			if result.Action != ActionBlock {
				result.Action = ActionLog
			}
		case ActionChallenge:
			if result.Action == ActionPass {
				result.Action = ActionChallenge
			}
		}
	}

	result.TotalScore = ctx.Accumulator.Total()
	result.Duration = time.Since(start)
	ctx.Action = result.Action
	// Copy timing data and return pooled map
	timingCopy := make(map[string]time.Duration, len(timing))
	for k, v := range timing {
		timingCopy[k] = v
	}
	timingMapPool.Put(timing)
	result.LayerTiming = timingCopy
	return result
}

// shouldSkip checks if a layer (specifically a Detector) should be skipped
// for the given path based on exclusions.
func shouldSkip(layer Layer, path string, exclusions []Exclusion) bool {
	det, ok := layer.(Detector)
	if !ok {
		return false // non-detector layers are never skipped
	}
	name := det.DetectorName()
	for _, exc := range exclusions {
		if strings.HasPrefix(path, exc.PathPrefix) {
			if slices.Contains(exc.Detectors, name) {
				return true
			}
		}
	}
	return false
}

// AddLayer adds a layer to the pipeline (thread-safe).
func (p *Pipeline) AddLayer(ol OrderedLayer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.layers = append(p.layers, ol)
	sort.Slice(p.layers, func(i, j int) bool {
		return p.layers[i].Order < p.layers[j].Order
	})
}

// Layers returns a copy of the current layer list (thread-safe).
func (p *Pipeline) Layers() []OrderedLayer {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]OrderedLayer, len(p.layers))
	copy(out, p.layers)
	return out
}
