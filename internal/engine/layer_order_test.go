package engine

import "testing"

// Regression (the catalog-closure weak note): OrderCORS and OrderRules were
// BOTH 150, and the pipeline sorts with sort.Slice — an UNSTABLE sort — so
// the runtime CORS-vs-custom-rules order was unspecified per process run,
// while the layerregistry displayed them alphabetically. Distinct values pin
// the documented sandwich: CORS headers, then custom rules, then rate
// limiting.

func TestCORSAndRulesOrdersAreDistinctAndOrdered(t *testing.T) {
	if OrderCORS == OrderRules {
		t.Fatalf("FAIL: OrderCORS and OrderRules are both %d — the unstable pipeline sort makes their runtime order nondeterministic", OrderCORS)
	}
	if !(OrderCORS < OrderRules && OrderRules < OrderRateLimit) {
		t.Fatalf("FAIL: expected OrderCORS (%d) < OrderRules (%d) < OrderRateLimit (%d)", OrderCORS, OrderRules, OrderRateLimit)
	}
}

type orderStubLayer struct {
	name  string
	order int
}

func (o orderStubLayer) Name() string                        { return o.name }
func (o orderStubLayer) Order() int                          { return o.order }
func (o orderStubLayer) Process(*RequestContext) LayerResult { return LayerResult{} }

// The pipeline sort must place cors before custom_rules deterministically —
// the same order the production wiring (cmd/guardianwaf/layers.go) adds them.
func TestPipelineSortDeterministicForCORSPriorToRules(t *testing.T) {
	p := NewPipeline(
		OrderedLayer{Layer: orderStubLayer{name: "custom_rules", order: OrderRules}, Order: OrderRules},
		OrderedLayer{Layer: orderStubLayer{name: "cors", order: OrderCORS}, Order: OrderCORS},
	)
	if p.layers[0].Layer.Name() != "cors" || p.layers[1].Layer.Name() != "custom_rules" {
		t.Fatalf("FAIL: pipeline order = [%s, %s], want [cors, custom_rules]", p.layers[0].Layer.Name(), p.layers[1].Layer.Name())
	}
}
