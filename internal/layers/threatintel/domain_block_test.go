package threatintel

import (
	"net"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression tests: DomainRep.BlockMalicious must actually block. The domain
// path used to append a "Domain flagged" finding but always returned
// ActionPass — unlike its IP twin in the same Process function, which returns
// ActionBlock — so the BlockMalicious knob silently did nothing for domains.

func TestDomainBlockMaliciousBlocks(t *testing.T) {
	cfg := Config{
		Enabled: true,
		DomainRep: DomainRepConfig{
			Enabled:        true,
			BlockMalicious: true,
		},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	layer.AddDomain("evil.example", &ThreatInfo{Score: 100, Type: "malware_c2", Source: "test"})

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("192.0.2.55"),
		Headers:  map[string][]string{"Host": {"evil.example"}},
	}
	result := layer.Process(ctx)

	if result.Action != engine.ActionBlock {
		t.Fatalf("FAIL: DomainRep.BlockMalicious=true did not block a listed domain (score 100): action = %v", result.Action)
	}
	if len(result.Findings) == 0 {
		t.Fatal("FAIL: blocked domain produced no findings")
	}
}

// Control: the IP path — the documented pattern in the same function — blocks
// under the equivalent configuration. Pre-fix this already passes.
func TestIPBlockMaliciousControl(t *testing.T) {
	cfg := Config{
		Enabled: true,
		IPReputation: IPRepConfig{
			Enabled:        true,
			BlockMalicious: true,
			ScoreThreshold: 50,
		},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	layer.AddIP("192.0.2.99", &ThreatInfo{Score: 100, Type: "malware_c2", Source: "test"})

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("192.0.2.99"),
		Headers:  map[string][]string{"Host": {"benign.example"}},
	}
	result := layer.Process(ctx)

	if result.Action != engine.ActionBlock {
		t.Fatalf("FAIL: IP control setup broken — BlockMalicious IP did not block (action = %v)", result.Action)
	}
}

// Boundary: log-only mode (BlockMalicious=false) must keep passing traffic
// while still reporting the flagged domain.
func TestDomainLogOnlyModeStillPasses(t *testing.T) {
	cfg := Config{
		Enabled: true,
		DomainRep: DomainRepConfig{
			Enabled:        true,
			BlockMalicious: false,
		},
	}
	layer, err := NewLayer(&cfg)
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}
	layer.AddDomain("susp.example", &ThreatInfo{Score: 100, Type: "phishing", Source: "test"})

	ctx := &engine.RequestContext{
		ClientIP: net.ParseIP("192.0.2.55"),
		Headers:  map[string][]string{"Host": {"susp.example"}},
	}
	result := layer.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Fatalf("FAIL: log-only domain mode blocked traffic: %v", result.Action)
	}
	if len(result.Findings) == 0 {
		t.Fatal("FAIL: log-only domain mode produced no findings")
	}
}
