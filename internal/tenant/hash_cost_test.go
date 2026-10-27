package tenant

import (
	"strings"
	"testing"
)

// testAPIKeyHashIterations keeps tenant creation cheap in tests. Hashes stay
// self-describing (v3$<iterations>$...), so verification paths are exercised
// exactly as in production.
const testAPIKeyHashIterations = 1000

func init() {
	apiKeyHashIterations = testAPIKeyHashIterations
}

// Guards the production cost: lowering it in tests must never leak into
// the shipped default.
func TestAPIKeyHashProductionCost(t *testing.T) {
	if apiKeyHashIterationsDefault < 600000 {
		t.Fatalf("apiKeyHashIterationsDefault = %d, want >= 600000 (OWASP PBKDF2-HMAC-SHA256)", apiKeyHashIterationsDefault)
	}
	apiKeyHashIterations = apiKeyHashIterationsDefault
	defer func() { apiKeyHashIterations = testAPIKeyHashIterations }()
	hash, err := hashAPIKey("gwaf_production_cost")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "v3$600000$") {
		t.Fatalf("production hash = %q, want a v3$600000$ prefix", hash)
	}
	if ok, legacy := verifyAPIKey(hash, "gwaf_production_cost"); !ok || legacy {
		t.Fatalf("verifyAPIKey(production hash) = %v, %v", ok, legacy)
	}
}
