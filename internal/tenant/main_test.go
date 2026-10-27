package tenant

import (
	"os"
	"testing"
)

// productionAPIKeyHashIterations is apiKeyHashIterations as compiled, before
// TestMain lowers it.
var productionAPIKeyHashIterations = apiKeyHashIterations

// TestMain lowers the PBKDF2 cost for new API-key hashes. At the production
// 600K iterations the package spent ~4 minutes under -race hashing keys; v3
// hashes are self-describing, so lowering the count does not change what the
// tests verify.
func TestMain(m *testing.M) {
	apiKeyHashIterations = 1000
	os.Exit(m.Run())
}

func TestProductionAPIKeyHashIterations(t *testing.T) {
	if productionAPIKeyHashIterations != 600000 {
		t.Fatalf("production PBKDF2 iterations = %d, want 600000 (OWASP 2023+)", productionAPIKeyHashIterations)
	}
}
