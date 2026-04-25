package feature

import (
	"os"
	"testing"
)

func TestLoadFromEnv_Basic(t *testing.T) {
	Reset()

	// Set environment variables before calling LoadFromEnv
	os.Setenv("GWAF_FEATURE_TEST_ALPHA", "true")
	os.Setenv("GWAF_FEATURE_TEST_BETA", "false")
	os.Setenv("GWAF_FEATURE_TEST_GAMMA", "1")
	os.Setenv("GWAF_FEATURE_TEST_DELTA", "yes")
	os.Setenv("GWAF_FEATURE_TEST_EPSILON", "no")
	os.Setenv("GWAF_FEATURE_TEST_ZETA", "0")
	os.Setenv("SOME_OTHER_VAR", "true") // should be ignored
	defer func() {
		os.Unsetenv("GWAF_FEATURE_TEST_ALPHA")
		os.Unsetenv("GWAF_FEATURE_TEST_BETA")
		os.Unsetenv("GWAF_FEATURE_TEST_GAMMA")
		os.Unsetenv("GWAF_FEATURE_TEST_DELTA")
		os.Unsetenv("GWAF_FEATURE_TEST_EPSILON")
		os.Unsetenv("GWAF_FEATURE_TEST_ZETA")
		os.Unsetenv("SOME_OTHER_VAR")
	}()

	LoadFromEnv()

	if !IsEnabled("test_alpha") {
		t.Error("expected test_alpha to be enabled via env")
	}
	if IsEnabled("test_beta") {
		t.Error("expected test_beta to be disabled via env")
	}
	if !IsEnabled("test_gamma") {
		t.Error("expected test_gamma to be enabled (value '1')")
	}
	if !IsEnabled("test_delta") {
		t.Error("expected test_delta to be enabled (value 'yes')")
	}
	if IsEnabled("test_epsilon") {
		t.Error("expected test_epsilon to be disabled (value 'no')")
	}
	if IsEnabled("test_zeta") {
		t.Error("expected test_zeta to be disabled (value '0')")
	}
	if IsEnabled("some_other_var") {
		t.Error("expected non-prefixed env var to be ignored")
	}
}

func TestLoadFromEnv_CaseInsensitive(t *testing.T) {
	Reset()

	os.Setenv("GWAF_FEATURE_MY_FLAG", "true")
	defer os.Unsetenv("GWAF_FEATURE_MY_FLAG")

	LoadFromEnv()

	// The env key GWAF_FEATURE_MY_FLAG should produce "my_flag" (lowercased)
	if !IsEnabled("my_flag") {
		t.Error("expected my_flag to be enabled")
	}
	if !IsEnabled("MY_FLAG") {
		t.Error("expected MY_FLAG lookup to also work (case-insensitive)")
	}
}

func TestLoadFromEnv_NoMatchingEnvVars(t *testing.T) {
	Reset()

	// Should not panic or modify anything when no GWAF_FEATURE_ vars exist
	LoadFromEnv()

	if IsEnabled("anything") {
		t.Error("expected no flags to be set")
	}
}

func TestLoadFromEnv_OverwriteExisting(t *testing.T) {
	Reset()

	Set("myfeature", false)
	if IsEnabled("myfeature") {
		t.Error("expected myfeature to be disabled initially")
	}

	os.Setenv("GWAF_FEATURE_MYFEATURE", "true")
	defer os.Unsetenv("GWAF_FEATURE_MYFEATURE")

	LoadFromEnv()

	if !IsEnabled("myfeature") {
		t.Error("expected LoadFromEnv to overwrite existing flag")
	}
}

func TestLoadFromEnv_EmptyValue(t *testing.T) {
	Reset()

	os.Setenv("GWAF_FEATURE_EMPTY_VAL", "")
	defer os.Unsetenv("GWAF_FEATURE_EMPTY_VAL")

	LoadFromEnv()

	// Empty value should not enable the flag
	if IsEnabled("empty_val") {
		t.Error("expected empty value to not enable the flag")
	}
}

func TestLoadFromEnv_EqualsSignInValue(t *testing.T) {
	Reset()

	os.Setenv("GWAF_FEATURE_KV_TEST", "true")
	defer os.Unsetenv("GWAF_FEATURE_KV_TEST")

	LoadFromEnv()

	if !IsEnabled("kv_test") {
		t.Error("expected kv_test to be enabled")
	}
}

func TestSetTenant_MultipleTenantsIsolation(t *testing.T) {
	Reset()

	Set("shared_feature", true)
	SetTenant("tenant_a", "shared_feature", false)
	SetTenant("tenant_b", "shared_feature", true)
	SetTenant("tenant_a", "extra_a", true)
	SetTenant("tenant_b", "extra_b", false)

	// tenant_a: shared overridden to false, extra_a=true
	if IsEnabledFor("tenant_a", "shared_feature") {
		t.Error("tenant_a should have shared_feature disabled")
	}
	if !IsEnabledFor("tenant_a", "extra_a") {
		t.Error("tenant_a should have extra_a enabled")
	}

	// tenant_b: shared overridden to true, extra_b=false
	if !IsEnabledFor("tenant_b", "shared_feature") {
		t.Error("tenant_b should have shared_feature enabled")
	}
	if IsEnabledFor("tenant_b", "extra_b") {
		t.Error("tenant_b should have extra_b disabled")
	}

	// Global should still be true
	if !IsEnabled("shared_feature") {
		t.Error("global shared_feature should still be true")
	}

	// Unknown tenant should fall back to global
	if !IsEnabledFor("unknown_tenant", "shared_feature") {
		t.Error("unknown tenant should get global value")
	}
}

func TestSetTenant_EmptyTenantID(t *testing.T) {
	Reset()

	SetTenant("", "myfeature", true)

	// Empty tenant ID should not crash, and the lookup with empty string
	// should use tenant override
	if !IsEnabledFor("", "myfeature") {
		t.Error("empty tenant lookup should find the override")
	}

	// Global should not be affected
	if IsEnabled("myfeature") {
		t.Error("global should not be set by SetTenant with empty ID")
	}
}

func TestLoadFromMap_EmptyMap(t *testing.T) {
	Reset()
	Set("existing", true)

	LoadFromMap(map[string]bool{})

	// Existing flags should not be cleared by loading empty map
	if !IsEnabled("existing") {
		t.Error("existing flags should remain after loading empty map")
	}
}

func TestLoadFromMap_Overwrites(t *testing.T) {
	Reset()

	Set("flag_a", false)
	Set("flag_b", true)

	LoadFromMap(map[string]bool{
		"flag_a": true,
		"flag_b": false,
	})

	if !IsEnabled("flag_a") {
		t.Error("flag_a should be overwritten to true")
	}
	if IsEnabled("flag_b") {
		t.Error("flag_b should be overwritten to false")
	}
}

func TestAll_ModifySnapshotDoesNotAffectGlobal(t *testing.T) {
	Reset()
	Set("protected", true)

	snapshot := All()
	snapshot["protected"] = false

	// Modifying the snapshot should not affect the global state
	if !IsEnabled("protected") {
		t.Error("modifying snapshot should not affect global flags")
	}
}

func TestAll_EmptyAfterReset(t *testing.T) {
	Reset()
	Set("temp", true)
	Reset()

	snapshot := All()
	if len(snapshot) != 0 {
		t.Errorf("expected empty snapshot after Reset, got %d entries", len(snapshot))
	}
}

func TestSetTenant_CaseInsensitiveName(t *testing.T) {
	Reset()

	SetTenant("t1", "MyFeature", true)

	if !IsEnabledFor("t1", "myfeature") {
		t.Error("SetTenant name should be case-insensitive")
	}
	if !IsEnabledFor("t1", "MYFEATURE") {
		t.Error("IsEnabledFor name should be case-insensitive")
	}
}

func TestIsEnabledFor_TenantExistsButFlagDoesNot(t *testing.T) {
	Reset()

	SetTenant("t1", "feature_x", true)

	// A flag not set for the tenant should fall back to global
	if IsEnabledFor("t1", "nonexistent_flag") {
		t.Error("unset flag for tenant should fall back to global (false)")
	}

	Set("nonexistent_flag", true)
	if !IsEnabledFor("t1", "nonexistent_flag") {
		t.Error("unset flag for tenant should fall back to global (true)")
	}
}

func TestIsEnabledFor_TenantOnlyFlag(t *testing.T) {
	Reset()

	// A flag set only for a tenant, not globally
	SetTenant("t1", "tenant_only", true)

	if IsEnabled("tenant_only") {
		t.Error("global should not have tenant_only set")
	}
	if !IsEnabledFor("t1", "tenant_only") {
		t.Error("tenant t1 should have tenant_only enabled")
	}
	if IsEnabledFor("t2", "tenant_only") {
		t.Error("tenant t2 should not have tenant_only set")
	}
}

func TestReset_ClearsTenants(t *testing.T) {
	Reset()

	SetTenant("t1", "f1", true)
	SetTenant("t2", "f2", true)

	Reset()

	if IsEnabledFor("t1", "f1") {
		t.Error("tenant flags should be cleared after Reset")
	}
	if IsEnabledFor("t2", "f2") {
		t.Error("tenant flags should be cleared after Reset")
	}
}

func TestLoadFromEnv_WithEqualsInValue(t *testing.T) {
	Reset()

	// Environment variables may contain = signs in value
	os.Setenv("GWAF_FEATURE_COMPLEX", "true")
	defer os.Unsetenv("GWAF_FEATURE_COMPLEX")

	LoadFromEnv()

	if !IsEnabled("complex") {
		t.Error("expected complex to be enabled")
	}
}
