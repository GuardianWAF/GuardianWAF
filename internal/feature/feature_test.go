package feature

import (
	"testing"
)

func TestSetAndGet(t *testing.T) {
	Reset()
	Set("my_feature", true)
	if !IsEnabled("my_feature") {
		t.Error("expected my_feature to be enabled")
	}
	Set("my_feature", false)
	if IsEnabled("my_feature") {
		t.Error("expected my_feature to be disabled")
	}
}

func TestCaseInsensitive(t *testing.T) {
	Reset()
	Set("New_Detector", true)
	if !IsEnabled("new_detector") {
		t.Error("flag names should be case-insensitive")
	}
	if !IsEnabled("NEW_DETECTOR") {
		t.Error("flag names should be case-insensitive")
	}
}

func TestDefaultFalse(t *testing.T) {
	Reset()
	if IsEnabled("nonexistent") {
		t.Error("unset flags should default to false")
	}
}

func TestTenantOverride(t *testing.T) {
	Reset()
	Set("feature_a", false)
	SetTenant("tenant1", "feature_a", true)

	if !IsEnabledFor("tenant1", "feature_a") {
		t.Error("tenant1 should have feature_a enabled")
	}
	if IsEnabledFor("tenant2", "feature_a") {
		t.Error("tenant2 should inherit global (disabled)")
	}
	if IsEnabled("feature_a") {
		t.Error("global should remain disabled")
	}
}

func TestLoadFromMap(t *testing.T) {
	Reset()
	LoadFromMap(map[string]bool{
		"alpha": true,
		"beta":  false,
	})
	if !IsEnabled("alpha") {
		t.Error("alpha should be enabled")
	}
	if IsEnabled("beta") {
		t.Error("beta should be disabled")
	}
}

func TestAll(t *testing.T) {
	Reset()
	Set("a", true)
	Set("b", false)
	snapshot := All()
	if !snapshot["a"] {
		t.Error("a should be true in snapshot")
	}
	if snapshot["b"] {
		t.Error("b should be false in snapshot")
	}
}

func TestReset(t *testing.T) {
	Set("x", true)
	Reset()
	if IsEnabled("x") {
		t.Error("flags should be cleared after Reset()")
	}
}
