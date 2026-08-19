package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// --- ValidationError formatting ---

func TestValidationError_ErrorFormatting_SingularAndPlural(t *testing.T) {
	ve := &ValidationError{}
	ve.addError("mode", "missing mode")
	msg := ve.Error()
	if !strings.Contains(msg, "1 error") || !strings.Contains(msg, "mode: missing mode") {
		t.Fatalf("singular format wrong: %q", msg)
	}
	ve.addError("listen", "bad port")
	msg2 := ve.Error()
	if !strings.Contains(msg2, "2 errors") {
		t.Fatalf("plural format wrong: %q", msg2)
	}
}

// --- safeConfigEnvName ---

func TestSafeConfigEnvName_Table(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"empty", "", false},
		{"simple", "prod", true},
		{"alphanumeric-hyphen", "staging-1", true},
		{"underscore", "a_b", true},
		{"path traversal", "../prod", false},
		{"slash", "prod/test", false},
		{"space", "prod space", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := safeConfigEnvName(tc.input)
			if got != tc.want {
				t.Errorf("safeConfigEnvName(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// --- cleanConfigPath ---

func TestCleanConfigPath_EmptyCleanAndNUL(t *testing.T) {
	got, err := cleanConfigPath("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "." {
		t.Errorf("got %q, want %q", got, ".")
	}
	got, err = cleanConfigPath("a/../b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "b" {
		t.Errorf("got %q, want %q", got, "b")
	}
	_, err = cleanConfigPath("bad\x00.yaml")
	if err == nil {
		t.Error("expected error for NUL path")
	}
}

// --- hasAllowedConfigExt ---

func TestHasAllowedConfigExt_AllowedAndRejected(t *testing.T) {
	exts := []string{".yaml", ".yml"}
	if !hasAllowedConfigExt("config.yaml", exts) {
		t.Error("expected .yaml to be allowed")
	}
	if !hasAllowedConfigExt("config.yml", exts) {
		t.Error("expected .yml to be allowed")
	}
	if hasAllowedConfigExt("config.txt", exts) {
		t.Error("expected .txt to be rejected")
	}
}

// --- configPathWithinDir ---

func TestConfigPathWithinDir_InsideAndEscape(t *testing.T) {
	dir := "/etc/guardianwaf"
	if !configPathWithinDir(dir, filepath.Join(dir, "rules.d", "custom.yaml")) {
		t.Error("child should be within dir")
	}
	if configPathWithinDir(dir, "/etc/passwd") {
		t.Error("sibling should NOT be within dir")
	}
	if configPathWithinDir(dir, filepath.Join(dir, "..", "other.yaml")) {
		t.Error("parent traversal should NOT be within dir")
	}
}

// --- splitCommaList ---

func TestSplitCommaList_TrimsAndDropsEmpty(t *testing.T) {
	result := splitCommaList("a, b, ,c,, ")
	expected := []string{"a", "b", "c"}
	if len(result) != len(expected) {
		t.Fatalf("got %v, want %v", result, expected)
	}
	for i := range result {
		if result[i] != expected[i] {
			t.Errorf("index %d: got %q, want %q", i, result[i], expected[i])
		}
	}
}

func TestSplitCommaList_Empty(t *testing.T) {
	result := splitCommaList("")
	if len(result) != 0 {
		t.Errorf("expected empty, got %v", result)
	}
}

// --- validateAIAnalysis bounds ---

func TestValidateAIAnalysis_BatchSizeZero(t *testing.T) {
	ve := &ValidationError{}
	ai := &AIAnalysisConfig{Enabled: true, BatchSize: 0}
	validateAIAnalysis(ai, ve)
	if len(ve.Errors) == 0 {
		t.Fatal("expected error for BatchSize=0")
	}
}

func TestValidateAIAnalysis_BatchIntervalZero(t *testing.T) {
	ve := &ValidationError{}
	ai := &AIAnalysisConfig{Enabled: true, BatchSize: 100, BatchInterval: 0}
	validateAIAnalysis(ai, ve)
	if len(ve.Errors) == 0 {
		t.Fatal("expected error for BatchInterval=0")
	}
}

func TestValidateAIAnalysis_MinScoreNegative(t *testing.T) {
	ve := &ValidationError{}
	ai := &AIAnalysisConfig{Enabled: true, BatchSize: 100, BatchInterval: time.Second, MinScore: -1}
	validateAIAnalysis(ai, ve)
	if len(ve.Errors) == 0 {
		t.Fatal("expected error for MinScore=-1")
	}
}

// --- validateRemovedLayers ---

func TestValidateRemovedLayers_DetectsEnabledRemovedLayers(t *testing.T) {
	ve := &ValidationError{}
	cfg := DefaultConfig()
	cfg.WAF.GraphQL = GraphQLConfig{Enabled: true}
	cfg.WAF.GRPC = GRPCConfig{Enabled: true}
	validateRemovedLayers(&cfg.WAF, ve)
	if len(ve.Errors) == 0 {
		t.Fatal("expected errors for enabled removed layers")
	}
}

// --- isValidIPOrCIDR ---

func TestIsValidIPOrCIDR_Table(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"192.168.1.1", true},
		{"::1", true},
		{"10.0.0.0/8", true},
		{"not-an-ip", false},
		{"", false},
		{"256.0.0.1", false},
	}
	for _, tc := range tests {
		got := isValidIPOrCIDR(tc.input)
		if got != tc.want {
			t.Errorf("isValidIPOrCIDR(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// --- isZeroValue ---

func TestIsZeroValue_Table(t *testing.T) {
	tests := []struct {
		name  string
		value reflect.Value
		want  bool
	}{
		{"empty string", reflect.ValueOf(""), true},
		{"non-empty string", reflect.ValueOf("x"), false},
		{"false bool", reflect.ValueOf(false), true},
		{"true bool", reflect.ValueOf(true), false},
		{"zero int", reflect.ValueOf(0), true},
		{"non-zero int", reflect.ValueOf(1), false},
		{"zero float64", reflect.ValueOf(0.0), true},
		{"non-zero float64", reflect.ValueOf(1.0), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isZeroValue(tc.value)
			if got != tc.want {
				t.Errorf("isZeroValue(%v) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// --- writeFileAtomic ---

func TestWriteFileAtomic_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	data := []byte("mode: enforce\n")
	if err := writeFileAtomic(path, data, 0o644); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", string(got), string(data))
	}
}

// --- parseDuration ---

func TestParseDuration_ValidAndInvalid(t *testing.T) {
	d, err := parseDuration("5m")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != 5*time.Minute {
		t.Errorf("got %v, want 5m", d)
	}
	_, err = parseDuration("bad")
	if err == nil {
		t.Fatal("expected error for bad duration")
	}
}

// --- docker validation ---

func TestValidateDocker_LocalSocketRejectsTLSVerify(t *testing.T) {
	ve := &ValidationError{}
	cfg := DefaultConfig()
	cfg.Docker.Enabled = true
	cfg.Docker.SocketPath = "/var/run/docker.sock"
	cfg.Docker.TLSVerify = true
	validateDocker(&cfg.Docker, ve)
	if len(ve.Errors) == 0 {
		t.Fatal("expected error for TLS with local socket")
	}
}
