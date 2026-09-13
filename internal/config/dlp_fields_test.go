package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression (buildDLP design-gap round): the DLP file-policy fields and
// custom_patterns existed only on the internal layer struct — config.DLPConfig
// could not express them and buildDLP could not map them, so serve-mode DLP
// silently ran without file-upload scanning and with no way to configure
// custom patterns. These tests pin the config surface, the YAML overlay, and
// the defensive copy.

func TestDefaultConfigDLPFilePolicy(t *testing.T) {
	cfg := DefaultConfig()
	d := cfg.WAF.DLP
	if !d.ScanFileUploads {
		t.Error("scan_file_uploads: got false, want true (library default)")
	}
	if !d.BlockExecutableFiles {
		t.Error("block_executable_files: got false, want true (library default)")
	}
	if d.BlockArchiveFiles {
		t.Error("block_archive_files: got true, want false (library default)")
	}
	if !d.BlockDangerousWebExtensions {
		t.Error("block_dangerous_web_extensions: got false, want true (library default)")
	}
	if d.MaxFileSize != 10<<20 {
		t.Errorf("max_file_size: got %d, want %d", d.MaxFileSize, 10<<20)
	}
	if d.CustomPatterns == nil || len(d.CustomPatterns) != 0 {
		t.Errorf("custom_patterns: got %v, want non-nil empty map", d.CustomPatterns)
	}
}

func TestDLPConfigYAMLOverlay(t *testing.T) {
	yamlDoc := `
mode: enforce
waf:
  dlp:
    enabled: true
    scan_file_uploads: false
    max_file_size: 2048
    custom_patterns:
      corp_id: "ACME-[0-9]{5}"
`
	node, err := Parse([]byte(yamlDoc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg := DefaultConfig()
	if err := PopulateFromNode(cfg, node); err != nil {
		t.Fatalf("PopulateFromNode: %v", err)
	}

	d := cfg.WAF.DLP
	// Present keys override the preset.
	if !d.Enabled {
		t.Error("enabled: got false, want true — a present key must override the preset")
	}
	if d.ScanFileUploads {
		t.Error("scan_file_uploads: got true, want false — a present key must override the preset")
	}
	if d.MaxFileSize != 2048 {
		t.Errorf("max_file_size: got %d, want 2048", d.MaxFileSize)
	}
	if got := d.CustomPatterns["corp_id"]; got != "ACME-[0-9]{5}" {
		t.Errorf("custom_patterns[corp_id]: got %q, want %q", got, "ACME-[0-9]{5}")
	}
	// Absent keys keep the preset.
	if !d.ScanRequest {
		t.Error("scan_request: absent key must keep the preset value true")
	}
	if !d.BlockExecutableFiles {
		t.Error("block_executable_files: absent key must keep the preset value true")
	}
	if !d.MaskResponse {
		t.Error("mask_response: absent key must keep the preset value true")
	}
	if d.MaxBodySize != 1024*1024 {
		t.Errorf("max_body_size: got %d, want the preset %d", d.MaxBodySize, 1024*1024)
	}
}

func TestDLPConfigDeepCopyIndependence(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WAF.DLP.CustomPatterns["k"] = "v"
	clone := cfg.WAF.DLP.DeepCopy()

	clone.CustomPatterns["k"] = "mutated"
	if cfg.WAF.DLP.CustomPatterns["k"] != "v" {
		t.Fatal("DeepCopy aliases CustomPatterns — mutating the clone changed the original")
	}
	clone.MaxFileSize = 5
	if cfg.WAF.DLP.MaxFileSize == 5 {
		t.Fatal("DeepCopy aliases MaxFileSize — mutating the clone changed the original")
	}
}

// End-to-end: the new DLP keys must survive the real LoadFile pipeline
// (Parse → validateKnownConfigKeys → DefaultConfig → PopulateFromNode), not
// just the Parse+PopulateFromNode pair.
func TestLoadFileDLPFilePolicyEndToEnd(t *testing.T) {
	yamlDoc := `
mode: enforce
waf:
  dlp:
    enabled: true
    scan_file_uploads: false
    max_file_size: 2048
    custom_patterns:
      corp_id: "ACME-[0-9]{5}"
`
	path := filepath.Join(t.TempDir(), "gwaf.yaml")
	if err := os.WriteFile(path, []byte(yamlDoc), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	cfg, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	d := cfg.WAF.DLP
	if !d.Enabled {
		t.Error("enabled: got false, want true")
	}
	if d.ScanFileUploads {
		t.Error("scan_file_uploads: got true, want false")
	}
	if d.MaxFileSize != 2048 {
		t.Errorf("max_file_size: got %d, want 2048", d.MaxFileSize)
	}
	if got := d.CustomPatterns["corp_id"]; got != "ACME-[0-9]{5}" {
		t.Errorf("custom_patterns[corp_id]: got %q, want %q", got, "ACME-[0-9]{5}")
	}
	// Absent keys keep the preset through the full LoadFile pipeline.
	if !d.ScanRequest {
		t.Error("scan_request: absent key must keep the preset value true")
	}
	if !d.BlockExecutableFiles {
		t.Error("block_executable_files: absent key must keep the preset value true")
	}
	if !d.MaskResponse {
		t.Error("mask_response: absent key must keep the preset value true")
	}
	if d.MaxBodySize != 1024*1024 {
		t.Errorf("max_body_size: got %d, want the preset %d", d.MaxBodySize, 1024*1024)
	}
}

// The schema-derived strict-key gate must stay strict at the dlp level: the
// new keys are known, an unknown sibling is still rejected.
func TestLoadFileRejectsUnknownDLPKey(t *testing.T) {
	yamlDoc := `
waf:
  dlp:
    enabled: true
    bogus_unknown_key: 1
`
	path := filepath.Join(t.TempDir(), "gwaf.yaml")
	if err := os.WriteFile(path, []byte(yamlDoc), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("FAIL: LoadFile accepted an unknown dlp key — the schema-derived strict-key gate did not fire")
	}
	if !strings.Contains(err.Error(), "bogus_unknown_key") {
		t.Fatalf("FAIL: LoadFile error %q does not name the unknown key", err)
	}
}
