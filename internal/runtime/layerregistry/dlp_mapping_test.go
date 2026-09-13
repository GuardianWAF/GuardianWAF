package layerregistry

import (
	"bytes"
	"mime/multipart"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/layers/dlp"
)

// Regression (buildDLP design-gap round): the DLP file-policy fields and
// custom_patterns existed only on the internal layer struct — config.DLPConfig
// could not express them and buildDLP mapped only seven fields, so serve-mode
// DLP silently ran with file-upload scanning disabled (zero-value bools) and
// no way to configure custom patterns. buildDLP now maps all thirteen fields;
// these tests prove each transports into built-layer behavior.

func buildTestDLPLayer(t *testing.T, mutate func(*config.Config)) *dlp.Layer {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.WAF.DLP.Enabled = true
	cfg.WAF.DLP.ScanFileUploads = true
	cfg.WAF.DLP.MaxFileSize = 1024
	cfg.WAF.DLP.BlockExecutableFiles = false
	cfg.WAF.DLP.BlockDangerousWebExtensions = true
	cfg.WAF.DLP.CustomPatterns = map[string]string{"corp_id": "ACME-[0-9]{5}"}
	if mutate != nil {
		mutate(cfg)
	}
	built, ok, err := BuildLayer("dlp", cfg)
	if err != nil {
		t.Fatalf("BuildLayer(dlp): %v", err)
	}
	if !ok {
		t.Fatal("BuildLayer(dlp): ok=false — the layer was not built despite dlp.enabled")
	}
	layer, isLayer := built.Layer.(*dlp.Layer)
	if !isLayer {
		t.Fatalf("BuildLayer(dlp) returned %T, want *dlp.Layer", built.Layer)
	}
	return layer
}

func multipartUpload(t *testing.T, filename, content string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write([]byte(content)); err != nil {
		t.Fatalf("write part: %v", err)
	}
	ct := w.FormDataContentType()
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	return buf.Bytes(), ct
}

func hasMatch(result *dlp.ScanResult, masked string) bool {
	for _, m := range result.Matches {
		if m.Masked == masked {
			return true
		}
	}
	return false
}

func TestBuildLayerDLPMapsCustomPatterns(t *testing.T) {
	layer := buildTestDLPLayer(t, nil)

	res, masked := layer.ScanResponse([]byte("id=ACME-54321 ok"), "text/plain")
	if res.Safe {
		t.Fatal("FAIL: custom pattern from operator config was not applied by the built layer")
	}
	if strings.Contains(string(masked), "ACME-54321") {
		t.Fatalf("FAIL: masked response still contains the unmasked match: %q", string(masked))
	}
}

func TestBuildLayerDLPMapsFilePolicyFlags(t *testing.T) {
	layer := buildTestDLPLayer(t, nil)

	// BlockExecutableFiles=false: an executable upload must not be flagged by
	// the executable gate (the flag's false must transport).
	body, ct := multipartUpload(t, "tool.sh", "#!/bin/sh\necho hi\n")
	res, err := layer.ScanFileUploads(body, ct)
	if err != nil {
		t.Fatalf("ScanFileUploads(tool.sh): %v", err)
	}
	if hasMatch(res, "[EXECUTABLE_FILE_BLOCKED]") {
		t.Fatal("FAIL: block_executable_files=false still produced an executable-file match — the flag did not transport")
	}

	// BlockDangerousWebExtensions=true: a double-extension upload is blocked.
	body, ct = multipartUpload(t, "shell.php.jpg", "malicious")
	res, err = layer.ScanFileUploads(body, ct)
	if err != nil {
		t.Fatalf("ScanFileUploads(shell.php.jpg): %v", err)
	}
	if res.Safe || !hasMatch(res, "[DANGEROUS_WEB_FILE_BLOCKED]") {
		t.Fatal("FAIL: block_dangerous_web_extensions=true did not block a double-extension upload — the flag did not transport")
	}

	// MaxFileSize: a part larger than max_file_size is flagged, not scanned.
	body, ct = multipartUpload(t, "big.txt", strings.Repeat("A", 2048))
	res, err = layer.ScanFileUploads(body, ct)
	if err != nil {
		t.Fatalf("ScanFileUploads(big.txt): %v", err)
	}
	if res.Safe || !hasMatch(res, "[FILE_TOO_LARGE]") {
		t.Fatal("FAIL: max_file_size=1024 did not flag an oversized part — the value did not transport")
	}
}

func TestBuildLayerDLPScanFileUploadsGateTransports(t *testing.T) {
	layer := buildTestDLPLayer(t, func(c *config.Config) {
		c.WAF.DLP.ScanFileUploads = false
	})

	body, ct := multipartUpload(t, "shell.php.jpg", "malicious")
	res, err := layer.ScanFileUploads(body, ct)
	if err != nil {
		t.Fatalf("ScanFileUploads with scan_file_uploads=false: %v", err)
	}
	if !res.Safe {
		t.Fatal("FAIL: scan_file_uploads=false must skip file scanning entirely")
	}
}
