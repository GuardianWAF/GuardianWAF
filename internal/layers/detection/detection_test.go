package detection

import (
	"bufio"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func defaultConfig() *Config {
	return &Config{
		Enabled: true,
		Detectors: map[string]DetectorConfig{
			"sqli": {Enabled: true, Multiplier: 1.0},
			"xss":  {Enabled: true, Multiplier: 1.0},
			"lfi":  {Enabled: true, Multiplier: 1.0},
			"cmdi": {Enabled: true, Multiplier: 1.0},
			"xxe":  {Enabled: true, Multiplier: 1.0},
			"ssrf": {Enabled: true, Multiplier: 1.0},
			"ssti": {Enabled: true, Multiplier: 1.0},
			"nosqli": {
				Enabled:    true,
				Multiplier: 1.0,
			},
			"smuggling":    {Enabled: true, Multiplier: 1.0},
			"openredirect": {Enabled: true, Multiplier: 1.0},
			"graphql":      {Enabled: true, Multiplier: 1.0},
		},
		GraphQLMaxDepth:           10,
		GraphQLMaxComplexity:      1000,
		GraphQLBlockIntrospection: true,
	}
}

func makeContext(path, query, body, contentType string) *engine.RequestContext {
	url := path
	if query != "" {
		url += "?" + query
	}
	r := httptest.NewRequest("GET", url, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	ctx := engine.AcquireContext(r, 2, 1024*1024)
	// Normalize (simulating sanitizer layer having run):
	ctx.NormalizedPath = strings.ToLower(ctx.Path)
	ctx.NormalizedQuery = ctx.QueryParams
	ctx.NormalizedBody = body
	return ctx
}

// 1. TestDetectionLayer_Disabled - layer disabled returns ActionPass, no findings
func TestDetectionLayer_Disabled(t *testing.T) {
	cfg := defaultConfig()
	cfg.Enabled = false
	layer := NewLayer(cfg)

	ctx := makeContext("/search", "q='+OR+1=1--", "", "")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected ActionPass when layer disabled, got %v", result.Action)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings when layer disabled, got %d", len(result.Findings))
	}
}

// 2. TestDetectionLayer_CleanRequest - clean request produces no findings
func TestDetectionLayer_CleanRequest(t *testing.T) {
	layer := NewLayer(defaultConfig())

	ctx := makeContext("/products", "page=1&limit=10", "", "")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for clean request, got %d", len(result.Findings))
		for _, f := range result.Findings {
			t.Logf("  finding: detector=%s desc=%s matched=%q", f.DetectorName, f.Description, f.MatchedValue)
		}
	}
	if result.Score != 0 {
		t.Errorf("expected score 0 for clean request, got %d", result.Score)
	}
}

// 3. TestDetectionLayer_SQLi - SQL injection in query triggers sqli findings
func TestDetectionLayer_SQLi(t *testing.T) {
	layer := NewLayer(defaultConfig())

	ctx := makeContext("/search", "q='+UNION+SELECT+1,2,3--", "", "")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatal("expected sqli findings, got none")
	}

	hasSQLi := false
	for _, f := range result.Findings {
		if f.DetectorName == "sqli" {
			hasSQLi = true
			break
		}
	}
	if !hasSQLi {
		t.Error("expected at least one finding from sqli detector")
	}
	if result.Score <= 0 {
		t.Errorf("expected positive score for sqli, got %d", result.Score)
	}
	if result.Action != engine.ActionLog {
		t.Errorf("expected ActionLog, got %v", result.Action)
	}
}

// 4. TestDetectionLayer_XSS - XSS in query triggers xss findings
func TestDetectionLayer_XSS(t *testing.T) {
	layer := NewLayer(defaultConfig())

	ctx := makeContext("/page", "name=<script>alert(1)</script>", "", "")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatal("expected xss findings, got none")
	}

	hasXSS := false
	for _, f := range result.Findings {
		if f.DetectorName == "xss" {
			hasXSS = true
			break
		}
	}
	if !hasXSS {
		t.Error("expected at least one finding from xss detector")
	}
	if result.Score <= 0 {
		t.Errorf("expected positive score for xss, got %d", result.Score)
	}
}

// 5. TestDetectionLayer_LFI - path traversal in path triggers lfi findings
func TestDetectionLayer_LFI(t *testing.T) {
	layer := NewLayer(defaultConfig())

	ctx := makeContext("/files/../../../../etc/passwd", "", "", "")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatal("expected lfi findings, got none")
	}

	hasLFI := false
	for _, f := range result.Findings {
		if f.DetectorName == "lfi" {
			hasLFI = true
			break
		}
	}
	if !hasLFI {
		t.Error("expected at least one finding from lfi detector")
	}
	if result.Score <= 0 {
		t.Errorf("expected positive score for lfi, got %d", result.Score)
	}
}

// 6. TestDetectionLayer_CMDi - command injection in query triggers cmdi findings
func TestDetectionLayer_CMDi(t *testing.T) {
	layer := NewLayer(defaultConfig())

	ctx := makeContext("/run", "cmd=test%3Bcat+/etc/passwd", "", "")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatal("expected cmdi findings, got none")
	}

	hasCMDi := false
	for _, f := range result.Findings {
		if f.DetectorName == "cmdi" {
			hasCMDi = true
			break
		}
	}
	if !hasCMDi {
		t.Error("expected at least one finding from cmdi detector")
	}
	if result.Score <= 0 {
		t.Errorf("expected positive score for cmdi, got %d", result.Score)
	}
}

// 7. TestDetectionLayer_XXE - XXE in XML body triggers xxe findings
func TestDetectionLayer_XXE(t *testing.T) {
	layer := NewLayer(defaultConfig())

	xmlBody := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`
	ctx := makeContext("/api/data", "", xmlBody, "application/xml")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatal("expected xxe findings, got none")
	}

	hasXXE := false
	for _, f := range result.Findings {
		if f.DetectorName == "xxe" {
			hasXXE = true
			break
		}
	}
	if !hasXXE {
		t.Error("expected at least one finding from xxe detector")
	}
	if result.Score <= 0 {
		t.Errorf("expected positive score for xxe, got %d", result.Score)
	}
}

// 8. TestDetectionLayer_XXE_NonXML - non-XML body with non-XML content-type produces no xxe findings
func TestDetectionLayer_XXE_NonXML(t *testing.T) {
	layer := NewLayer(defaultConfig())

	// Body that does NOT look like XML — should not trigger XXE scanning
	jsonBody := `{"user": "admin", "query": "SELECT * FROM users"}`
	ctx := makeContext("/api/data", "", jsonBody, "application/json")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)

	for _, f := range result.Findings {
		if f.DetectorName == "xxe" {
			t.Errorf("expected no xxe findings for non-XML body, but found: %s", f.Description)
		}
	}
}

// 8b. TestDetectionLayer_XXE_XMLBodyNonXMLContentType - XML body with non-XML content-type IS detected
func TestDetectionLayer_XXE_XMLBodyNonXMLContentType(t *testing.T) {
	layer := NewLayer(defaultConfig())

	// Body starts with <!DOCTYPE — should be scanned even with application/json content-type
	xmlBody := `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
	ctx := makeContext("/api/data", "", xmlBody, "application/json")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)

	hasXXE := false
	for _, f := range result.Findings {
		if f.DetectorName == "xxe" {
			hasXXE = true
			break
		}
	}
	if !hasXXE {
		t.Error("expected xxe findings for XML body with non-XML content-type (bypass detection)")
	}
}

func TestDetectionLayer_CorpusQualityBaseline(t *testing.T) {
	layer := NewLayer(defaultConfig())
	root := filepath.Join("..", "..", "..", "testdata")
	attackFiles := map[string]string{
		"cmdi":         filepath.Join(root, "attacks", "cmdi.txt"),
		"lfi":          filepath.Join(root, "attacks", "lfi.txt"),
		"nosqli":       filepath.Join(root, "attacks", "nosqli.txt"),
		"sqli":         filepath.Join(root, "attacks", "sqli.txt"),
		"ssrf":         filepath.Join(root, "attacks", "ssrf.txt"),
		"ssti":         filepath.Join(root, "attacks", "ssti.txt"),
		"xss":          filepath.Join(root, "attacks", "xss.txt"),
		"xxe":          filepath.Join(root, "attacks", "xxe.txt"),
		"openredirect": filepath.Join(root, "attacks", "openredirect.txt"),
		"graphql":      filepath.Join(root, "attacks", "graphql.txt"),
	}

	for detector, path := range attackFiles {
		samples := readDetectionCorpus(t, path)
		if len(samples) < 20 {
			t.Fatalf("%s attack corpus too small: got %d samples", detector, len(samples))
		}

		detected := 0
		var missed []string
		for _, sample := range samples {
			result := processCorpusSample(layer, detector, sample)
			if result.Score > 0 && len(result.Findings) > 0 {
				detected++
			} else if len(missed) < 10 {
				missed = append(missed, sample)
			}
		}

		rate := float64(detected) / float64(len(samples))
		t.Logf("%s attack corpus detection rate: %d/%d %.1f%%", detector, detected, len(samples), rate*100)
		if rate < 0.90 {
			t.Logf("%s first missed attack samples: %q", detector, missed)
			t.Fatalf("%s attack corpus detection rate %.1f%% below 90%% baseline", detector, rate*100)
		}
	}

	benignCorpora := []struct {
		name    string
		path    string
		context string
		min     int
	}{
		{name: "generic", path: filepath.Join(root, "benign", "queries.txt"), context: "benign", min: 40},
		{name: "cmdi", path: filepath.Join(root, "benign", "cmdi.txt"), context: "benign-cmdi", min: 20},
		{name: "lfi", path: filepath.Join(root, "benign", "lfi.txt"), context: "benign-lfi", min: 20},
		{name: "nosqli", path: filepath.Join(root, "benign", "nosqli.txt"), context: "benign-nosqli", min: 20},
		{name: "ssrf", path: filepath.Join(root, "benign", "ssrf.txt"), context: "benign-ssrf", min: 20},
		{name: "ssti", path: filepath.Join(root, "benign", "ssti.txt"), context: "benign-ssti", min: 20},
		{name: "application_logs", path: filepath.Join(root, "benign", "application_logs.txt"), context: "benign-log", min: 20},
	}

	totalBenignSamples := 0
	totalFalseBlocks := 0
	totalWeightedFalsePositiveScore := 0
	for _, corpus := range benignCorpora {
		samples := readDetectionCorpus(t, corpus.path)
		if len(samples) < corpus.min {
			t.Fatalf("%s benign corpus too small: got %d samples, want at least %d", corpus.name, len(samples), corpus.min)
		}

		falseBlocks := 0
		weightedScore := 0
		for _, sample := range samples {
			result := processCorpusSample(layer, corpus.context, sample)
			weightedScore += weightedFalsePositiveScore(result.Findings)
			if result.Score >= 50 {
				falseBlocks++
				t.Logf("%s benign sample reached block threshold: score=%d weighted_fp=%d findings=%s sample=%q", corpus.name, result.Score, weightedFalsePositiveScore(result.Findings), summarizeFindings(result.Findings), sample)
			}
		}

		totalBenignSamples += len(samples)
		totalFalseBlocks += falseBlocks
		totalWeightedFalsePositiveScore += weightedScore
		falseBlockRate := float64(falseBlocks) / float64(len(samples))
		avgWeightedScore := float64(weightedScore) / float64(len(samples))
		t.Logf("%s benign corpus block false-positive rate: %d/%d %.1f%%; weighted FP avg: %.2f", corpus.name, falseBlocks, len(samples), falseBlockRate*100, avgWeightedScore)
	}

	falseBlockRate := float64(totalFalseBlocks) / float64(totalBenignSamples)
	avgWeightedFalsePositiveScore := float64(totalWeightedFalsePositiveScore) / float64(totalBenignSamples)
	t.Logf("combined benign corpus block false-positive rate: %d/%d %.1f%%; weighted FP avg: %.2f", totalFalseBlocks, totalBenignSamples, falseBlockRate*100, avgWeightedFalsePositiveScore)
	if falseBlockRate > 0.06 {
		t.Fatalf("combined benign corpus block false-positive rate %.1f%% exceeds 6%% baseline", falseBlockRate*100)
	}
	if avgWeightedFalsePositiveScore > 1.0 {
		t.Fatalf("combined benign corpus weighted false-positive average %.2f exceeds 1.00 baseline", avgWeightedFalsePositiveScore)
	}
}

func readDetectionCorpus(t *testing.T, path string) []string {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	defer f.Close()

	var samples []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		samples = append(samples, line)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("Scan(%s): %v", path, err)
	}
	return samples
}

func processCorpusSample(layer *Layer, detector, sample string) engine.LayerResult {
	path := "/corpus"
	query := "q=" + url.QueryEscape(sample)
	body := ""
	contentType := ""

	switch detector {
	case "lfi":
		path = "/download/" + sample
		query = "file=" + url.QueryEscape(sample)
	case "xxe":
		path = "/xml"
		query = ""
		body = sample
		contentType = "application/xml"
	case "benign":
		path = "/search"
		query = "q=" + url.QueryEscape(sample)
	case "benign-cmdi":
		path = "/docs/commands"
		query = "text=" + url.QueryEscape(sample)
	case "benign-lfi":
		path = "/download/reference"
		query = "file=" + url.QueryEscape(sample)
	case "benign-nosqli":
		path = "/api/filter"
		query = ""
		body = sample
		contentType = "application/json"
	case "benign-ssrf":
		path = "/link-preview"
		query = "url=" + url.QueryEscape(sample)
	case "benign-ssti":
		path = "/templates/preview"
		query = "template=" + url.QueryEscape(sample)
	case "benign-log":
		path = "/observability/logs"
		query = ""
		body = sample
		contentType = "text/plain"
	case "openredirect":
		path = "/redirect"
		query = "redirect=" + url.QueryEscape(sample)
	case "graphql":
		path = "/graphql"
		query = ""
		body = sample
		contentType = "application/graphql"
	}

	ctx := makeContext(path, query, body, contentType)
	defer engine.ReleaseContext(ctx)

	return layer.Process(ctx)
}

func weightedFalsePositiveScore(findings []engine.Finding) int {
	total := 0
	for _, finding := range findings {
		switch finding.Severity {
		case engine.SeverityCritical:
			total += 12
		case engine.SeverityHigh:
			total += 7
		case engine.SeverityMedium:
			total += 3
		case engine.SeverityLow:
			total++
		}
	}
	return total
}

func summarizeFindings(findings []engine.Finding) string {
	if len(findings) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(findings))
	for _, finding := range findings {
		parts = append(parts, finding.DetectorName+":"+finding.Severity.String()+":"+finding.Description)
	}
	return strings.Join(parts, "; ")
}

// 9. TestDetectionLayer_SSRF - SSRF URL in query triggers ssrf findings
func TestDetectionLayer_SSRF(t *testing.T) {
	layer := NewLayer(defaultConfig())

	ctx := makeContext("/proxy", "url=http://169.254.169.254/latest/meta-data/", "", "")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatal("expected ssrf findings, got none")
	}

	hasSSRF := false
	for _, f := range result.Findings {
		if f.DetectorName == "ssrf" {
			hasSSRF = true
			break
		}
	}
	if !hasSSRF {
		t.Error("expected at least one finding from ssrf detector")
	}
	if result.Score <= 0 {
		t.Errorf("expected positive score for ssrf, got %d", result.Score)
	}
}

// 10. TestDetectionLayer_MultipleDetectors - input triggers multiple detectors, all findings accumulated
func TestDetectionLayer_MultipleDetectors(t *testing.T) {
	layer := NewLayer(defaultConfig())

	// This query contains both SQLi and XSS patterns
	ctx := makeContext("/page", "q=<script>alert(1)</script>'+UNION+SELECT+1--", "", "")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)
	if len(result.Findings) == 0 {
		t.Fatal("expected findings from multiple detectors, got none")
	}

	detectors := make(map[string]bool)
	for _, f := range result.Findings {
		detectors[f.DetectorName] = true
	}

	if len(detectors) < 2 {
		t.Errorf("expected findings from at least 2 detectors, got %d: %v", len(detectors), detectors)
	}
}

// 11. TestDetectionLayer_Exclusion - exclude sqli for /api/webhook/* path, verify sqli skipped but others run
func TestDetectionLayer_Exclusion(t *testing.T) {
	cfg := defaultConfig()
	cfg.Exclusions = []Exclusion{
		{
			PathPrefix: "/api/webhook",
			Detectors:  []string{"sqli"},
			Reason:     "Webhook payloads may contain SQL-like patterns",
		},
	}
	layer := NewLayer(cfg)

	// SQLi payload on an excluded path
	ctx := makeContext("/api/webhook/github", "q='+UNION+SELECT+1,2,3--", "", "")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)

	for _, f := range result.Findings {
		if f.DetectorName == "sqli" {
			t.Error("expected sqli detector to be excluded for /api/webhook path, but found sqli finding")
		}
	}

	// Verify that a non-excluded detector (like xss) still runs on the same path
	ctx2 := makeContext("/api/webhook/github", "q=<script>alert(1)</script>", "", "")
	defer engine.ReleaseContext(ctx2)

	result2 := layer.Process(ctx2)
	hasXSS := false
	for _, f := range result2.Findings {
		if f.DetectorName == "xss" {
			hasXSS = true
			break
		}
	}
	if !hasXSS {
		t.Error("expected xss detector to still run on excluded path (only sqli was excluded)")
	}
}

// 12. TestDetectionLayer_DetectorDisabled - disable sqli detector, verify it's skipped
func TestDetectionLayer_DetectorDisabled(t *testing.T) {
	cfg := defaultConfig()
	cfg.Detectors["sqli"] = DetectorConfig{Enabled: false, Multiplier: 1.0}
	layer := NewLayer(cfg)

	ctx := makeContext("/search", "q='+UNION+SELECT+1,2,3--", "", "")
	defer engine.ReleaseContext(ctx)

	result := layer.Process(ctx)

	for _, f := range result.Findings {
		if f.DetectorName == "sqli" {
			t.Error("expected sqli detector to be disabled, but found sqli finding")
		}
	}
}

// 13. TestDetectionLayer_Multiplier - set sqli multiplier to 2.0, verify scores doubled
func TestDetectionLayer_Multiplier(t *testing.T) {
	// First run with multiplier 1.0
	cfg1 := Config{
		Enabled: true,
		Detectors: map[string]DetectorConfig{
			"sqli": {Enabled: true, Multiplier: 1.0},
		},
	}
	layer1 := NewLayer(&cfg1)

	ctx1 := makeContext("/search", "q='+UNION+SELECT+1,2,3--", "", "")
	defer engine.ReleaseContext(ctx1)
	result1 := layer1.Process(ctx1)

	// Then run with multiplier 2.0
	cfg2 := Config{
		Enabled: true,
		Detectors: map[string]DetectorConfig{
			"sqli": {Enabled: true, Multiplier: 2.0},
		},
	}
	layer2 := NewLayer(&cfg2)

	ctx2 := makeContext("/search", "q='+UNION+SELECT+1,2,3--", "", "")
	defer engine.ReleaseContext(ctx2)
	result2 := layer2.Process(ctx2)

	if result1.Score == 0 {
		t.Fatal("expected non-zero score with multiplier 1.0")
	}

	// The 2.0 multiplier score should be approximately double
	// Due to integer rounding, allow some tolerance
	expectedMin := result1.Score * 2 * 90 / 100  // 90% of double
	expectedMax := result1.Score * 2 * 110 / 100 // 110% of double

	if result2.Score < expectedMin || result2.Score > expectedMax {
		t.Errorf("expected score ~%d with 2.0 multiplier (base=%d), got %d",
			result1.Score*2, result1.Score, result2.Score)
	}
}

// 14. TestDetectionLayer_AllDetectorsPresent - verify all configured detectors initialized
func TestDetectionLayer_AllDetectorsPresent(t *testing.T) {
	layer := NewLayer(defaultConfig())

	if len(layer.detectors) != 11 {
		t.Errorf("expected 11 detectors, got %d", len(layer.detectors))
	}

	expected := map[string]bool{
		"sqli":         false,
		"xss":          false,
		"lfi":          false,
		"cmdi":         false,
		"xxe":          false,
		"ssrf":         false,
		"ssti":         false,
		"nosqli":       false,
		"smuggling":    false,
		"openredirect": false,
		"graphql":      false,
	}

	for _, det := range layer.detectors {
		name := det.DetectorName()
		if _, ok := expected[name]; ok {
			expected[name] = true
		} else {
			t.Errorf("unexpected detector: %s", name)
		}
	}

	for name, found := range expected {
		if !found {
			t.Errorf("detector %s not found in layer", name)
		}
	}
}

// 15. TestDetectionLayer_Name - verify Name() returns "detection"
func TestDetectionLayer_Name(t *testing.T) {
	layer := NewLayer(defaultConfig())
	if layer.Name() != "detection" {
		t.Errorf("expected layer name 'detection', got %q", layer.Name())
	}
}
