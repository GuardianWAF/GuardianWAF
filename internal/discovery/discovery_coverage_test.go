package discovery

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- Layer coverage (currently 0%) ---

func TestNewLayer_Cov(t *testing.T) {
	l, err := NewLayer(nil)
	if err != nil {
		t.Fatalf("NewLayer(nil) failed: %v", err)
	}
	if l == nil {
		t.Fatal("expected layer, got nil")
	}
	if l.Name() != "api-discovery" {
		t.Errorf("Name() = %q, want api-discovery", l.Name())
	}
	if l.Order() != 310 {
		t.Errorf("Order() = %d, want 310", l.Order())
	}
	defer l.Stop()
}

func TestNewLayer_WithConfig_Cov(t *testing.T) {
	cfg := &EngineConfig{
		RingBufferSize:   100,
		MinSamples:       1,
		ClusterThreshold: 0.8,
		ExportInterval:   1 * time.Second,
	}
	l, err := NewLayer(cfg)
	if err != nil {
		t.Fatalf("NewLayer failed: %v", err)
	}
	defer l.Stop()
}

func TestLayer_Process_NilEngine_Cov(t *testing.T) {
	l := &Layer{engine: nil}
	ctx := &engine.RequestContext{}
	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for nil engine, got %v", result.Action)
	}
}

func TestLayer_Process_NilManager_Cov(t *testing.T) {
	l := &Layer{engine: &Engine{manager: nil}}
	ctx := &engine.RequestContext{
		Request: httptest.NewRequest("GET", "/test", nil),
	}
	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for nil manager, got %v", result.Action)
	}
}

func TestLayer_Process_NilRequest_Cov(t *testing.T) {
	cfg := &EngineConfig{
		RingBufferSize:   100,
		MinSamples:       1,
		ClusterThreshold: 0.8,
		ExportInterval:   1 * time.Second,
	}
	l, _ := NewLayer(cfg)
	defer l.Stop()

	ctx := &engine.RequestContext{
		Request: nil,
	}
	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for nil request, got %v", result.Action)
	}
}

func TestLayer_Process_WithRequest_Cov(t *testing.T) {
	cfg := &EngineConfig{
		RingBufferSize:   100,
		MinSamples:       1,
		ClusterThreshold: 0.8,
		ExportInterval:   1 * time.Second,
	}
	l, _ := NewLayer(cfg)
	defer l.Stop()

	ctx := &engine.RequestContext{
		Request: httptest.NewRequest("GET", "/api/test", nil),
	}
	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for discovery layer, got %v", result.Action)
	}
}

func TestLayer_Process_WithMetadata_Cov(t *testing.T) {
	cfg := &EngineConfig{
		RingBufferSize:   100,
		MinSamples:       1,
		ClusterThreshold: 0.8,
		ExportInterval:   1 * time.Second,
	}
	l, _ := NewLayer(cfg)
	defer l.Stop()

	ctx := &engine.RequestContext{
		Request:  httptest.NewRequest("GET", "/api/test", nil),
		Metadata: map[string]any{"status_code": 200},
	}
	result := l.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass, got %v", result.Action)
	}
}

func TestLayer_RecordRequest_Cov(t *testing.T) {
	cfg := &EngineConfig{
		RingBufferSize:   100,
		MinSamples:       1,
		ClusterThreshold: 0.8,
		ExportInterval:   1 * time.Second,
	}
	l, _ := NewLayer(cfg)
	defer l.Stop()

	req := httptest.NewRequest("GET", "/api/test", nil)
	l.RecordRequest(req, 200)
}

func TestLayer_RecordRequest_NilEngine_Cov(t *testing.T) {
	l := &Layer{engine: nil}
	l.RecordRequest(httptest.NewRequest("GET", "/", nil), 200)
}

func TestLayer_ExportToOpenAPI_Cov(t *testing.T) {
	cfg := &EngineConfig{
		RingBufferSize:   100,
		MinSamples:       1,
		ClusterThreshold: 0.8,
		ExportInterval:   1 * time.Second,
	}
	l, _ := NewLayer(cfg)
	defer l.Stop()

	spec := l.ExportToOpenAPI()
	// May be nil if no data processed yet - that's OK
	_ = spec
}

func TestLayer_ExportToOpenAPI_NilEngine_Cov(t *testing.T) {
	l := &Layer{engine: nil}
	spec := l.ExportToOpenAPI()
	if spec != nil {
		t.Error("expected nil for nil engine")
	}
}

func TestLayer_GetStats_Cov(t *testing.T) {
	cfg := &EngineConfig{
		RingBufferSize:   100,
		MinSamples:       1,
		ClusterThreshold: 0.8,
		ExportInterval:   1 * time.Second,
	}
	l, _ := NewLayer(cfg)
	defer l.Stop()

	stats := l.GetStats()
	if !stats.IsLearning {
		t.Error("expected IsLearning=true")
	}
}

func TestLayer_GetStats_NilEngine_Cov(t *testing.T) {
	l := &Layer{engine: nil}
	stats := l.GetStats()
	if stats.EndpointsDiscovered != 0 {
		t.Error("expected zero stats")
	}
}

func TestLayer_GetStats_NilManager_Cov(t *testing.T) {
	l := &Layer{engine: &Engine{manager: nil}}
	stats := l.GetStats()
	if stats.EndpointsDiscovered != 0 {
		t.Error("expected zero stats with nil manager")
	}
}

func TestLayer_Start_Cov(t *testing.T) {
	l := &Layer{engine: nil}
	l.Start() // Should not panic
}

func TestLayer_Stop_Cov(t *testing.T) {
	l := &Layer{engine: nil}
	l.Stop() // Should not panic
}

func TestLayer_Stop_NilEngine_Cov(t *testing.T) {
	l := &Layer{engine: nil}
	l.Stop() // Should not panic
}

// --- Helper functions coverage ---

func TestIsSlug_Cov(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"my-blog-post", true},
		{"hello-world-123", true},
		{"UPPERCASE", false},
		{"has spaces", false},
		{"", false},
		{"abc123", true},
	}
	for _, tt := range tests {
		got := isSlug(tt.input)
		if got != tt.expected {
			t.Errorf("isSlug(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestIsHash_Cov(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"d41d8cd98f00b204e9800998ecf8427e", true}, // MD5 length (32)
		{"", false},                                // too short
		{"a1b2", false},                            // too short
		{"d41d8cd98f00b204e9800998ecf8427z", false}, // invalid hex
	}
	for _, tt := range tests {
		got := isHash(tt.input)
		if got != tt.expected {
			t.Errorf("isHash(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestInferDataType_Cov(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"123", "integer"},
		{"true", "boolean"},
		{"false", "boolean"},
		{"hello", "string"},
		{"", "string"},
	}
	for _, tt := range tests {
		got := inferDataType(tt.input)
		if got != tt.expected {
			t.Errorf("inferDataType(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestSplitPath_Cov(t *testing.T) {
	tests := []struct {
		input    string
		expected int // length of result
	}{
		{"/api/users/123", 3},
		{"api/users", 2},
		{"/", 0},
		{"", 0},
		{"///", 0}, // all slashes trimmed
	}
	for _, tt := range tests {
		result := splitPath(tt.input)
		if len(result) != tt.expected {
			t.Errorf("splitPath(%q) = %v (len %d), want len %d", tt.input, result, len(result), tt.expected)
		}
	}
}

func TestIsInteger_Cov(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"123", true},
		{"0", true},
		{"", false},
		{"12a3", false},
		{"-1", false}, // only digits
	}
	for _, tt := range tests {
		got := isInteger(tt.input)
		if got != tt.expected {
			t.Errorf("isInteger(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestContains_Cov(t *testing.T) {
	if !contains("hello world", "world") {
		t.Error("expected to find 'world' in 'hello world'")
	}
	if contains("hello", "world") {
		t.Error("expected not to find 'world' in 'hello'")
	}
	if !contains("hello", "") {
		t.Error("empty substring should always match")
	}
}

func TestFindSubstring_Cov(t *testing.T) {
	if findSubstring("hello world", "world") != 6 {
		t.Error("expected index 6")
	}
	if findSubstring("hello", "world") != -1 {
		t.Error("expected -1 for not found")
	}
	if findSubstring("", "") != 0 {
		t.Error("empty in empty should be 0")
	}
}

func TestContainsSensitivePattern_Cov(t *testing.T) {
	patterns := []struct {
		pattern  string
		expected bool
	}{
		{"/api/users", false},
		{"/api/admin/settings", true},
		{"/api/auth/login", true},
		{"/api/password/reset", true},
		{"/api/payment/process", true},
		{"/api/credit/card", true},
		{"/api/token/refresh", true},
		{"/api/secret/key", true},
		{"/api/user/profile", false},
	}
	for _, tt := range patterns {
		got := containsSensitivePattern(tt.pattern)
		if got != tt.expected {
			t.Errorf("containsSensitivePattern(%q) = %v, want %v", tt.pattern, got, tt.expected)
		}
	}
}

func TestSlicesEqual_Cov(t *testing.T) {
	tests := []struct {
		a, b     []string
		expected bool
	}{
		{[]string{"a", "b"}, []string{"a", "b"}, true},
		{[]string{"a", "b"}, []string{"b", "a"}, true},
		{[]string{"a"}, []string{"a", "b"}, false},
		{[]string{}, []string{}, true},
		{[]string{"a", "a"}, []string{"a", "b"}, false},
	}
	for _, tt := range tests {
		got := slicesEqual(tt.a, tt.b)
		if got != tt.expected {
			t.Errorf("slicesEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.expected)
		}
	}
}

func TestSanitizeOperationID_Cov(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/api/users/{id}", "_api_users__id_"},
		{"simple", "simple"},
		{"", ""},
	}
	for _, tt := range tests {
		got := sanitizeOperationID(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeOperationID(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// --- Clustering Engine edge cases ---

func TestClusteringEngine_DifferentSegmentLengths_Cov(t *testing.T) {
	eng := NewClusteringEngine(2, 0.8)
	now := time.Now()

	requests := []CapturedRequest{
		{Method: "GET", Path: "/api/v2/users/123", Timestamp: now},
		{Method: "GET", Path: "/api/v2/users/456", Timestamp: now},
		{Method: "GET", Path: "/api/v2/users/789", Timestamp: now},
	}

	clusters := eng.Cluster(requests)
	if len(clusters) == 0 {
		t.Log("no clusters for varying segment lengths (may be expected)")
	}
}

func TestClusteringEngine_CreateClusterEmpty_Cov(t *testing.T) {
	eng := NewClusteringEngine(1, 0.8)
	cluster := eng.createCluster(nil)
	if cluster != nil {
		t.Error("expected nil for empty requests")
	}
}

func TestInferPatternEmpty_Cov(t *testing.T) {
	eng := NewClusteringEngine(1, 0.8)
	pattern, segments := eng.inferPattern(nil)
	if pattern != "" {
		t.Errorf("expected empty pattern, got %q", pattern)
	}
	if segments != nil {
		t.Error("expected nil segments")
	}
}

func TestIsDynamicPosition_SingleValue_Cov(t *testing.T) {
	eng := NewClusteringEngine(1, 0.8)
	// Single value => uniqueRatio = 1/1 = 1.0 > 0.5 => dynamic
	result := eng.isDynamicPosition([]string{"only"})
	if result {
		t.Error("single value should not be dynamic (need >= 2)")
	}
}

func TestIsDynamicPosition_AllSame_Cov(t *testing.T) {
	eng := NewClusteringEngine(1, 0.8)
	// All same => uniqueRatio = 1/5 = 0.2, NOT > 0.5 => not dynamic
	result := eng.isDynamicPosition([]string{"same", "same", "same", "same", "same"})
	if result {
		t.Error("all same values should not be dynamic")
	}
}

func TestGetPatternForType_Cov(t *testing.T) {
	eng := NewClusteringEngine(1, 0.8)
	tests := []struct {
		typ      string
		expected string
	}{
		{"id", `[^/]+`},
		{"uuid", `[0-9a-f-]{36}`},
		{"slug", `[a-z0-9-]+`},
		{"unknown", `[^/]+`},
	}
	for _, tt := range tests {
		got := eng.getPatternForType(tt.typ)
		if got != tt.expected {
			t.Errorf("getPatternForType(%q) = %q, want %q", tt.typ, got, tt.expected)
		}
	}
}

func TestSegmentTypeToDataType_Cov(t *testing.T) {
	eng := NewClusteringEngine(1, 0.8)
	tests := []struct {
		typ      string
		expected string
	}{
		{"id", "integer"},
		{"uuid", "string"},
		{"slug", "string"},
		{"unknown", "string"},
	}
	for _, tt := range tests {
		got := eng.segmentTypeToDataType(tt.typ)
		if got != tt.expected {
			t.Errorf("segmentTypeToDataType(%q) = %q, want %q", tt.typ, got, tt.expected)
		}
	}
}

// --- Analyzer: DetectChanges with parameter count change ---

func TestAnalyzer_DetectChanges_ParamCountChange_Cov(t *testing.T) {
	cfg := DefaultConfig().Analysis
	analyzer := NewAnalyzer(cfg)

	oldInv := &Inventory{
		Endpoints: map[string]*Endpoint{
			"ep1": {
				ID:         "ep1",
				Pattern:    "/api/test",
				Methods:    []string{"GET"},
				Parameters: []Parameter{{Name: "p1"}},
			},
		},
	}

	newInv := &Inventory{
		Endpoints: map[string]*Endpoint{
			"ep1": {
				ID:         "ep1",
				Pattern:    "/api/test",
				Methods:    []string{"GET"},
				Parameters: []Parameter{{Name: "p1"}, {Name: "p2"}, {Name: "p3"}},
			},
		},
	}

	changes := analyzer.DetectChanges(oldInv, newInv)
	found := false
	for _, c := range changes {
		if strings.Contains(c.Description, "Parameter count") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected parameter count change, got changes: %v", changes)
	}
}

// --- inferTags with auth-required and sensitive ---

func TestInferTags_AuthRequired_Cov(t *testing.T) {
	cfg := DefaultConfig().Analysis
	analyzer := NewAnalyzer(cfg)

	cluster := Cluster{
		Pattern: "/api/data",
		Parameters: []Parameter{
			{Name: "authorization", In: "header"},
		},
	}
	tags := analyzer.inferTags(cluster)
	found := false
	for _, tag := range tags {
		if tag == "auth-required" {
			found = true
		}
	}
	if !found {
		t.Error("expected auth-required tag")
	}
}

func TestInferTags_APIKeyAuth_Cov(t *testing.T) {
	cfg := DefaultConfig().Analysis
	analyzer := NewAnalyzer(cfg)

	cluster := Cluster{
		Pattern: "/api/data",
		Parameters: []Parameter{
			{Name: "x-api-key", In: "header"},
		},
	}
	tags := analyzer.inferTags(cluster)
	found := false
	for _, tag := range tags {
		if tag == "auth-required" {
			found = true
		}
	}
	if !found {
		t.Error("expected auth-required tag for x-api-key")
	}
}

func TestInferTags_Sensitive_Cov(t *testing.T) {
	cfg := DefaultConfig().Analysis
	analyzer := NewAnalyzer(cfg)

	cluster := Cluster{
		Pattern: "/api/admin/users",
	}
	tags := analyzer.inferTags(cluster)
	found := false
	for _, tag := range tags {
		if tag == "sensitive" {
			found = true
		}
	}
	if !found {
		t.Error("expected sensitive tag for admin path")
	}
}

func TestInferTags_Public_Cov(t *testing.T) {
	cfg := DefaultConfig().Analysis
	analyzer := NewAnalyzer(cfg)

	cluster := Cluster{
		Pattern: "/api/public/data",
	}
	tags := analyzer.inferTags(cluster)
	if len(tags) != 1 || tags[0] != "public" {
		t.Errorf("expected public tag, got %v", tags)
	}
}

// --- getStatusCodeDescription ---

func TestGetStatusCodeDescription_Cov(t *testing.T) {
	gen := NewSchemaGenerator()
	tests := []struct {
		code     string
		expected string
	}{
		{"200", "OK"},
		{"201", "Created"},
		{"204", "No Content"},
		{"400", "Bad Request"},
		{"401", "Unauthorized"},
		{"403", "Forbidden"},
		{"404", "Not Found"},
		{"500", "Internal Server Error"},
		{"418", "Status 418"}, // unknown
	}
	for _, tt := range tests {
		got := gen.getStatusCodeDescription(tt.code)
		if got != tt.expected {
			t.Errorf("getStatusCodeDescription(%q) = %q, want %q", tt.code, got, tt.expected)
		}
	}
}

// --- extractBodySample edge case: body larger than sample size ---

func TestCollector_BodySampleTruncation_Cov(t *testing.T) {
	cfg := CollectionConfig{BufferSize: 10, SampleRate: 1.0, BodySampleSize: 10}
	c := NewCollector(cfg)

	// Create a body larger than BodySampleSize
	body := []byte("this is a very long body that exceeds the sample size")
	req := &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: "/api/data"},
		Body:   io.NopCloser(bytes.NewReader(body)),
	}
	c.Collect(req, nil, 0)

	flushed := c.Flush()
	if len(flushed) != 1 {
		t.Fatalf("expected 1 request, got %d", len(flushed))
	}
	if len(flushed[0].BodySample) > 10 {
		t.Errorf("body sample should be truncated to 10 bytes, got %d", len(flushed[0].BodySample))
	}
}

// --- Collector: Peek on empty buffer ---

func TestCollector_PeekEmpty_Cov(t *testing.T) {
	cfg := CollectionConfig{BufferSize: 10, SampleRate: 1.0}
	c := NewCollector(cfg)

	result := c.Peek()
	if result != nil {
		t.Error("expected nil for empty peek")
	}
}

// --- Manager: ExportOpenAPI with empty inventory ---

func TestManager_ExportOpenAPI_EmptyInventory_Cov(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	mgr, _ := NewManager(cfg)
	defer mgr.Close()

	// Empty inventory (default)
	spec := mgr.ExportOpenAPI()
	if spec == nil {
		t.Error("expected non-nil spec even with empty inventory")
	}
}

// --- Manager: process with requests ---

func TestManager_Process_Cov(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Analysis.MinClusterSize = 1
	cfg.Collection.FlushPeriod = 1 * time.Hour // prevent auto-flush
	mgr, _ := NewManager(cfg)
	defer mgr.Close()

	// Record some requests
	for i := 0; i < 5; i++ {
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/api/test"},
		}
		mgr.Record(req, &http.Response{StatusCode: 200}, 10*time.Millisecond)
	}

	// Manually trigger process
	mgr.process()

	// Check stats
	stats := mgr.Stats()
	if stats.RequestsCollected < 5 {
		t.Errorf("expected at least 5 collected, got %d", stats.RequestsCollected)
	}
}

// --- Manager: process with empty collector ---

func TestManager_ProcessEmpty_Cov(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Analysis.MinClusterSize = 1
	cfg.Collection.FlushPeriod = 1 * time.Hour
	mgr, _ := NewManager(cfg)
	defer mgr.Close()

	// Don't record anything - process should handle empty
	mgr.process()
	// Should not panic
}

// --- Manager: Close idempotent ---

func TestManager_Close_Idempotent_Cov(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false
	mgr, _ := NewManager(cfg)

	err := mgr.Close()
	if err != nil {
		t.Errorf("first Close failed: %v", err)
	}
	err = mgr.Close()
	if err != nil {
		t.Errorf("second Close failed: %v", err)
	}
}

// --- generateEndpointID and generateChangeID ---

func TestGenerateEndpointID_Cov(t *testing.T) {
	id1 := generateEndpointID("/api/users")
	id2 := generateEndpointID("/api/users")
	if id1 != id2 {
		t.Error("same pattern should produce same ID")
	}
	id3 := generateEndpointID("/api/orders")
	if id1 == id3 {
		t.Error("different patterns should produce different IDs")
	}
	if len(id1) != 12 {
		t.Errorf("expected 12-char ID, got %d", len(id1))
	}
}

func TestGenerateChangeID_Cov(t *testing.T) {
	id := generateChangeID()
	if !strings.HasPrefix(id, "change-") {
		t.Errorf("expected change- prefix, got %s", id)
	}
}

// --- countDynamicEndpoints ---

func TestCountDynamicEndpoints_Cov(t *testing.T) {
	clusters := []Cluster{
		{Pattern: "/api/users/{id}", Parameters: []Parameter{{Name: "id"}}},
		{Pattern: "/api/static", Parameters: nil},
		{Pattern: "/api/orders/{orderId}", Parameters: []Parameter{{Name: "orderId"}, {Name: "filter"}}},
	}
	count := countDynamicEndpoints(clusters)
	if count != 2 {
		t.Errorf("expected 2 dynamic endpoints, got %d", count)
	}
}

// --- Manager SetEnabled then re-enable ---

func TestManager_SetEnabled_Reenable_Cov(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Collection.FlushPeriod = 100 * time.Millisecond
	mgr, _ := NewManager(cfg)

	// Disable then re-enable
	mgr.SetEnabled(false)
	if mgr.Enabled() {
		t.Error("should be disabled")
	}

	mgr.SetEnabled(true)
	if !mgr.Enabled() {
		t.Error("should be re-enabled")
	}

	mgr.Close()
}
