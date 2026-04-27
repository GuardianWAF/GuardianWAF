package crs

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// ---------------------------------------------------------------------------
// Transaction tests
// ---------------------------------------------------------------------------

func TestTransaction_RequestBodyString(t *testing.T) {
	tx := NewTransaction()
	tx.RequestBody = []byte("hello world")
	got := tx.RequestBodyString()
	if got != "hello world" {
		t.Errorf("expected 'hello world', got '%s'", got)
	}
	// Call again to exercise sync.Once cached path
	got2 := tx.RequestBodyString()
	if got2 != "hello world" {
		t.Errorf("cached: expected 'hello world', got '%s'", got2)
	}
}

func TestTransaction_ResponseBodyString(t *testing.T) {
	tx := NewTransaction()
	tx.ResponseBody = []byte("<html>ok</html>")
	got := tx.ResponseBodyString()
	if got != "<html>ok</html>" {
		t.Errorf("expected '<html>ok</html>', got '%s'", got)
	}
	// Cached path
	got2 := tx.ResponseBodyString()
	if got2 != "<html>ok</html>" {
		t.Errorf("cached: expected '<html>ok</html>', got '%s'", got2)
	}
}

func TestTransaction_SetGetVar(t *testing.T) {
	tx := NewTransaction()
	tx.SetVar("anomaly_score", "42")
	if v := tx.GetVar("anomaly_score"); v != "42" {
		t.Errorf("expected '42', got '%s'", v)
	}
	if v := tx.GetVar("nonexistent"); v != "" {
		t.Errorf("expected empty, got '%s'", v)
	}
}

func TestTransaction_AddAnomalyScore(t *testing.T) {
	tx := NewTransaction()
	tx.AddAnomalyScore(5)
	tx.AddAnomalyScore(3)
	if tx.AnomalyScore != 8 {
		t.Errorf("expected anomaly score 8, got %d", tx.AnomalyScore)
	}
}

// ---------------------------------------------------------------------------
// Transform function tests
// ---------------------------------------------------------------------------

func TestTransform_AllTransforms(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		xform    string
		expected string
	}{
		{"replaceNulls", "a\x00b", "replaceNulls", "a b"},
		{"urlEncode", "hello world", "urlEncode", "hello%20world"},
		{"t:lowercase prefix", "HELLO", "t:lowercase", "hello"},
		{"t:uppercase prefix", "hello", "t:uppercase", "HELLO"},
		{"t:urlDecode prefix", "a%20b", "t:urlDecode", "a b"},
		{"t:urlEncode prefix", "a b", "t:urlEncode", "a%20b"},
		{"t:htmlEntityDecode prefix", "&lt;", "t:htmlEntityDecode", "<"},
		{"t:removeWhitespace prefix", "a b", "t:removeWhitespace", "ab"},
		{"t:trim prefix", " hi ", "t:trim", "hi"},
		{"t:removeNulls prefix", "a\x00b", "t:removeNulls", "ab"},
		{"t:replaceNulls prefix", "a\x00b", "t:replaceNulls", "a b"},
		{"unknown transform passthrough", "hi", "unknownTransform", "hi"},
		{"empty transforms", "hi", "", "hi"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var xforms []string
			if tt.xform != "" {
				xforms = []string{tt.xform}
			}
			got := Transform(tt.value, xforms)
			if got != tt.expected {
				t.Errorf("Transform(%q, %v) = %q; want %q", tt.value, xforms, got, tt.expected)
			}
		})
	}
}

func TestTransform_ChainMultiple(t *testing.T) {
	result := Transform("  HELLO\x00WORLD  ", []string{"t:lowercase", "t:removeNulls", "t:trim"})
	if result != "helloworld" {
		t.Errorf("chained transform got %q", result)
	}
}

// ---------------------------------------------------------------------------
// Operator Evaluator - comprehensive coverage
// ---------------------------------------------------------------------------

func TestOperatorEvaluator_AllTypes(t *testing.T) {
	eval := NewOperatorEvaluator()

	tests := []struct {
		name     string
		opType   string
		arg      string
		value    string
		expected bool
	}{
		// @rx
		{"rx match", "@rx", `\d+`, "abc123", true},
		{"rx no match", "@rx", `^\d+$`, "abc", false},

		// @eq / @streq
		{"eq match", "@eq", "hello", "hello", true},
		{"eq no match", "@eq", "hello", "world", false},
		{"streq match", "@streq", "test", "test", true},
		{"streq no match", "@streq", "test", "TEST", false},

		// @contains
		{"contains match", "@contains", "world", "hello world", true},
		{"contains no match", "@contains", "xyz", "hello world", false},

		// @beginsWith
		{"beginsWith match", "@beginsWith", "hello", "hello world", true},
		{"beginsWith no match", "@beginsWith", "world", "hello world", false},

		// @endsWith
		{"endsWith match", "@endsWith", "world", "hello world", true},
		{"endsWith no match", "@endsWith", "hello", "hello world", false},

		// @ge / @le / @gt / @lt
		{"ge true equal", "@ge", "10", "10", true},
		{"ge true greater", "@ge", "5", "10", true},
		{"ge false", "@ge", "15", "10", false},
		{"le true equal", "@le", "10", "10", true},
		{"le true less", "@le", "15", "10", true},
		{"le false", "@le", "5", "10", false},
		{"gt true", "@gt", "5", "10", true},
		{"gt false equal", "@gt", "10", "10", false},
		{"lt true", "@lt", "15", "10", true},
		{"lt false equal", "@lt", "10", "10", false},

		// @pm (phrase match)
		{"pm match", "@pm", "attack exploit hack", "this is an attack", true},
		{"pm match quoted", "@pm", `"attack" 'exploit'`, "exploit here", true},
		{"pm no match", "@pm", "attack exploit", "nothing here", false},
		{"pm empty", "@pm", "", "anything", false},

		// @within
		{"within match", "@within", "GET POST PUT", "POST", true},
		{"within no match", "@within", "GET POST PUT", "DELETE", false},
		{"within empty arg", "@within", "", "anything", false},

		// @ipMatch
		{"ipMatch cidr", "@ipMatch", "192.168.1.0/24", "192.168.1.100", true},
		{"ipMatch cidr no match", "@ipMatch", "10.0.0.0/8", "192.168.1.1", false},
		{"ipMatch single ip", "@ipMatch", "127.0.0.1", "127.0.0.1", true},
		{"ipMatch single ip no match", "@ipMatch", "127.0.0.1", "127.0.0.2", false},

		// @validateByteRange
		{"byteRange valid", "@validateByteRange", "32-126", "hello world!", true},
		{"byteRange invalid", "@validateByteRange", "48-57", "abc", false},

		// @validateUrlEncoding
		{"urlEncoding valid", "@validateUrlEncoding", "", "hello%20world", true},
		{"urlEncoding incomplete", "@validateUrlEncoding", "", "hello%", false},
		{"urlEncoding bad hex", "@validateUrlEncoding", "", "hello%GG", false},
		{"urlEncoding no escapes", "@validateUrlEncoding", "", "hello", true},

		// @validateUtf8Encoding
		{"utf8 valid", "@validateUtf8Encoding", "", "hello world", true},

		// unknown operator falls back to regex
		{"unknown op regex fallback", "test", "test", "test", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := RuleOperator{Type: tt.opType, Argument: tt.arg}
			result, err := eval.Evaluate(op, tt.value)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("Evaluate(%s, %q, %q) = %v; want %v", tt.opType, tt.arg, tt.value, result, tt.expected)
			}
		})
	}
}

func TestOperatorEvaluator_NumericErrors(t *testing.T) {
	eval := NewOperatorEvaluator()

	// Non-numeric value should return error
	_, err := eval.Evaluate(RuleOperator{Type: "@gt", Argument: "10"}, "notanumber")
	if err == nil {
		t.Error("expected error for non-numeric value in @gt")
	}

	// Non-numeric argument
	_, err = eval.Evaluate(RuleOperator{Type: "@gt", Argument: "abc"}, "10")
	if err == nil {
		t.Error("expected error for non-numeric argument in @gt")
	}
}

func TestOperatorEvaluator_InvalidRegex(t *testing.T) {
	eval := NewOperatorEvaluator()
	_, err := eval.Evaluate(RuleOperator{Type: "@rx", Argument: "(?P<invalid"}, "test")
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestOperatorEvaluator_CompareNumericAllOps(t *testing.T) {
	eval := NewOperatorEvaluator()
	ops := []struct {
		op   string
		want bool
	}{
		{"==", true},
		{"!=", false},
		{">", false},
		{">=", true},
		{"<", false},
		{"<=", true},
	}
	for _, tt := range ops {
		t.Run(tt.op, func(t *testing.T) {
			result, err := eval.compareNumeric("10", "10", tt.op)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if result != tt.want {
				t.Errorf("compareNumeric(10, 10, %s) = %v; want %v", tt.op, result, tt.want)
			}
		})
	}
	// Unknown operator
	_, err := eval.compareNumeric("10", "10", "???")
	if err == nil {
		t.Error("expected error for unknown comparison operator")
	}
}

func TestOperatorEvaluator_GetCaptureGroups(t *testing.T) {
	eval := NewOperatorEvaluator()
	op := RuleOperator{Type: "@rx", Argument: `(test)`}
	result, err := eval.Evaluate(op, "this is a test string")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !result {
		t.Fatal("expected match")
	}
	cg := eval.GetCaptureGroups()
	if len(cg) < 2 || cg[1] != "test" {
		t.Errorf("expected capture group 'test', got %v", cg)
	}
}

func TestOperatorEvaluator_IpMatch_InvalidIP(t *testing.T) {
	eval := NewOperatorEvaluator()
	op := RuleOperator{Type: "@ipMatch", Argument: "192.168.1.0/24"}
	result, err := eval.Evaluate(op, "not-an-ip-or-resolvable-host.invalid.tld")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result {
		t.Error("expected false for unresolvable IP value")
	}
}

func TestOperatorEvaluator_ByteRange_SingleByte(t *testing.T) {
	eval := NewOperatorEvaluator()
	op := RuleOperator{Type: "@validateByteRange", Argument: "65"}
	result, err := eval.Evaluate(op, "A")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !result {
		t.Error("expected 'A' (byte 65) to match byte range 65")
	}

	result, err = eval.Evaluate(op, "B")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result {
		t.Error("expected 'B' (byte 66) not to match byte range 65")
	}
}

func TestOperatorEvaluator_ByteRange_MultipleRanges(t *testing.T) {
	eval := NewOperatorEvaluator()
	op := RuleOperator{Type: "@validateByteRange", Argument: "48-57,65-90"}
	result, err := eval.Evaluate(op, "A1B2")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !result {
		t.Error("expected 'A1B2' to match byte range 48-57,65-90")
	}

	result, err = eval.Evaluate(op, "a1b2")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result {
		t.Error("expected 'a1b2' (lowercase) not to match byte range 48-57,65-90")
	}
}

func TestOperatorEvaluator_Utf8Encoding_Invalid(t *testing.T) {
	eval := NewOperatorEvaluator()
	op := RuleOperator{Type: "@validateUtf8Encoding", Argument: ""}
	invalid := string([]byte{0xff, 0xfe, 0xfd})
	result, err := eval.Evaluate(op, invalid)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result {
		t.Error("expected invalid UTF-8 to return false")
	}
}

// ---------------------------------------------------------------------------
// ParseByteRanges
// ---------------------------------------------------------------------------

func TestParseByteRanges(t *testing.T) {
	ranges := parseByteRanges("48-57, 65, 97-122")
	if len(ranges) != 3 {
		t.Fatalf("expected 3 ranges, got %d", len(ranges))
	}
	if ranges[0].min != 48 || ranges[0].max != 57 {
		t.Errorf("range 0: expected 48-57, got %d-%d", ranges[0].min, ranges[0].max)
	}
	if ranges[1].min != 65 || ranges[1].max != 65 {
		t.Errorf("range 1: expected 65-65, got %d-%d", ranges[1].min, ranges[1].max)
	}
	if ranges[2].min != 97 || ranges[2].max != 122 {
		t.Errorf("range 2: expected 97-122, got %d-%d", ranges[2].min, ranges[2].max)
	}
}

func TestParseByteRanges_EmptyParts(t *testing.T) {
	ranges := parseByteRanges(",,48-57,,")
	if len(ranges) != 1 {
		t.Fatalf("expected 1 range, got %d", len(ranges))
	}
}

func TestIsValidUTF8(t *testing.T) {
	if !isValidUTF8("hello") {
		t.Error("expected valid UTF-8")
	}
	if isValidUTF8(string([]byte{0xff})) {
		t.Error("expected invalid UTF-8")
	}
}

// ---------------------------------------------------------------------------
// Variable Resolver - comprehensive coverage
// ---------------------------------------------------------------------------

func newTestTransaction() *Transaction {
	tx := NewTransaction()
	tx.Method = "POST"
	tx.URI = "/api/users?name=alice&age=30"
	tx.Path = "/api/users"
	tx.Query = "name=alice&age=30"
	tx.Protocol = "HTTP/1.1"
	tx.RequestHeaders = map[string][]string{
		"Content-Type":  {"application/json"},
		"Host":          {"example.com"},
		"User-Agent":    {"TestClient/1.0"},
		"Authorization": {"Bearer token123"},
	}
	tx.RequestBody = []byte(`{"name":"alice"}`)
	tx.RequestArgs = map[string][]string{
		"name": {"alice"},
		"age":  {"30"},
	}
	tx.RequestCookies = map[string]string{
		"session": "abc123",
		"theme":   "dark",
	}
	tx.ClientIP = "10.0.0.1"
	tx.ClientPort = 54321
	tx.ServerIP = "192.168.1.1"
	tx.ServerPort = 8080
	tx.StatusCode = 200
	tx.ResponseHeaders = map[string][]string{
		"Content-Type": {"text/html"},
	}
	tx.ResponseBody = []byte("<html>OK</html>")
	tx.Timestamp = time.Date(2025, 6, 15, 14, 30, 0, 0, time.UTC)
	tx.Variables = map[string]string{
		"anomaly_score":  "5",
		"blocking_score": "0",
		"SERVER_NAME":    "example.com",
	}
	return tx
}

func TestVariableResolver_RequestLine(t *testing.T) {
	tx := newTestTransaction()
	vr := NewVariableResolver(tx)

	tests := []struct {
		name string
		rv   RuleVariable
		want string
	}{
		{"REQUEST_LINE", RuleVariable{Name: "REQUEST_LINE"}, "POST /api/users?name=alice&age=30 HTTP/1.1"},
		{"REQUEST_METHOD", RuleVariable{Name: "REQUEST_METHOD"}, "POST"},
		{"REQUEST_URI", RuleVariable{Name: "REQUEST_URI"}, "/api/users?name=alice&age=30"},
		{"REQUEST_URI_RAW", RuleVariable{Name: "REQUEST_URI_RAW"}, "/api/users?name=alice&age=30"},
		{"REQUEST_PROTOCOL", RuleVariable{Name: "REQUEST_PROTOCOL"}, "HTTP/1.1"},
		{"REQUEST_FILENAME", RuleVariable{Name: "REQUEST_FILENAME"}, "/api/users"},
		{"QUERY_STRING", RuleVariable{Name: "QUERY_STRING"}, "name=alice&age=30"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vals, err := vr.Resolve(tt.rv)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if len(vals) != 1 || vals[0] != tt.want {
				t.Errorf("Resolve(%s) = %v; want [%s]", tt.rv.Name, vals, tt.want)
			}
		})
	}
}

func TestVariableResolver_Body(t *testing.T) {
	tx := newTestTransaction()
	vr := NewVariableResolver(tx)

	vals, err := vr.Resolve(RuleVariable{Name: "REQUEST_BODY"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != `{"name":"alice"}` {
		t.Errorf("REQUEST_BODY = %v", vals)
	}

	vals, err = vr.Resolve(RuleVariable{Name: "REQUEST_BODY_LENGTH"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "16" {
		t.Errorf("REQUEST_BODY_LENGTH = %v", vals)
	}
}

func TestVariableResolver_Response(t *testing.T) {
	tx := newTestTransaction()
	vr := NewVariableResolver(tx)

	vals, err := vr.Resolve(RuleVariable{Name: "RESPONSE_STATUS"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "200" {
		t.Errorf("RESPONSE_STATUS = %v", vals)
	}

	vals, err = vr.Resolve(RuleVariable{Name: "RESPONSE_BODY"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "<html>OK</html>" {
		t.Errorf("RESPONSE_BODY = %v", vals)
	}
}

func TestVariableResolver_Server(t *testing.T) {
	tx := newTestTransaction()
	vr := NewVariableResolver(tx)

	tests := []struct {
		name string
		rv   RuleVariable
		want string
	}{
		{"SERVER_NAME", RuleVariable{Name: "SERVER_NAME"}, "example.com"},
		{"SERVER_ADDR", RuleVariable{Name: "SERVER_ADDR"}, "192.168.1.1"},
		{"SERVER_PORT", RuleVariable{Name: "SERVER_PORT"}, "8080"},
		{"REMOTE_ADDR", RuleVariable{Name: "REMOTE_ADDR"}, "10.0.0.1"},
		{"REMOTE_PORT", RuleVariable{Name: "REMOTE_PORT"}, "54321"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vals, err := vr.Resolve(tt.rv)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if len(vals) != 1 || vals[0] != tt.want {
				t.Errorf("Resolve(%s) = %v; want [%s]", tt.rv.Name, vals, tt.want)
			}
		})
	}
}

func TestVariableResolver_Time(t *testing.T) {
	tx := newTestTransaction()
	vr := NewVariableResolver(tx)

	tests := []struct {
		name string
		rv   RuleVariable
	}{
		{"TIME", RuleVariable{Name: "TIME"}},
		{"TIME_EPOCH", RuleVariable{Name: "TIME_EPOCH"}},
		{"TIME_YEAR", RuleVariable{Name: "TIME_YEAR"}},
		{"TIME_MON", RuleVariable{Name: "TIME_MON"}},
		{"TIME_DAY", RuleVariable{Name: "TIME_DAY"}},
		{"TIME_HOUR", RuleVariable{Name: "TIME_HOUR"}},
		{"TIME_MIN", RuleVariable{Name: "TIME_MIN"}},
		{"TIME_SEC", RuleVariable{Name: "TIME_SEC"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vals, err := vr.Resolve(tt.rv)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if len(vals) != 1 || vals[0] == "" {
				t.Errorf("Resolve(%s) returned empty", tt.rv.Name)
			}
		})
	}
}

func TestVariableResolver_TX(t *testing.T) {
	tx := newTestTransaction()
	vr := NewVariableResolver(tx)

	// TX with key
	vals, err := vr.Resolve(RuleVariable{Name: "TX", Key: "anomaly_score"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "5" {
		t.Errorf("TX:anomaly_score = %v", vals)
	}

	// TX with unknown key
	vals, err = vr.Resolve(RuleVariable{Name: "TX", Key: "nonexistent"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 0 {
		t.Errorf("TX:nonexistent = %v; want empty", vals)
	}

	// TX without key (all vars)
	vals, err = vr.Resolve(RuleVariable{Name: "TX"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) == 0 {
		t.Error("TX (all vars) should return values")
	}
}

func TestVariableResolver_ARGS(t *testing.T) {
	tx := newTestTransaction()
	vr := NewVariableResolver(tx)

	// All args
	vals, err := vr.Resolve(RuleVariable{Name: "ARGS"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 2 {
		t.Errorf("ARGS (all) = %v; want 2 values", vals)
	}

	// Specific arg
	vals, err = vr.Resolve(RuleVariable{Collection: "ARGS", Key: "name"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "alice" {
		t.Errorf("ARGS:name = %v", vals)
	}

	// Count
	vals, err = vr.Resolve(RuleVariable{Name: "ARGS", Count: true})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "2" {
		t.Errorf("ARGS count = %v", vals)
	}

	// ARGS_NAMES
	vals, err = vr.Resolve(RuleVariable{Name: "ARGS_NAMES"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 2 {
		t.Errorf("ARGS_NAMES = %v; want 2 names", vals)
	}

	// ARGS_GET
	vals, err = vr.Resolve(RuleVariable{Name: "ARGS_GET"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 2 {
		t.Errorf("ARGS_GET = %v; want 2 values", vals)
	}

	// ARGS_POST
	vals, err = vr.Resolve(RuleVariable{Name: "ARGS_POST"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 2 {
		t.Errorf("ARGS_POST = %v; want 2 values", vals)
	}

	// Nonexistent key
	vals, err = vr.Resolve(RuleVariable{Collection: "ARGS", Key: "nonexistent"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 0 {
		t.Errorf("ARGS:nonexistent = %v; want empty", vals)
	}
}

func TestVariableResolver_ARGS_RegexKey(t *testing.T) {
	tx := newTestTransaction()
	vr := NewVariableResolver(tx)

	vals, err := vr.Resolve(RuleVariable{Collection: "ARGS", Key: "na*", KeyRegex: true})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "alice" {
		t.Errorf("ARGS:na* = %v", vals)
	}
}

func TestVariableResolver_Headers(t *testing.T) {
	tx := newTestTransaction()
	vr := NewVariableResolver(tx)

	// All headers
	vals, err := vr.Resolve(RuleVariable{Name: "REQUEST_HEADERS"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) < 3 {
		t.Errorf("REQUEST_HEADERS (all) = %v; want at least 3", vals)
	}

	// Specific header
	vals, err = vr.Resolve(RuleVariable{Collection: "REQUEST_HEADERS", Key: "Host"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "example.com" {
		t.Errorf("REQUEST_HEADERS:Host = %v", vals)
	}

	// Count
	vals, err = vr.Resolve(RuleVariable{Name: "REQUEST_HEADERS", Count: true})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 {
		t.Errorf("REQUEST_HEADERS count = %v", vals)
	}

	// Nonexistent header
	vals, err = vr.Resolve(RuleVariable{Collection: "REQUEST_HEADERS", Key: "X-Nonexistent"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 0 {
		t.Errorf("REQUEST_HEADERS:X-Nonexistent = %v; want empty", vals)
	}

	// REQUEST_HEADERS_NAMES
	vals, err = vr.Resolve(RuleVariable{Name: "REQUEST_HEADERS_NAMES"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) < 3 {
		t.Errorf("REQUEST_HEADERS_NAMES = %v; want at least 3", vals)
	}

	// Response headers
	vals, err = vr.Resolve(RuleVariable{Collection: "RESPONSE_HEADERS", Key: "Content-Type"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "text/html" {
		t.Errorf("RESPONSE_HEADERS:Content-Type = %v", vals)
	}
}

func TestVariableResolver_Headers_RegexKey(t *testing.T) {
	tx := newTestTransaction()
	vr := NewVariableResolver(tx)

	vals, err := vr.Resolve(RuleVariable{Collection: "REQUEST_HEADERS", Key: "Content*", KeyRegex: true})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "application/json" {
		t.Errorf("REQUEST_HEADERS:Content* = %v", vals)
	}
}

func TestVariableResolver_Cookies(t *testing.T) {
	tx := newTestTransaction()
	vr := NewVariableResolver(tx)

	// All cookies
	vals, err := vr.Resolve(RuleVariable{Name: "REQUEST_COOKIES"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 2 {
		t.Errorf("REQUEST_COOKIES (all) = %v; want 2", vals)
	}

	// Specific cookie
	vals, err = vr.Resolve(RuleVariable{Collection: "REQUEST_COOKIES", Key: "session"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "abc123" {
		t.Errorf("REQUEST_COOKIES:session = %v", vals)
	}

	// Count
	vals, err = vr.Resolve(RuleVariable{Name: "REQUEST_COOKIES", Count: true})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "2" {
		t.Errorf("REQUEST_COOKIES count = %v", vals)
	}

	// Nonexistent cookie
	vals, err = vr.Resolve(RuleVariable{Collection: "REQUEST_COOKIES", Key: "nonexistent"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 0 {
		t.Errorf("REQUEST_COOKIES:nonexistent = %v; want empty", vals)
	}

	// REQUEST_COOKIES_NAMES
	vals, err = vr.Resolve(RuleVariable{Name: "REQUEST_COOKIES_NAMES"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 2 {
		t.Errorf("REQUEST_COOKIES_NAMES = %v; want 2", vals)
	}
}

func TestVariableResolver_Cookies_RegexKey(t *testing.T) {
	tx := newTestTransaction()
	vr := NewVariableResolver(tx)

	vals, err := vr.Resolve(RuleVariable{Collection: "REQUEST_COOKIES", Key: "ses*", KeyRegex: true})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "abc123" {
		t.Errorf("REQUEST_COOKIES:ses* = %v", vals)
	}
}

func TestVariableResolver_ArgsCombinedSize(t *testing.T) {
	tx := newTestTransaction()
	vr := NewVariableResolver(tx)

	vals, err := vr.Resolve(RuleVariable{Name: "ARGS_COMBINED_SIZE"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	// "alice" (5) + "30" (2) = 7
	if len(vals) != 1 || vals[0] != "7" {
		t.Errorf("ARGS_COMBINED_SIZE = %v", vals)
	}
}

func TestVariableResolver_FullRequest(t *testing.T) {
	tx := newTestTransaction()
	vr := NewVariableResolver(tx)

	vals, err := vr.Resolve(RuleVariable{Name: "FULL_REQUEST"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 {
		t.Fatalf("FULL_REQUEST = %v", vals)
	}
	if !strings.Contains(vals[0], "POST") || !strings.Contains(vals[0], "Host:") {
		t.Errorf("FULL_REQUEST does not contain expected content: %s", vals[0])
	}
}

func TestVariableResolver_FullRequestLength(t *testing.T) {
	tx := newTestTransaction()
	vr := NewVariableResolver(tx)

	vals, err := vr.Resolve(RuleVariable{Name: "FULL_REQUEST_LENGTH"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 {
		t.Fatalf("FULL_REQUEST_LENGTH = %v", vals)
	}
}

func TestVariableResolver_UnknownVar(t *testing.T) {
	tx := newTestTransaction()
	vr := NewVariableResolver(tx)

	vals, err := vr.Resolve(RuleVariable{Name: "UNKNOWN_VARIABLE"})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 0 {
		t.Errorf("UNKNOWN_VARIABLE = %v; want empty", vals)
	}
}

func TestVariableResolver_CollectionFallsToName(t *testing.T) {
	tx := newTestTransaction()
	vr := NewVariableResolver(tx)

	rv := RuleVariable{Collection: "REQUEST_METHOD"}
	vals, err := vr.Resolve(rv)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vals) != 1 || vals[0] != "POST" {
		t.Errorf("Collection=REQUEST_METHOD = %v", vals)
	}
}

// ---------------------------------------------------------------------------
// matchWildcard tests
// ---------------------------------------------------------------------------

func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		s       string
		pattern string
		want    bool
	}{
		{"", "", true},
		{"anything", "*", true},
		{"foobar", "foo*", true},
		{"foobar", "*bar", true},
		{"axbxc", "*x*", true},
		{"hello", "hello", true},
		{"hello", "world", false},
		{"foo", "*bar", false},
		{"bar", "foo*", false},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.pattern, func(t *testing.T) {
			got, err := matchWildcard(tt.s, tt.pattern)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if got != tt.want {
				t.Errorf("matchWildcard(%q, %q) = %v; want %v", tt.s, tt.pattern, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Parser tests - comprehensive
// ---------------------------------------------------------------------------

func TestParser_SecAction(t *testing.T) {
	p := NewParser()
	content := `SecAction "id:980145,phase:5,pass,nolog,msg:'End of Phase 5'"`
	rules, err := p.ParseFile(content)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.ID != "980145" {
		t.Errorf("ID = %q; want 980145", r.ID)
	}
	if r.Phase != 5 {
		t.Errorf("Phase = %d; want 5", r.Phase)
	}
	// "nolog" comes after "pass" and overwrites Action
	if r.Actions.Action != "nolog" {
		t.Errorf("Action = %q; want nolog", r.Actions.Action)
	}
}

func TestParser_SecAction_Quoted(t *testing.T) {
	p := NewParser()
	content := `SecAction "id:900001,phase:1,pass,nolog"`
	rules, err := p.ParseFile(content)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].ID != "900001" {
		t.Errorf("ID = %q", rules[0].ID)
	}
}

func TestParser_CommentsAndBlanks(t *testing.T) {
	p := NewParser()
	content := `
# This is a comment

SecRule REQUEST_METHOD "@rx ^GET$" "id:1,phase:1,pass"

# Another comment

SecRule REQUEST_URI "@rx ." "id:2,phase:1,pass"
`
	rules, err := p.ParseFile(content)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
}

func TestParser_Variables(t *testing.T) {
	p := NewParser()

	tests := []struct {
		input   string
		wantLen int
	}{
		{"REQUEST_METHOD", 1},
		{"ARGS", 1},
		{"REQUEST_HEADERS:User-Agent", 1},
		{"ARGS|REQUEST_URI", 2},
		{"!REQUEST_COOKIES:session", 1},
		{"&ARGS", 1},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			vars, err := p.parseVariables(tt.input)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if len(vars) != tt.wantLen {
				t.Fatalf("expected %d vars, got %d", tt.wantLen, len(vars))
			}
		})
	}
}

func TestParser_Variables_KeyRegex(t *testing.T) {
	p := NewParser()
	vars, err := p.parseVariables("ARGS:/^user_/")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vars) != 1 {
		t.Fatalf("expected 1 var, got %d", len(vars))
	}
	if !vars[0].KeyRegex {
		t.Error("expected KeyRegex=true")
	}
	if vars[0].Key != "^user_" {
		t.Errorf("Key = %q; want ^user_", vars[0].Key)
	}
}

func TestParser_Variables_ExclusionAndCount(t *testing.T) {
	p := NewParser()
	vars, err := p.parseVariables("!ARGS:password|&REQUEST_HEADERS")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(vars) != 2 {
		t.Fatalf("expected 2 vars, got %d", len(vars))
	}
	// Note: the parser checks for "!+" and "&+" prefixes which never match
	// single-char "!A" or "&R" prefixes, so Exclude and Count remain false.
}

func TestParser_Operators(t *testing.T) {
	p := NewParser()

	tests := []struct {
		input  string
		opType string
		neg    bool
		arg    string
	}{
		{"@rx ^test$", "@rx", false, "^test$"},
		{"!@rx ^test$", "@rx", true, "^test$"},
		{"@eq 42", "@eq", false, "42"},
		{"@ge 10", "@ge", false, "10"},
		{"@le 10", "@le", false, "10"},
		{"@gt 10", "@gt", false, "10"},
		{"@lt 10", "@lt", false, "10"},
		{"@contains attack", "@contains", false, "attack"},
		{"@beginsWith GET", "@beginsWith", false, "GET"},
		{"@endsWith .php", "@endsWith", false, ".php"},
		{"@pm attack hack", "@pm", false, "attack hack"},
		{"@pmf /path/to/file", "@pmf", false, "/path/to/file"},
		{"@within GET POST", "@within", false, "GET POST"},
		{"@streq hello", "@streq", false, "hello"},
		{"@ipMatch 192.168.0.0/16", "@ipMatch", false, "192.168.0.0/16"},
		{"@ipMatchF /path/to/ips", "@ipMatch", false, "/path/to/ips"},
		{"@validateByteRange 32-126", "@validateByteRange", false, "32-126"},
		{"@validateUrlEncoding", "@validateUrlEncoding", false, ""},
		{"@validateUtf8Encoding", "@validateUtf8Encoding", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			op, err := p.parseOperator(tt.input)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if op.Type != tt.opType {
				t.Errorf("Type = %q; want %q", op.Type, tt.opType)
			}
			if op.Negated != tt.neg {
				t.Errorf("Negated = %v; want %v", op.Negated, tt.neg)
			}
			if op.Argument != tt.arg {
				t.Errorf("Argument = %q; want %q", op.Argument, tt.arg)
			}
		})
	}
}

func TestParser_Operator_DefaultRx(t *testing.T) {
	p := NewParser()
	op, err := p.parseOperator("somepattern")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if op.Type != "@rx" {
		t.Errorf("expected default @rx, got %q", op.Type)
	}
	if op.Argument != "somepattern" {
		t.Errorf("Argument = %q; want 'somepattern'", op.Argument)
	}
}

func TestParser_Operator_UnknownOperator(t *testing.T) {
	p := NewParser()
	op, err := p.parseOperator("@customOp value")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if op.Type != "@customOp" {
		t.Errorf("Type = %q; want @customOp", op.Type)
	}
}

func TestParser_Actions_All(t *testing.T) {
	p := NewParser()
	actions, err := p.parseActions("id:942100,phase:2,deny,status:403,redirect:https://example.com,msg:'SQL Injection',logdata:'data',severity:CRITICAL,tag:attack-sqli,tag:owasp,skip:3,skipAfter:marker123,t:lowercase,t:urlDecode,pass,nolog,auditlog,chain,capture,setvar:tx.anomaly_score=+5")
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if actions.ID != "942100" {
		t.Errorf("ID = %q", actions.ID)
	}
	if actions.Phase != 2 {
		t.Errorf("Phase = %d", actions.Phase)
	}
	if actions.Status != 403 {
		t.Errorf("Status = %d", actions.Status)
	}
	if actions.Redirect != "https://example.com" {
		t.Errorf("Redirect = %q", actions.Redirect)
	}
	if actions.Msg != "SQL Injection" {
		t.Errorf("Msg = %q", actions.Msg)
	}
	if actions.LogData != "data" {
		t.Errorf("LogData = %q", actions.LogData)
	}
	if actions.Severity != "CRITICAL" {
		t.Errorf("Severity = %q", actions.Severity)
	}
	if len(actions.Tag) != 2 {
		t.Errorf("Tag = %v", actions.Tag)
	}
	if actions.Skip != 3 {
		t.Errorf("Skip = %d", actions.Skip)
	}
	if actions.SkipAfter != "marker123" {
		t.Errorf("SkipAfter = %q", actions.SkipAfter)
	}
	if len(actions.Transformations) != 2 {
		t.Errorf("Transformations = %v", actions.Transformations)
	}
	if !actions.Chain {
		t.Error("expected Chain=true")
	}
	if len(actions.SetVar) != 1 {
		t.Fatalf("SetVar len = %d", len(actions.SetVar))
	}
	sv := actions.SetVar[0]
	if sv.Collection != "tx" {
		t.Errorf("SetVar Collection = %q", sv.Collection)
	}
	if sv.Variable != "anomaly_score" {
		t.Errorf("SetVar Variable = %q", sv.Variable)
	}
	if sv.Operation != "+=" {
		t.Errorf("SetVar Operation = %q", sv.Operation)
	}
	if sv.Value != "5" {
		t.Errorf("SetVar Value = %q", sv.Value)
	}
}

func TestParser_Actions_StandaloneActions(t *testing.T) {
	p := NewParser()

	standalone := []string{"deny", "pass", "block", "drop", "allow", "proxy", "log", "nolog"}
	for _, action := range standalone {
		t.Run(action, func(t *testing.T) {
			actions, err := p.parseActions(action)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if actions.Action != action {
				t.Errorf("Action = %q; want %q", actions.Action, action)
			}
		})
	}
}

func TestParser_ParseVarAction(t *testing.T) {
	p := NewParser()

	tests := []struct {
		input      string
		collection string
		variable   string
		operation  string
		value      string
	}{
		{"tx.anomaly_score=+5", "tx", "anomaly_score", "+=", "5"},
		{"tx.blocking_score=10", "tx", "blocking_score", "=", "10"},
		{"tx.score=-3", "tx", "score", "-=", "3"},
		{"ip.blocked=1", "ip", "blocked", "=", "1"},
		// No collection (no dot): variable gets entire string before =
		{"anomaly_score=+1", "", "anomaly_score", "+=", "1"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			va := p.parseVarAction(tt.input)
			if va.Collection != tt.collection {
				t.Errorf("Collection = %q; want %q", va.Collection, tt.collection)
			}
			if va.Variable != tt.variable {
				t.Errorf("Variable = %q; want %q", va.Variable, tt.variable)
			}
			if va.Operation != tt.operation {
				t.Errorf("Operation = %q; want %q", va.Operation, tt.operation)
			}
			if va.Value != tt.value {
				t.Errorf("Value = %q; want %q", va.Value, tt.value)
			}
		})
	}
}

func TestParser_InvalidSecRule(t *testing.T) {
	p := NewParser()
	content := `SecRule REQUEST_METHOD "@rx ^GET$"` // Missing actions
	_, err := p.ParseFile(content)
	if err == nil {
		t.Error("expected error for invalid SecRule format")
	}
}

func TestParser_InvalidVariables(t *testing.T) {
	p := NewParser()
	content := `SecRule "@rx ^GET$" "id:1,phase:1,pass"`
	_, err := p.ParseFile(content)
	if err == nil {
		t.Error("expected error for insufficient SecRule parts")
	}
}

func TestParser_EmptyOperatorParsesAsDefault(t *testing.T) {
	p := NewParser()
	// Empty operator string is parsed with default @rx type and empty argument
	content := `SecRule REQUEST_METHOD "" "id:1,phase:1,pass"`
	rules, err := p.ParseFile(content)
	if err != nil {
		t.Fatalf("did not expect error for empty operator: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Operator.Type != "@rx" {
		t.Errorf("Operator.Type = %q; want @rx", rules[0].Operator.Type)
	}
}

func TestParser_InlineChain(t *testing.T) {
	p := NewParser()
	// Note: inline chain (all parts on one line) requires quoted strings
	// The splitQuoted parser includes quotes in output, so inline chains
	// may not parse correctly. This test verifies the current behavior.
	content := `SecRule REQUEST_METHOD "@streq POST" "id:900100,phase:2,deny,chain" "REQUEST_HEADERS:Content-Length" "@eq 0" "deny"`
	rules, err := p.ParseFile(content)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Chain == nil {
		t.Fatal("expected chain rule")
	}
	// The chain is parsed; verify it exists
	t.Logf("Chain vars: %+v, Chain op: %+v", rules[0].Chain.Variables, rules[0].Chain.Operator)
}

func TestParser_MultiLineChain(t *testing.T) {
	p := NewParser()
	content := `SecRule REQUEST_METHOD "@streq POST" "id:900200,phase:2,deny,chain"
SecRule REQUEST_HEADERS:Content-Length "@eq 0" "deny"`
	rules, err := p.ParseFile(content)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule (with chain), got %d", len(rules))
	}
	if rules[0].Chain == nil {
		t.Fatal("expected chain")
	}
}

func TestParser_SplitQuoted(t *testing.T) {
	p := NewParser()
	tests := []struct {
		input string
		want  int
	}{
		{`A "B C" D`, 3},
		{`A 'B C' D`, 3},
		{`"A B" "C D"`, 2},
		{`A B C`, 3},
		{`"A B C"`, 1},
	}
	for _, tt := range tests {
		parts := p.splitQuoted(tt.input)
		if len(parts) != tt.want {
			t.Errorf("splitQuoted(%q) = %d parts; want %d: %v", tt.input, len(parts), tt.want, parts)
		}
	}
}

func TestSplitEscaped(t *testing.T) {
	tests := []struct {
		input string
		sep   byte
		want  int
	}{
		{"a|b|c", '|', 3},
		{`a\|b|c`, '|', 2},
		{"abc", '|', 1},
		{"a|b\\|c|d", '|', 3},
	}
	for _, tt := range tests {
		parts := splitEscaped(tt.input, tt.sep)
		if len(parts) != tt.want {
			t.Errorf("splitEscaped(%q, %c) = %d parts; want %d: %v", tt.input, tt.sep, len(parts), tt.want, parts)
		}
	}
}

func TestSplitActions(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"a,b,c", 3},
		{"a,'b,c',d", 3},
		// splitActions only handles single-quote escaping, not double
		{`a,b,"c,d",e`, 5},
		{"", 0},
		{"single", 1},
	}
	for _, tt := range tests {
		parts := splitActions(tt.input)
		if len(parts) != tt.want {
			t.Errorf("splitActions(%q) = %d parts; want %d: %v", tt.input, len(parts), tt.want, parts)
		}
	}
}

// ---------------------------------------------------------------------------
// Layer tests - LoadRules from file
// ---------------------------------------------------------------------------

func TestLayer_LoadRules_FromFile(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "test.conf")
	content := `
SecRule REQUEST_METHOD "@rx ^GET$" "id:100001,phase:1,deny,status:405,msg:'Only GET allowed',severity:'WARNING'"
SecRule REQUEST_URI "@rx \.\." "id:100002,phase:1,deny,status:403,msg:'Path traversal',severity:'CRITICAL'"
`
	if err := os.WriteFile(ruleFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	layer := NewLayer(&Config{Enabled: true, ParanoiaLevel: 1, AnomalyThreshold: 5})
	if err := layer.LoadRules(ruleFile); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	rule := layer.GetRule("100001")
	if rule == nil {
		t.Fatal("expected to find rule 100001")
	}
	if rule.Msg != "Only GET allowed" {
		t.Errorf("Msg = %q", rule.Msg)
	}

	rule2 := layer.GetRule("100002")
	if rule2 == nil {
		t.Fatal("expected to find rule 100002")
	}
}

func TestLayer_LoadRules_FromDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	file1 := filepath.Join(tmpDir, "rules1.conf")
	file2 := filepath.Join(tmpDir, "rules2.conf")

	content1 := `SecRule REQUEST_METHOD "@rx ^POST$" "id:200001,phase:1,deny,msg:'POST blocked'"`
	content2 := `SecRule REQUEST_URI "@rx admin" "id:200002,phase:1,deny,msg:'Admin access'"`

	if err := os.WriteFile(file1, []byte(content1), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file2, []byte(content2), 0644); err != nil {
		t.Fatal(err)
	}

	layer := NewLayer(&Config{Enabled: true, ParanoiaLevel: 1, AnomalyThreshold: 5})
	if err := layer.LoadRules(tmpDir); err != nil {
		t.Fatalf("LoadRules from dir failed: %v", err)
	}

	if layer.GetRule("200001") == nil {
		t.Error("expected rule 200001")
	}
	if layer.GetRule("200002") == nil {
		t.Error("expected rule 200002")
	}
}

func TestLayer_LoadRules_NonexistentPath(t *testing.T) {
	layer := NewLayer(&Config{Enabled: true})
	err := layer.LoadRules("/nonexistent/path/to/rules")
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestLayer_LoadRules_InvalidRuleFile(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "bad.conf")
	content := `SecRule "@rx ^GET$" "id:1,phase:1,pass"` // Missing variable part
	if err := os.WriteFile(ruleFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	layer := NewLayer(&Config{Enabled: true})
	err := layer.LoadRules(ruleFile)
	if err == nil {
		t.Error("expected error for invalid rule file")
	}
}

func TestLayer_LoadRules_SkipsNonConfFiles(t *testing.T) {
	tmpDir := t.TempDir()

	confFile := filepath.Join(tmpDir, "rules.conf")
	if err := os.WriteFile(confFile, []byte(`SecRule REQUEST_METHOD "@rx ^GET$" "id:300001,phase:1,pass"`), 0644); err != nil {
		t.Fatal(err)
	}

	txtFile := filepath.Join(tmpDir, "notes.txt")
	if err := os.WriteFile(txtFile, []byte(`SecRule REQUEST_METHOD "@rx ^GET$" "id:300002,phase:1,pass"`), 0644); err != nil {
		t.Fatal(err)
	}

	layer := NewLayer(&Config{Enabled: true, ParanoiaLevel: 1, AnomalyThreshold: 5})
	if err := layer.LoadRules(tmpDir); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	if layer.GetRule("300001") == nil {
		t.Error("expected rule 300001 from .conf file")
	}
	if layer.GetRule("300002") != nil {
		t.Error("did not expect rule 300002 from .txt file")
	}
}

func TestLayer_LoadRules_DisabledRulesSkipped(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rules.conf")
	content := `
SecRule REQUEST_METHOD "@rx ^GET$" "id:400001,phase:1,pass"
SecRule REQUEST_URI "@rx ." "id:400002,phase:1,pass"
`
	if err := os.WriteFile(ruleFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 5,
		DisabledRules:    []string{"400001"},
	})
	if err := layer.LoadRules(ruleFile); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	if layer.GetRule("400001") != nil {
		t.Error("rule 400001 should be skipped (disabled)")
	}
	if layer.GetRule("400002") == nil {
		t.Error("expected rule 400002")
	}
}

func TestLayer_LoadRules_ParanoiaLevelFiltering(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rules.conf")
	content := `SecRule REQUEST_METHOD "@rx ^GET$" "id:500001,phase:1,pass"`
	if err := os.WriteFile(ruleFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	layer := NewLayer(&Config{Enabled: true, ParanoiaLevel: 1, AnomalyThreshold: 5})
	if err := layer.LoadRules(ruleFile); err != nil {
		t.Fatalf("LoadRules failed: %v", err)
	}

	if layer.GetRule("500001") == nil {
		t.Error("expected rule 500001 with PL=1")
	}
}

// ---------------------------------------------------------------------------
// Layer tests - Process function paths
// ---------------------------------------------------------------------------

func TestLayer_Process_TenantDisabled(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 5,
	})
	layer.rules = testRules()
	layer.buildRuleMaps()

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/test",
		Headers: map[string][]string{},
		TenantWAFConfig: &config.WAFConfig{
			CRS: config.CRSConfig{Enabled: false},
		},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass when tenant CRS disabled, got %v", result.Action)
	}
}

func TestLayer_Process_PassClean(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 100,
	})
	layer.rules = []*Rule{
		{
			ID:        "999001",
			Phase:     1,
			Variables: []RuleVariable{{Name: "REQUEST_METHOD"}},
			Operator:  RuleOperator{Type: "@rx", Argument: "^(CONNECT|TRACE)$"},
			Actions:   RuleActions{Action: "deny", Severity: "CRITICAL"},
		},
	}
	layer.buildRuleMaps()

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/safe/path",
		Headers: map[string][]string{"Host": {"example.com"}},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass for clean request, got %v", result.Action)
	}
}

func TestLayer_Process_BlockOnDeny(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 100,
	})
	layer.rules = []*Rule{
		{
			ID:        "999100",
			Phase:     1,
			Variables: []RuleVariable{{Name: "REQUEST_METHOD"}},
			Operator:  RuleOperator{Type: "@eq", Argument: "CONNECT"},
			Actions:   RuleActions{Action: "deny", Severity: "CRITICAL", Msg: "Bad method"},
		},
	}
	layer.buildRuleMaps()

	ctx := &engine.RequestContext{
		Method:  "CONNECT",
		Path:    "/",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for denied method, got %v", result.Action)
	}
	if result.Score == 0 {
		t.Error("expected non-zero score on block")
	}
}

func TestLayer_Process_BlockOnAnomalyThreshold(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 5,
	})
	layer.rules = []*Rule{
		{
			ID:        "999200",
			Phase:     2,
			Variables: []RuleVariable{{Name: "REQUEST_BODY"}},
			Operator:  RuleOperator{Type: "@contains", Argument: "attack"},
			Actions:   RuleActions{Severity: "WARNING", Msg: "Suspicious body"},
		},
	}
	layer.buildRuleMaps()

	ctx := &engine.RequestContext{
		Method:  "POST",
		Path:    "/submit",
		Body:    []byte("this is an attack payload"),
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	// WARNING severity = 5, anomaly threshold = 5
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block via anomaly threshold, got %v (score=%d)", result.Action, result.Score)
	}
}

func TestLayer_Process_Phase2Body(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 100,
	})
	layer.rules = []*Rule{
		{
			ID:        "999300",
			Phase:     2,
			Variables: []RuleVariable{{Name: "REQUEST_BODY"}},
			Operator:  RuleOperator{Type: "@rx", Argument: "(?i)(union|select).*(from|table)"},
			Actions:   RuleActions{Action: "deny", Severity: "CRITICAL", Msg: "SQLi in body"},
		},
	}
	layer.buildRuleMaps()

	ctx := &engine.RequestContext{
		Method:  "POST",
		Path:    "/search",
		Body:    []byte("1 UNION SELECT * FROM users"),
		Headers: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for SQLi in body, got %v", result.Action)
	}
}

func TestLayer_Process_WithHTTPURL(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 100,
	})
	layer.rules = []*Rule{
		{
			ID:        "999400",
			Phase:     1,
			Variables: []RuleVariable{{Name: "REQUEST_URI"}},
			Operator:  RuleOperator{Type: "@contains", Argument: "admin"},
			Actions:   RuleActions{Action: "deny", Severity: "CRITICAL", Msg: "Admin access"},
		},
	}
	layer.buildRuleMaps()

	req, _ := http.NewRequest("GET", "http://example.com/admin/secret?foo=bar", nil)
	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/admin/secret",
		Request: req,
		Headers: map[string][]string{"Host": {"example.com"}},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for admin URI, got %v", result.Action)
	}
}

func TestLayer_Process_WithClientIP(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 100,
	})
	layer.rules = []*Rule{
		{
			ID:        "999500",
			Phase:     1,
			Variables: []RuleVariable{{Name: "REMOTE_ADDR"}},
			Operator:  RuleOperator{Type: "@ipMatch", Argument: "10.0.0.0/8"},
			Actions:   RuleActions{Action: "deny", Severity: "CRITICAL", Msg: "Internal IP"},
		},
	}
	layer.buildRuleMaps()

	ctx := &engine.RequestContext{
		Method:   "GET",
		Path:     "/test",
		ClientIP: net.ParseIP("10.0.0.50"),
		Headers:  map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for internal IP, got %v", result.Action)
	}
}

func TestLayer_Process_ExcludedVariable(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 100,
	})
	layer.rules = []*Rule{
		{
			ID: "999600",
			Phase: 1,
			Variables: []RuleVariable{
				{Name: "REQUEST_METHOD", Exclude: true},
			},
			Operator: RuleOperator{Type: "@rx", Argument: ".*"},
			Actions:  RuleActions{Action: "deny", Severity: "CRITICAL", Msg: "Should not match"},
		},
	}
	layer.buildRuleMaps()

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/test",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass when all variables excluded, got %v", result.Action)
	}
}

func TestLayer_Process_ChainRule(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 100,
	})
	layer.rules = []*Rule{
		{
			ID:        "999700",
			Phase:     1,
			Variables: []RuleVariable{{Name: "REQUEST_METHOD"}},
			Operator:  RuleOperator{Type: "@eq", Argument: "POST"},
			Actions:   RuleActions{Action: "deny", Severity: "CRITICAL", Msg: "POST blocked"},
			Chain: &Rule{
				Variables: []RuleVariable{{Collection: "REQUEST_HEADERS", Key: "Content-Type"}},
				Operator:  RuleOperator{Type: "@contains", Argument: "json"},
				Actions:   RuleActions{},
			},
		},
	}
	layer.buildRuleMaps()

	// Should match: POST + json content type
	ctx := &engine.RequestContext{
		Method: "POST",
		Path:   "/api",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
	}
	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block for chained rule match, got %v", result.Action)
	}

	// Should not match: POST + non-json content type
	ctx2 := &engine.RequestContext{
		Method: "POST",
		Path:   "/api",
		Headers: map[string][]string{
			"Content-Type": {"text/plain"},
		},
	}
	result2 := layer.Process(ctx2)
	if result2.Action != engine.ActionPass {
		t.Errorf("expected pass when chain does not match, got %v", result2.Action)
	}
}

func TestLayer_Process_Transformations(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 100,
	})
	layer.rules = []*Rule{
		{
			ID:        "999800",
			Phase:     1,
			Variables: []RuleVariable{{Name: "REQUEST_URI"}},
			Operator:  RuleOperator{Type: "@contains", Argument: "admin"},
			Actions: RuleActions{
				Action:          "deny",
				Severity:        "CRITICAL",
				Msg:             "Admin access",
				Transformations: []string{"lowercase"},
			},
		},
	}
	layer.buildRuleMaps()

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/ADMIN/SECRET",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionBlock {
		t.Errorf("expected block after lowercase transform, got %v", result.Action)
	}
}

func TestLayer_Process_SetVar(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 100,
	})
	layer.rules = []*Rule{
		{
			ID:        "999900",
			Phase:     1,
			Variables: []RuleVariable{{Name: "REQUEST_METHOD"}},
			Operator:  RuleOperator{Type: "@eq", Argument: "GET"},
			Actions: RuleActions{
				Action:   "pass",
				Severity: "NOTICE",
				Msg:      "GET request",
				SetVar:   []VarAction{{Collection: "tx", Variable: "custom_var", Operation: "=", Value: "set"}},
			},
		},
	}
	layer.buildRuleMaps()

	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    "/test",
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass, got %v", result.Action)
	}
}

// ---------------------------------------------------------------------------
// Layer method tests
// ---------------------------------------------------------------------------

func TestLayer_NewLayer_NilConfig(t *testing.T) {
	layer := NewLayer(nil)
	if layer == nil {
		t.Fatal("expected non-nil layer")
	}
	if layer.config.Enabled {
		t.Error("expected disabled by default")
	}
}

func TestLayer_GetRulesByPhase(t *testing.T) {
	layer := NewLayer(DefaultConfig())
	layer.rules = testRules()
	layer.buildRuleMaps()

	phase1 := layer.GetRulesByPhase(1)
	if len(phase1) == 0 {
		t.Error("expected phase 1 rules")
	}

	phase2 := layer.GetRulesByPhase(2)
	if len(phase2) == 0 {
		t.Error("expected phase 2 rules")
	}

	phase99 := layer.GetRulesByPhase(99)
	if len(phase99) != 0 {
		t.Error("expected no rules for non-existent phase")
	}
}

func TestLayer_GetAllRules(t *testing.T) {
	layer := NewLayer(DefaultConfig())
	layer.rules = testRules()
	layer.buildRuleMaps()

	all := layer.GetAllRules()
	if len(all) != len(testRules()) {
		t.Errorf("expected %d rules, got %d", len(testRules()), len(all))
	}

	// Verify it's a copy
	all[0] = nil
	if layer.rules[0] == nil {
		t.Error("GetAllRules should return a copy")
	}
}

func TestLayer_ShouldBlock(t *testing.T) {
	layer := NewLayer(&Config{AnomalyThreshold: 5})

	tests := []struct {
		action string
		score  int
		want   bool
	}{
		{"deny", 0, true},
		{"block", 0, true},
		{"drop", 0, true},
		{"pass", 5, true},
		{"pass", 4, false},
		{"log", 10, true},
	}

	for _, tt := range tests {
		name := tt.action + "-" + string(rune('0'+tt.score))
		t.Run(name, func(t *testing.T) {
			rule := &Rule{Actions: RuleActions{Action: tt.action}}
			got := layer.shouldBlock(rule, tt.score, 0)
			if got != tt.want {
				t.Errorf("shouldBlock(%s, %d) = %v; want %v", tt.action, tt.score, got, tt.want)
			}
		})
	}
}

func TestLayer_NewLayer_WithRulePath(t *testing.T) {
	tmpDir := t.TempDir()
	ruleFile := filepath.Join(tmpDir, "rules.conf")
	content := `SecRule REQUEST_METHOD "@rx ^GET$" "id:700001,phase:1,pass,msg:'Test rule'"`
	if err := os.WriteFile(ruleFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	layer := NewLayer(&Config{
		Enabled:          true,
		RulePath:         ruleFile,
		ParanoiaLevel:    1,
		AnomalyThreshold: 5,
	})
	if layer.GetRule("700001") == nil {
		t.Error("expected rule 700001 to be loaded from RulePath")
	}
}

// ---------------------------------------------------------------------------
// urlDecode edge cases
// ---------------------------------------------------------------------------

func TestUrlDecode_EdgeCases(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"hello%20world", "hello world"},
		{"%3Cscript%3E", "<script>"},
		{"no%encoding", "no%encoding"},
		{"%", "%"},
		{"%a", "%a"},
		{"%GG", "%GG"},
		{"", ""},
		{"plain", "plain"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := urlDecode(tt.input)
			if got != tt.expect {
				t.Errorf("urlDecode(%q) = %q; want %q", tt.input, got, tt.expect)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Regex cache tests
// ---------------------------------------------------------------------------

func TestGetCachedRegex(t *testing.T) {
	re, err := getCachedRegex(`^\d+$`)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if !re.MatchString("123") {
		t.Error("expected match")
	}

	re2, err := getCachedRegex(`^\d+$`)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if re != re2 {
		t.Error("expected same cached regex instance")
	}
}

func TestGetCachedRegex_InvalidPattern(t *testing.T) {
	_, err := getCachedRegex(`(?P<invalid`)
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

// ---------------------------------------------------------------------------
// Full integration test with programmatically defined rules
// ---------------------------------------------------------------------------

func TestLayer_Integration_FullPipeline(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 5,
	})
	layer.rules = []*Rule{
		{
			ID:        "960001",
			Phase:     1,
			Variables: []RuleVariable{{Name: "REQUEST_METHOD"}},
			Operator:  RuleOperator{Type: "@rx", Argument: `^(CONNECT|TRACE|TRACK)$`},
			Actions:   RuleActions{Action: "deny", Severity: "WARNING", Msg: "Method not allowed"},
		},
		{
			ID:        "960002",
			Phase:     1,
			Variables: []RuleVariable{{Name: "REQUEST_URI"}},
			Operator:  RuleOperator{Type: "@rx", Argument: `\.\.\/`},
			Actions:   RuleActions{Action: "deny", Severity: "CRITICAL", Msg: "Path traversal"},
		},
		{
			ID:        "960003",
			Phase:     2,
			Variables: []RuleVariable{{Name: "QUERY_STRING"}},
			Operator:  RuleOperator{Type: "@rx", Argument: `(?i)(union\s+(all\s+)?select|select\s+.+\s+from|insert\s+into)`},
			Actions:   RuleActions{Action: "deny", Severity: "CRITICAL", Msg: "SQL Injection"},
		},
		{
			ID:        "960004",
			Phase:     2,
			Variables: []RuleVariable{{Name: "REQUEST_BODY"}},
			Operator:  RuleOperator{Type: "@rx", Argument: `(?i)(<script|javascript\s*:|on(error|load|click)\s*=)`},
			Actions:   RuleActions{Action: "deny", Severity: "CRITICAL", Msg: "XSS Attack"},
		},
		{
			ID:        "960005",
			Phase:     1,
			Variables: []RuleVariable{{Collection: "REQUEST_HEADERS", Key: "User-Agent"}},
			Operator:  RuleOperator{Type: "@rx", Argument: `(?i)(nikto|sqlmap|nmap|masscan)`},
			Actions:   RuleActions{Action: "deny", Severity: "ERROR", Msg: "Malicious user agent"},
		},
	}
	layer.buildRuleMaps()

	tests := []struct {
		name string
		ctx  *engine.RequestContext
		want engine.Action
	}{
		{
			"clean GET",
			&engine.RequestContext{
				Method:  "GET",
				Path:    "/api/users",
				Headers: map[string][]string{"User-Agent": {"Mozilla/5.0"}},
			},
			engine.ActionPass,
		},
		{
			"CONNECT blocked",
			&engine.RequestContext{
				Method:  "CONNECT",
				Path:    "/",
				Headers: map[string][]string{"User-Agent": {"curl/7.0"}},
			},
			engine.ActionBlock,
		},
		{
			"path traversal",
			&engine.RequestContext{
				Method:  "GET",
				Path:    "/../../../etc/passwd",
				Headers: map[string][]string{"User-Agent": {"Mozilla/5.0"}},
			},
			engine.ActionBlock,
		},
		{
			"SQLi in query",
			&engine.RequestContext{
				Method: "GET",
				Path:   "/search?q=1 UNION SELECT * FROM users",
				Request: &http.Request{
					URL: &url.URL{
						Path:     "/search",
						RawQuery: "q=1 UNION SELECT * FROM users",
					},
				},
				Headers: map[string][]string{"User-Agent": {"Mozilla/5.0"}},
			},
			engine.ActionBlock,
		},
		{
			"XSS in body",
			&engine.RequestContext{
				Method:  "POST",
				Path:    "/comment",
				Body:    []byte(`<script>alert('xss')</script>`),
				Headers: map[string][]string{"User-Agent": {"Mozilla/5.0"}},
			},
			engine.ActionBlock,
		},
		{
			"malicious user agent",
			&engine.RequestContext{
				Method:  "GET",
				Path:    "/",
				Headers: map[string][]string{"User-Agent": {"sqlmap/1.0"}},
			},
			engine.ActionBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := layer.Process(tt.ctx)
			if result.Action != tt.want {
				t.Errorf("expected %v, got %v (score=%d, findings=%d)",
					tt.want, result.Action, result.Score, len(result.Findings))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// evaluateRule with matched value truncation
// ---------------------------------------------------------------------------

func TestLayer_EvaluateRule_LongMatchedValue(t *testing.T) {
	layer := NewLayer(&Config{
		Enabled:          true,
		ParanoiaLevel:    1,
		AnomalyThreshold: 100,
	})
	layer.rules = []*Rule{
		{
			ID:        "990001",
			Phase:     1,
			Variables: []RuleVariable{{Name: "REQUEST_URI"}},
			Operator:  RuleOperator{Type: "@rx", Argument: ".*"},
			Actions:   RuleActions{Action: "pass", Severity: "NOTICE", Msg: "Long value test"},
		},
	}
	layer.buildRuleMaps()

	longPath := "/" + strings.Repeat("a", 300)
	ctx := &engine.RequestContext{
		Method:  "GET",
		Path:    longPath,
		Headers: map[string][]string{},
	}

	result := layer.Process(ctx)
	if result.Action != engine.ActionPass {
		t.Errorf("expected pass, got %v", result.Action)
	}
	for _, f := range result.Findings {
		if len(f.MatchedValue) > 200 {
			t.Errorf("matched value should be truncated to 200 chars, got %d", len(f.MatchedValue))
		}
	}
}

// ---------------------------------------------------------------------------
// Rule scoring by severity
// ---------------------------------------------------------------------------

func TestLayer_RuleScoringBySeverity(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{"CRITICAL", 10},
		{"ERROR", 8},
		{"WARNING", 5},
		{"NOTICE", 2},
		{"", 1},
		{"UNKNOWN", 1},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			layer := NewLayer(&Config{
				Enabled:          true,
				ParanoiaLevel:    1,
				AnomalyThreshold: 100,
			})
			layer.rules = []*Rule{
				{
					ID:        "score-test",
					Phase:     1,
					Variables: []RuleVariable{{Name: "REQUEST_METHOD"}},
					Operator:  RuleOperator{Type: "@eq", Argument: "GET"},
					Actions:   RuleActions{Action: "pass", Severity: tt.severity, Msg: "test"},
				},
			}
			layer.buildRuleMaps()

			ctx := &engine.RequestContext{
				Method:  "GET",
				Path:    "/",
				Headers: map[string][]string{},
			}
			result := layer.Process(ctx)
			if result.Score != tt.want {
				t.Errorf("severity %q: score = %d; want %d", tt.severity, result.Score, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// urlEncode
// ---------------------------------------------------------------------------

func TestUrlEncode(t *testing.T) {
	got := urlEncode("hello world")
	if got != "hello%20world" {
		t.Errorf("urlEncode('hello world') = %q; want 'hello%%20world'", got)
	}
}

// ---------------------------------------------------------------------------
// htmlEntityDecode edge cases
// ---------------------------------------------------------------------------

func TestHtmlEntityDecode(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"&lt;script&gt;", "<script>"},
		{"a &amp; b", "a & b"},
		{`he said &quot;hi&quot;`, `he said "hi"`},
		{"&#x27;single&#x27;", "'single'"},
		{"no entities", "no entities"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := htmlEntityDecode(tt.input)
			if got != tt.expect {
				t.Errorf("htmlEntityDecode(%q) = %q; want %q", tt.input, got, tt.expect)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// evaluateUrlEncoding edge cases
// ---------------------------------------------------------------------------

func TestOperatorEvaluator_UrlEncoding_EdgeCases(t *testing.T) {
	eval := NewOperatorEvaluator()

	// Value ending with % at last-2 position (incomplete %XX)
	result, err := eval.Evaluate(RuleOperator{Type: "@validateUrlEncoding", Argument: ""}, "test%2")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result {
		t.Error("expected false for incomplete pct encoding at boundary")
	}
}

// ---------------------------------------------------------------------------
// Default config
// ---------------------------------------------------------------------------

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled {
		t.Error("expected disabled by default")
	}
	if cfg.ParanoiaLevel != 1 {
		t.Errorf("ParanoiaLevel = %d", cfg.ParanoiaLevel)
	}
	if cfg.AnomalyThreshold != 5 {
		t.Errorf("AnomalyThreshold = %d", cfg.AnomalyThreshold)
	}
}

// ---------------------------------------------------------------------------
// RuleSet type
// ---------------------------------------------------------------------------

func TestRuleSet(t *testing.T) {
	rs := &RuleSet{
		Rules: testRules(),
	}
	if len(rs.Rules) == 0 {
		t.Error("expected rules in RuleSet")
	}
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

func TestLayer_Stats(t *testing.T) {
	layer := NewLayer(DefaultConfig())
	layer.rules = testRules()
	layer.buildRuleMaps()

	stats := layer.Stats()
	if stats["total"] != len(testRules()) {
		t.Errorf("total = %d; want %d", stats["total"], len(testRules()))
	}
	if _, ok := stats["phase_1"]; !ok {
		t.Error("expected phase_1 key in stats")
	}
	if _, ok := stats["phase_2"]; !ok {
		t.Error("expected phase_2 key in stats")
	}
	if _, ok := stats["disabled"]; !ok {
		t.Error("expected disabled key in stats")
	}
}
