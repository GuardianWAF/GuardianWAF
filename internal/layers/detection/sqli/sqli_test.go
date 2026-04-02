package sqli

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// --- Tokenizer Tests ---

func TestTokenizer_BasicTokens(t *testing.T) {
	input := "SELECT * FROM users WHERE id = 1"
	tokens := Tokenize(input)

	expected := []struct {
		typ TokenType
		val string
	}{
		{TokenKeyword, "SELECT"},
		{TokenWhitespace, " "},
		{TokenWildcard, "*"},
		{TokenWhitespace, " "},
		{TokenKeyword, "FROM"},
		{TokenWhitespace, " "},
		{TokenOther, "users"},
		{TokenWhitespace, " "},
		{TokenKeyword, "WHERE"},
		{TokenWhitespace, " "},
		{TokenOther, "id"},
		{TokenWhitespace, " "},
		{TokenOperator, "="},
		{TokenWhitespace, " "},
		{TokenNumericLiteral, "1"},
	}

	if len(tokens) != len(expected) {
		t.Fatalf("expected %d tokens, got %d: %v", len(expected), len(tokens), tokens)
	}

	for i, exp := range expected {
		if tokens[i].Type != exp.typ {
			t.Errorf("token[%d]: expected type %v, got %v (value=%q)", i, exp.typ, tokens[i].Type, tokens[i].Value)
		}
		if tokens[i].Value != exp.val {
			t.Errorf("token[%d]: expected value %q, got %q", i, exp.val, tokens[i].Value)
		}
	}
}

func TestTokenizer_StringLiterals(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		typ      TokenType
	}{
		{"single quote", "'hello'", "'hello'", TokenStringLiteral},
		{"double quote", `"hello"`, `"hello"`, TokenStringLiteral},
		{"backtick", "`table`", "`table`", TokenStringLiteral},
		{"escaped single quote backslash", `'it\'s'`, `'it\'s'`, TokenStringLiteral},
		{"escaped single quote doubled", "'it''s'", "'it''s'", TokenStringLiteral},
		{"empty string", "''", "''", TokenStringLiteral},
		{"string with spaces", "'hello world'", "'hello world'", TokenStringLiteral},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := Tokenize(tt.input)
			found := false
			for _, tok := range tokens {
				if tok.Type == tt.typ && tok.Value == tt.expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected token type=%v value=%q in tokens: %v", tt.typ, tt.expected, tokens)
			}
		})
	}
}

func TestTokenizer_Comments(t *testing.T) {
	tests := []struct {
		name  string
		input string
		value string
	}{
		{"double dash", "-- comment", "-- comment"},
		{"hash", "# comment", "# comment"},
		{"block comment", "/* comment */", "/* comment */"},
		{"empty block", "/**/", "/**/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := Tokenize(tt.input)
			found := false
			for _, tok := range tokens {
				if tok.Type == TokenComment && tok.Value == tt.value {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected comment token %q in tokens: %v", tt.value, tokens)
			}
		})
	}
}

func TestTokenizer_Numbers(t *testing.T) {
	tests := []struct {
		name  string
		input string
		value string
	}{
		{"integer", "123", "123"},
		{"hex", "0x1A", "0x1A"},
		{"hex upper", "0XFF", "0XFF"},
		{"binary", "0b1010", "0b1010"},
		{"decimal", "3.14", "3.14"},
		{"zero", "0", "0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := Tokenize(tt.input)
			found := false
			for _, tok := range tokens {
				if tok.Type == TokenNumericLiteral && tok.Value == tt.value {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected numeric token %q in tokens: %v", tt.value, tokens)
			}
		})
	}
}

func TestTokenizer_Keywords(t *testing.T) {
	keywords := []string{"SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "DROP", "INSERT", "UPDATE", "DELETE"}
	for _, kw := range keywords {
		t.Run(kw, func(t *testing.T) {
			tokens := Tokenize(kw)
			if len(tokens) == 0 {
				t.Fatalf("no tokens for %q", kw)
			}
			// OR and AND are operator keywords
			if kw == "OR" || kw == "AND" {
				// These map to TokenOperator because IsOperatorKeyword is checked first
				// Actually OR is not in sqlOperators, only NOT, LIKE, IN, BETWEEN, IS, EXISTS
				// Let me check: OR is a keyword, AND is a keyword
				_ = kw // Silence empty branch warning
			}
			tok := tokens[0]
			if tok.Type != TokenKeyword && tok.Type != TokenOperator {
				t.Errorf("expected keyword or operator type for %q, got %v", kw, tok.Type)
			}
		})
	}
}

func TestTokenizer_Operators(t *testing.T) {
	tests := []struct {
		input string
		value string
	}{
		{"=", "="},
		{"!=", "!="},
		{"<>", "<>"},
		{">=", ">="},
		{"<=", "<="},
		{">", ">"},
		{"<", "<"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			tokens := Tokenize(tt.input)
			if len(tokens) == 0 {
				t.Fatal("no tokens")
			}
			if tokens[0].Type != TokenOperator || tokens[0].Value != tt.value {
				t.Errorf("expected operator %q, got type=%v value=%q", tt.value, tokens[0].Type, tokens[0].Value)
			}
		})
	}
}

func TestTokenizer_SpecialChars(t *testing.T) {
	tests := []struct {
		input string
		typ   TokenType
	}{
		{"(", TokenParenOpen},
		{")", TokenParenClose},
		{";", TokenSemicolon},
		{",", TokenComma},
		{"*", TokenWildcard},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			tokens := Tokenize(tt.input)
			if len(tokens) == 0 {
				t.Fatal("no tokens")
			}
			if tokens[0].Type != tt.typ {
				t.Errorf("expected type %v, got %v", tt.typ, tokens[0].Type)
			}
		})
	}
}

func TestTokenizer_CommentInWord(t *testing.T) {
	// UN/**/ION should tokenize as: Other("UN"), Comment("/**/"), Other("ION")
	tokens := Tokenize("UN/**/ION")
	significant := 0
	types := make([]TokenType, 0, len(tokens))
	for _, tok := range tokens {
		types = append(types, tok.Type)
		if tok.Type != TokenWhitespace {
			significant++
		}
	}
	if significant != 3 {
		t.Errorf("expected 3 significant tokens, got %d: types=%v", significant, types)
	}
}

// --- Detection Tests ---

// Attack payloads that MUST be detected with minimum scores
var attackPayloads = []struct {
	name     string
	input    string
	minScore int
}{
	{"basic union select", "' UNION SELECT * FROM users --", 90},
	{"tautology", "' OR 1=1 --", 80},
	{"tautology string", "' OR 'a'='a", 80},
	{"stacked query drop", "'; DROP TABLE users --", 95},
	{"sleep injection", "' OR SLEEP(5) --", 90},
	{"benchmark", "' OR BENCHMARK(10000000,SHA1('test')) --", 90},
	{"load_file", "' UNION SELECT LOAD_FILE('/etc/passwd') --", 100},
	{"into outfile", "' INTO OUTFILE '/tmp/data.txt' --", 100},
	{"exec xp_cmdshell", "'; EXEC xp_cmdshell('dir') --", 80},
	{"char obfuscation", "' OR CHAR(49)=CHAR(49) --", 50},
	{"hex literal", "' OR 0x50=0x50 --", 40},
	{"double dash comment after string", "admin'--", 35},
	{"hash comment", "admin'#", 35},
	{"waitfor delay", "'; WAITFOR DELAY '0:0:5' --", 90},
	{"information_schema", "' UNION SELECT table_name FROM INFORMATION_SCHEMA.TABLES --", 90},
	{"group_concat", "' UNION SELECT GROUP_CONCAT(username) FROM users --", 90},
	{"nested subquery", "' OR (SELECT COUNT(*) FROM users) > 0 --", 50},
	{"update injection", "'; UPDATE users SET admin=1 WHERE id=1 --", 95},
}

// Benign inputs that must NOT trigger high scores
var benignInputs = []struct {
	name     string
	input    string
	maxScore int
}{
	{"normal query", "search for products", 0},
	{"email address", "user@example.com", 0},
	{"normal number", "12345", 0},
	{"json data", `{"name": "John", "age": 30}`, 0},
	{"url with equals", "page=1&sort=name", 0},
	{"name O'Brien", "O'Brien", 15},
	{"it's a test", "it's a nice day", 15},
	{"sql tutorial text", "Learn about SELECT statements", 15},
	{"McDonald's", "McDonald's Restaurant", 15},
	{"comment in text", "This is a comment -- by the author", 15},
}

func TestDetect_AttackPayloads(t *testing.T) {
	for _, tt := range attackPayloads {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore < tt.minScore {
				t.Errorf("input=%q: total score %d < minimum %d\nfindings: %+v",
					tt.input, totalScore, tt.minScore, findings)
			}
		})
	}
}

func TestDetect_BenignInputs(t *testing.T) {
	for _, tt := range benignInputs {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore > tt.maxScore {
				t.Errorf("input=%q: total score %d > maximum %d\nfindings: %+v",
					tt.input, totalScore, tt.maxScore, findings)
			}
		})
	}
}

func TestDetect_EmptyInput(t *testing.T) {
	findings := Detect("", "query")
	if findings != nil {
		t.Errorf("expected nil findings for empty input, got %v", findings)
	}
}

func TestDetect_UnionSelect(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minScore int
	}{
		{"basic", "UNION SELECT 1,2,3", 90},
		{"union all select", "UNION ALL SELECT 1,2,3", 90},
		{"with prefix", "' UNION SELECT username FROM users", 90},
		{"case insensitive", "union select 1", 90},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore < tt.minScore {
				t.Errorf("input=%q: total score %d < %d", tt.input, totalScore, tt.minScore)
			}
		})
	}
}

func TestDetect_Tautology(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minScore int
	}{
		{"numeric 1=1", "' OR 1=1", 80},
		{"string a=a", "' OR 'a'='a'", 80},
		{"true=true", "' OR true=true", 80},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore < tt.minScore {
				t.Errorf("input=%q: total score %d < %d\nfindings: %+v",
					tt.input, totalScore, tt.minScore, findings)
			}
		})
	}
}

func TestDetect_StackedQueries(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minScore int
	}{
		{"drop table", "'; DROP TABLE users", 95},
		{"delete from", "'; DELETE FROM users", 95},
		{"truncate", "'; TRUNCATE TABLE users", 95},
		{"insert into", "'; INSERT INTO admin VALUES('hacker','pass')", 95},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore < tt.minScore {
				t.Errorf("input=%q: total score %d < %d\nfindings: %+v",
					tt.input, totalScore, tt.minScore, findings)
			}
		})
	}
}

func TestDetect_TimeBasedBlind(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minScore int
	}{
		{"sleep", "' OR SLEEP(5)--", 90},
		{"benchmark", "' OR BENCHMARK(10000000,SHA1('test'))--", 90},
		{"waitfor delay", "'; WAITFOR DELAY '0:0:5'--", 90},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore < tt.minScore {
				t.Errorf("input=%q: total score %d < %d\nfindings: %+v",
					tt.input, totalScore, tt.minScore, findings)
			}
		})
	}
}

func TestDetect_FileAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		minScore int
	}{
		{"load_file", "UNION SELECT LOAD_FILE('/etc/passwd')", 100},
		{"into outfile", "SELECT * INTO OUTFILE '/tmp/data.txt'", 100},
		{"into dumpfile", "SELECT * INTO DUMPFILE '/tmp/data.bin'", 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore < tt.minScore {
				t.Errorf("input=%q: total score %d < %d\nfindings: %+v",
					tt.input, totalScore, tt.minScore, findings)
			}
		})
	}
}

// --- Detector Integration Tests ---

func TestDetector_Integration(t *testing.T) {
	det := NewDetector(true, 1.0)

	// Verify interface compliance
	var _ engine.Detector = det

	if det.Name() != "sqli-detector" {
		t.Errorf("expected name 'sqli-detector', got %q", det.Name())
	}
	if det.DetectorName() != "sqli" {
		t.Errorf("expected detector name 'sqli', got %q", det.DetectorName())
	}
	if len(det.Patterns()) == 0 {
		t.Error("expected non-empty patterns list")
	}

	// Create a request context with a malicious query parameter
	reqURL, _ := url.Parse("http://example.com/search?q=' UNION SELECT * FROM users --")
	req := &http.Request{
		Method: "GET",
		URL:    reqURL,
		Header: http.Header{},
	}

	ctx := &engine.RequestContext{
		Request:        req,
		Method:         "GET",
		NormalizedPath: "/search",
		NormalizedQuery: map[string][]string{
			"q": {"' UNION SELECT * FROM users --"},
		},
		Headers: map[string][]string{},
		Cookies: map[string]string{},
	}

	result := det.Process(ctx)

	if result.Action != engine.ActionLog {
		t.Errorf("expected ActionLog, got %v", result.Action)
	}
	if result.Score < 90 {
		t.Errorf("expected score >= 90, got %d", result.Score)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings for SQL injection payload")
	}

	// Verify finding fields
	for _, f := range result.Findings {
		if f.DetectorName != "sqli" {
			t.Errorf("expected detector name 'sqli', got %q", f.DetectorName)
		}
		if f.Category != "sqli" {
			t.Errorf("expected category 'sqli', got %q", f.Category)
		}
		if f.Location == "" {
			t.Error("expected non-empty location")
		}
	}
}

func TestDetector_Disabled(t *testing.T) {
	det := NewDetector(false, 1.0)

	ctx := &engine.RequestContext{
		NormalizedPath: "' UNION SELECT * FROM users --",
		NormalizedQuery: map[string][]string{
			"q": {"' OR 1=1 --"},
		},
		Headers: map[string][]string{},
		Cookies: map[string]string{},
	}

	result := det.Process(ctx)

	if result.Action != engine.ActionPass {
		t.Errorf("disabled detector should return ActionPass, got %v", result.Action)
	}
	if len(result.Findings) != 0 {
		t.Errorf("disabled detector should produce no findings, got %d", len(result.Findings))
	}
	if result.Score != 0 {
		t.Errorf("disabled detector should have score 0, got %d", result.Score)
	}
}

func TestDetector_Multiplier(t *testing.T) {
	input := "' UNION SELECT * FROM users --"

	// Get baseline score at 1.0 multiplier
	det1 := NewDetector(true, 1.0)
	ctx1 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{
			"q": {input},
		},
		Headers: map[string][]string{},
		Cookies: map[string]string{},
	}
	result1 := det1.Process(ctx1)

	// Get score at 2.0 multiplier
	det2 := NewDetector(true, 2.0)
	ctx2 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{
			"q": {input},
		},
		Headers: map[string][]string{},
		Cookies: map[string]string{},
	}
	result2 := det2.Process(ctx2)

	if result1.Score == 0 {
		t.Fatal("baseline score should not be 0")
	}

	// Score at 2x should be roughly double (integer rounding may cause slight differences)
	expectedMin := result1.Score*2 - len(result1.Findings) // allow rounding tolerance
	if result2.Score < expectedMin {
		t.Errorf("2x multiplier: expected score >= %d, got %d (baseline=%d)",
			expectedMin, result2.Score, result1.Score)
	}

	// Score at 0.5x multiplier
	det05 := NewDetector(true, 0.5)
	ctx05 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{
			"q": {input},
		},
		Headers: map[string][]string{},
		Cookies: map[string]string{},
	}
	result05 := det05.Process(ctx05)

	if result05.Score >= result1.Score {
		t.Errorf("0.5x multiplier score %d should be less than 1.0x score %d",
			result05.Score, result1.Score)
	}
}

func TestDetector_ScanLocations(t *testing.T) {
	det := NewDetector(true, 1.0)
	payload := "' UNION SELECT * FROM users --"

	// Test body scanning
	ctx := &engine.RequestContext{
		NormalizedBody:  payload,
		NormalizedQuery: map[string][]string{},
		Headers:         map[string][]string{},
		Cookies:         map[string]string{},
	}
	result := det.Process(ctx)
	if result.Score < 90 {
		t.Errorf("body scan: expected score >= 90, got %d", result.Score)
	}
	hasBody := false
	for _, f := range result.Findings {
		if f.Location == "body" {
			hasBody = true
		}
	}
	if !hasBody {
		t.Error("expected findings with location 'body'")
	}

	// Test cookie scanning
	ctx2 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{},
		Headers:         map[string][]string{},
		Cookies: map[string]string{
			"session": payload,
		},
	}
	result2 := det.Process(ctx2)
	if result2.Score < 90 {
		t.Errorf("cookie scan: expected score >= 90, got %d", result2.Score)
	}

	// Test Referer header scanning
	ctx3 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{},
		Headers: map[string][]string{
			"Referer": {payload},
		},
		Cookies: map[string]string{},
	}
	result3 := det.Process(ctx3)
	if result3.Score < 90 {
		t.Errorf("referer scan: expected score >= 90, got %d", result3.Score)
	}

	// Test User-Agent scanning (scores halved)
	ctx4 := &engine.RequestContext{
		NormalizedQuery: map[string][]string{},
		Headers: map[string][]string{
			"User-Agent": {payload},
		},
		Cookies: map[string]string{},
	}
	result4 := det.Process(ctx4)
	if result4.Score >= result.Score {
		t.Errorf("User-Agent scan score %d should be less than direct scan score %d (due to 0.5x)",
			result4.Score, result.Score)
	}
}

func TestDetect_CaseInsensitivity(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"lowercase", "' union select * from users --"},
		{"uppercase", "' UNION SELECT * FROM USERS --"},
		{"mixed case", "' Union Select * From Users --"},
		{"random case", "' uNiOn sElEcT * fRoM uSeRs --"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := Detect(tt.input, "query")
			totalScore := 0
			for _, f := range findings {
				totalScore += f.Score
			}
			if totalScore < 90 {
				t.Errorf("input=%q: total score %d < 90 (case insensitive detection failed)",
					tt.input, totalScore)
			}
		})
	}
}

func TestDetect_FindingFields(t *testing.T) {
	findings := Detect("' UNION SELECT * FROM users --", "query")
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	for _, f := range findings {
		if f.DetectorName != "sqli" {
			t.Errorf("DetectorName: expected 'sqli', got %q", f.DetectorName)
		}
		if f.Category != "sqli" {
			t.Errorf("Category: expected 'sqli', got %q", f.Category)
		}
		if f.Location != "query" {
			t.Errorf("Location: expected 'query', got %q", f.Location)
		}
		if f.Score <= 0 {
			t.Errorf("Score should be > 0, got %d", f.Score)
		}
		if f.Description == "" {
			t.Error("Description should not be empty")
		}
		if f.Confidence <= 0 || f.Confidence > 1.0 {
			t.Errorf("Confidence should be in (0, 1.0], got %f", f.Confidence)
		}
		if len(f.MatchedValue) > 200 {
			t.Errorf("MatchedValue should be truncated to 200 chars, got %d", len(f.MatchedValue))
		}
	}
}

func TestTokenType_String(t *testing.T) {
	tests := []struct {
		typ  TokenType
		want string
	}{
		{TokenStringLiteral, "StringLiteral"},
		{TokenNumericLiteral, "NumericLiteral"},
		{TokenKeyword, "Keyword"},
		{TokenOperator, "Operator"},
		{TokenFunction, "Function"},
		{TokenComment, "Comment"},
		{TokenParenOpen, "ParenOpen"},
		{TokenParenClose, "ParenClose"},
		{TokenSemicolon, "Semicolon"},
		{TokenComma, "Comma"},
		{TokenWildcard, "Wildcard"},
		{TokenWhitespace, "Whitespace"},
		{TokenOther, "Other"},
		{TokenType(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.typ.String(); got != tt.want {
				t.Errorf("TokenType(%d).String() = %q, want %q", tt.typ, got, tt.want)
			}
		})
	}
}

func TestKeywords_Functions(t *testing.T) {
	// Test IsKeyword
	if !IsKeyword("SELECT") {
		t.Error("SELECT should be a keyword")
	}
	if IsKeyword("NOTAKEYWORD") {
		t.Error("NOTAKEYWORD should not be a keyword")
	}

	// Test IsFunction
	if !IsFunction("SLEEP") {
		t.Error("SLEEP should be a function")
	}
	if IsFunction("NOTAFUNCTION") {
		t.Error("NOTAFUNCTION should not be a function")
	}

	// Test IsOperatorKeyword
	if !IsOperatorKeyword("LIKE") {
		t.Error("LIKE should be an operator keyword")
	}
	if IsOperatorKeyword("SELECT") {
		t.Error("SELECT should not be an operator keyword")
	}

	// Test IsDangerousKeyword
	if !IsDangerousKeyword("DROP") {
		t.Error("DROP should be dangerous")
	}
	if IsDangerousKeyword("FROM") {
		t.Error("FROM should not be dangerous")
	}

	// Test IsDangerousFunction
	if !IsDangerousFunction("SLEEP") {
		t.Error("SLEEP should be dangerous")
	}
	if IsDangerousFunction("COUNT") {
		t.Error("COUNT should not be dangerous")
	}
}

func TestDetect_LongInput(t *testing.T) {
	// Test with a very long benign input (should not crash or produce high score)
	long := strings.Repeat("normal text content ", 1000)
	findings := Detect(long, "body")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore > 0 {
		t.Errorf("long benign input scored %d, expected 0", totalScore)
	}
}

// Benchmark for performance verification
func BenchmarkTokenize(b *testing.B) {
	input := "' UNION SELECT username, password FROM users WHERE id=1 OR 1=1 --"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Tokenize(input)
	}
}

func TestMakeFinding_LongMatchTruncation(t *testing.T) {
	longMatch := strings.Repeat("x", 250)
	f := makeFinding(50, engine.SeverityHigh, "test", longMatch, "query", 0.8)
	if len(f.MatchedValue) > 200 {
		t.Errorf("expected matched value truncated to <= 200 chars, got %d", len(f.MatchedValue))
	}
	if f.MatchedValue[len(f.MatchedValue)-3:] != "..." {
		t.Error("expected truncated value to end with '...'")
	}
}

func TestStripQuotes_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"single char", "x", "x"},
		{"empty string", "", ""},
		{"mismatched quotes", "'hello\"", "'hello\""},
		{"single quotes", "'hello'", "hello"},
		{"double quotes", `"hello"`, "hello"},
		{"backticks", "`hello`", "hello"},
		{"just quotes", "''", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripQuotes(tt.input)
			if got != tt.want {
				t.Errorf("stripQuotes(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractRange_BoundaryEdgeCases(t *testing.T) {
	tokens := []Token{
		{Type: TokenKeyword, Value: "SELECT"},
		{Type: TokenWildcard, Value: "*"},
		{Type: TokenKeyword, Value: "FROM"},
	}

	// start < 0 should be clamped to 0
	result := extractRange(tokens, -5, 2)
	if !strings.Contains(result, "SELECT") {
		t.Errorf("expected result to start from token 0, got %q", result)
	}

	// end >= len(tokens) should be clamped to len(tokens)-1
	result2 := extractRange(tokens, 0, 100)
	if !strings.Contains(result2, "FROM") {
		t.Errorf("expected result to include last token, got %q", result2)
	}

	// empty tokens
	result3 := extractRange(nil, 0, 0)
	if result3 != "" {
		t.Errorf("expected empty result for nil tokens, got %q", result3)
	}
}

func TestTokenizer_UnterminatedString(t *testing.T) {
	// Unterminated string -- the quote should be emitted as a standalone token
	tokens := Tokenize("'unterminated")
	if len(tokens) == 0 {
		t.Fatal("expected at least one token")
	}
	// First token should be the lone quote
	if tokens[0].Type != TokenStringLiteral {
		t.Errorf("expected StringLiteral for unterminated quote, got %v", tokens[0].Type)
	}
}

func TestTokenizer_UnterminatedBlockComment(t *testing.T) {
	// Unterminated block comment
	tokens := Tokenize("/* unterminated comment")
	if len(tokens) == 0 {
		t.Fatal("expected at least one token")
	}
	found := false
	for _, tok := range tokens {
		if tok.Type == TokenComment {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a comment token for unterminated block comment")
	}
}

func TestTokenizer_NestedCommentStyle(t *testing.T) {
	// /* comment */ with content after
	tokens := Tokenize("/* test */ SELECT")
	hasComment := false
	hasKeyword := false
	for _, tok := range tokens {
		if tok.Type == TokenComment {
			hasComment = true
		}
		if tok.Type == TokenKeyword && tok.Value == "SELECT" {
			hasKeyword = true
		}
	}
	if !hasComment || !hasKeyword {
		t.Errorf("expected both comment and keyword, hasComment=%v hasKeyword=%v", hasComment, hasKeyword)
	}
}

func TestTokenizer_BinaryLiteral(t *testing.T) {
	tokens := Tokenize("0B1010")
	found := false
	for _, tok := range tokens {
		if tok.Type == TokenNumericLiteral && tok.Value == "0B1010" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected binary literal 0B1010, tokens: %v", tokens)
	}
}

func TestTokenizer_EscapedQuoteAtEnd(t *testing.T) {
	// Backslash at the very end of a quoted string before close
	tokens := Tokenize("'test\\'")
	if len(tokens) == 0 {
		t.Fatal("expected at least one token")
	}
}

func TestAnalyzeTokens_EmptyTokens(t *testing.T) {
	findings := AnalyzeTokens(nil, "query")
	if len(findings) != 0 {
		t.Errorf("expected no findings for nil tokens, got %d", len(findings))
	}

	findings2 := AnalyzeTokens([]Token{}, "query")
	if len(findings2) != 0 {
		t.Errorf("expected no findings for empty tokens, got %d", len(findings2))
	}
}

func TestHasTautology_InsufficientTokens(t *testing.T) {
	// Only 2 tokens from startIdx, need at least 3
	tokens := []Token{
		{Type: TokenNumericLiteral, Value: "1"},
		{Type: TokenOperator, Value: "="},
	}
	result := hasTautology(tokens, 0)
	if result {
		t.Error("expected false for insufficient tokens")
	}
}

func TestHasTautology_CommentsBeforeAllOperands(t *testing.T) {
	// Comments interspersed: 1 /* comment */ = /* comment */ 1
	tokens := []Token{
		{Type: TokenComment, Value: "/* c1 */"},
		{Type: TokenNumericLiteral, Value: "1"},
		{Type: TokenComment, Value: "/* c2 */"},
		{Type: TokenOperator, Value: "="},
		{Type: TokenComment, Value: "/* c3 */"},
		{Type: TokenNumericLiteral, Value: "1"},
	}
	result := hasTautology(tokens, 0)
	if !result {
		t.Error("expected true for 1=1 with comments")
	}
}

func TestHasTautology_NonEqualOperator(t *testing.T) {
	// 1 < 1 -- should not be a tautology
	tokens := []Token{
		{Type: TokenNumericLiteral, Value: "1"},
		{Type: TokenOperator, Value: "<"},
		{Type: TokenNumericLiteral, Value: "1"},
	}
	result := hasTautology(tokens, 0)
	if result {
		t.Error("expected false for non-equal operator")
	}
}

func TestHasTautology_CrossTypeTautology(t *testing.T) {
	// 'a' = a (string vs identifier -- cross-type tautology)
	tokens := []Token{
		{Type: TokenStringLiteral, Value: "'a'"},
		{Type: TokenOperator, Value: "="},
		{Type: TokenOther, Value: "a"},
	}
	result := hasTautology(tokens, 0)
	if !result {
		t.Error("expected true for cross-type tautology 'a'=a")
	}
}

func TestCheckExecString_WithComment(t *testing.T) {
	// EXEC /* comment */ 'command'
	findings := Detect("EXEC /* comment */ 'normal_value'", "query")
	hasExec := false
	for _, f := range findings {
		if strings.Contains(f.Description, "EXEC") {
			hasExec = true
		}
	}
	if !hasExec {
		t.Error("expected EXEC detection with comment before arg")
	}
}

func TestCheckExecString_ExecuteKeyword(t *testing.T) {
	findings := Detect("EXECUTE sp_executesql", "query")
	hasExec := false
	for _, f := range findings {
		if strings.Contains(f.Description, "EXEC") {
			hasExec = true
		}
	}
	if !hasExec {
		t.Error("expected EXECUTE detection")
	}
}

func TestCheckMultipleDangerousKeywords_TwoKeywords(t *testing.T) {
	// Only 2 dangerous keywords -- should NOT trigger the bonus
	findings := Detect("SELECT DROP", "query")
	hasMultiple := false
	for _, f := range findings {
		if strings.Contains(f.Description, "Multiple dangerous") {
			hasMultiple = true
		}
	}
	if hasMultiple {
		t.Error("should not detect 'multiple dangerous keywords' with only 2")
	}
}

func TestCheckMultipleDangerousKeywords_ThreeKeywords(t *testing.T) {
	// 3 dangerous keywords -- should trigger the bonus
	findings := Detect("SELECT DROP DELETE", "query")
	hasMultiple := false
	for _, f := range findings {
		if strings.Contains(f.Description, "Multiple dangerous") {
			hasMultiple = true
		}
	}
	if !hasMultiple {
		t.Error("expected 'multiple dangerous keywords' detection with 3+ keywords")
	}
}

func TestCheckIntoOutfile_WithComment(t *testing.T) {
	// INTO /* comment */ OUTFILE
	findings := Detect("INTO /* comment */ OUTFILE '/tmp/test'", "query")
	hasInto := false
	for _, f := range findings {
		if strings.Contains(f.Description, "INTO OUTFILE") {
			hasInto = true
		}
	}
	if !hasInto {
		t.Error("expected INTO OUTFILE detection with comment")
	}
}

func TestCheckStackedQuery_WithComment(t *testing.T) {
	// ; /* comment */ DROP
	findings := Detect("; /* comment */ DROP TABLE users", "query")
	hasStacked := false
	for _, f := range findings {
		if strings.Contains(f.Description, "Stacked query") {
			hasStacked = true
		}
	}
	if !hasStacked {
		t.Error("expected stacked query detection with comment between ; and keyword")
	}
}

func TestCheckTimeBasedBlind_WaitforDelay(t *testing.T) {
	// WAITFOR /* comment */ DELAY
	findings := Detect("WAITFOR DELAY '0:0:5'", "query")
	hasWaitfor := false
	for _, f := range findings {
		if strings.Contains(f.Description, "WAITFOR DELAY") {
			hasWaitfor = true
		}
	}
	if !hasWaitfor {
		t.Error("expected WAITFOR DELAY detection")
	}
}

func TestCheckTimeBasedBlind_WaitforWithoutDelay(t *testing.T) {
	// WAITFOR followed by something other than DELAY
	findings := Detect("WAITFOR TIME '12:00:00'", "query")
	// Should not detect WAITFOR DELAY specifically
	for _, f := range findings {
		if strings.Contains(f.Description, "WAITFOR DELAY") {
			t.Error("should not detect WAITFOR DELAY when TIME follows")
		}
	}
}

func TestTokenizer_AtSignIdentifier(t *testing.T) {
	tokens := Tokenize("@@version")
	found := false
	for _, tok := range tokens {
		if tok.Value == "@@version" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected @@version token, got %v", tokens)
	}
}

func TestTokenizer_DotInIdentifier(t *testing.T) {
	tokens := Tokenize("dbo.users")
	found := false
	for _, tok := range tokens {
		if tok.Value == "dbo.users" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected dbo.users token, got %v", tokens)
	}
}

func TestDetect_IsolatedKeywordScoring(t *testing.T) {
	// A single dangerous keyword should produce a low score
	findings := Detect("DROP", "query")
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore != 10 {
		t.Errorf("isolated keyword DROP: expected score 10, got %d", totalScore)
	}
}

func TestContainsSQLContent(t *testing.T) {
	if !containsSQLContent("hello OR world") {
		t.Error("expected true for 'hello OR world'")
	}
	if !containsSQLContent("SELECT something") {
		t.Error("expected true for 'SELECT something'")
	}
	if containsSQLContent("hello world") {
		t.Error("expected false for 'hello world'")
	}
	if !containsSQLContent("test SLEEP more") {
		t.Error("expected true for 'test SLEEP more'")
	}
}

func TestCheckUnionSelect_UnionWithoutSelect(t *testing.T) {
	// UNION followed by non-SELECT keyword -- should not trigger
	findings := Detect("UNION DROP", "query")
	hasUnionSelect := false
	for _, f := range findings {
		if strings.Contains(f.Description, "UNION SELECT") {
			hasUnionSelect = true
		}
	}
	if hasUnionSelect {
		t.Error("should not detect UNION SELECT when SELECT is not present")
	}
}

func TestCheckBooleanInjection_ANDWithoutPrecedingString(t *testing.T) {
	// AND with tautology but no preceding string literal
	findings := Detect("id AND 1=1", "query")
	hasBoolInjWithTautology := false
	for _, f := range findings {
		if strings.Contains(f.Description, "tautology") {
			hasBoolInjWithTautology = true
		}
	}
	// Should still detect tautology via OR/AND path
	if !hasBoolInjWithTautology {
		t.Error("expected tautology detection for 'id AND 1=1'")
	}
}

// --- Coverage gap tests for patterns.go ---

func TestDetect_BooleanTautology_1Equals1(t *testing.T) {
	// Standalone tautology pattern: 1=1
	findings := Detect("' OR 1=1", "query")
	hasTautologyFinding := false
	for _, f := range findings {
		if strings.Contains(f.Description, "tautology") {
			hasTautologyFinding = true
		}
	}
	if !hasTautologyFinding {
		t.Error("expected tautology finding for '1=1' pattern")
	}
}

func TestDetect_BooleanTautology_StringEqualsString(t *testing.T) {
	// String tautology: 'a'='a'
	findings := Detect("' OR 'a'='a'", "query")
	hasTautologyFinding := false
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
		if strings.Contains(f.Description, "tautology") {
			hasTautologyFinding = true
		}
	}
	if !hasTautologyFinding {
		t.Errorf("expected tautology finding for string equality, findings: %+v", findings)
	}
	if totalScore < 80 {
		t.Errorf("expected score >= 80 for string tautology, got %d", totalScore)
	}
}

func TestDetect_TimeBasedBlind_WaitforDelay(t *testing.T) {
	findings := Detect("WAITFOR DELAY '0:0:5'", "query")
	hasWaitfor := false
	for _, f := range findings {
		if strings.Contains(f.Description, "WAITFOR DELAY") {
			hasWaitfor = true
		}
	}
	if !hasWaitfor {
		t.Error("expected WAITFOR DELAY finding")
	}
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 90 {
		t.Errorf("expected score >= 90 for WAITFOR DELAY, got %d", totalScore)
	}
}

func TestDetect_ExecXpCmdshell(t *testing.T) {
	findings := Detect("EXEC xp_cmdshell 'dir'", "query")
	hasExec := false
	for _, f := range findings {
		if strings.Contains(f.Description, "EXEC") {
			hasExec = true
		}
	}
	if !hasExec {
		t.Error("expected EXEC finding for xp_cmdshell")
	}
	totalScore := 0
	for _, f := range findings {
		totalScore += f.Score
	}
	if totalScore < 80 {
		t.Errorf("expected score >= 80 for EXEC xp_cmdshell, got %d", totalScore)
	}
}

func TestDetect_ExecWithStringLiteral(t *testing.T) {
	// EXEC followed by a string literal directly
	findings := Detect("EXEC 'SELECT * FROM users'", "query")
	hasExec := false
	for _, f := range findings {
		if strings.Contains(f.Description, "EXEC") {
			hasExec = true
		}
	}
	if !hasExec {
		t.Error("expected EXEC/EXECUTE finding")
	}
}

func TestDetect_BooleanInjection_ANDTautology(t *testing.T) {
	// AND with tautology: 'x' AND 1=1
	findings := Detect("'x' AND 1=1", "query")
	hasTautology := false
	for _, f := range findings {
		if strings.Contains(f.Description, "tautology") {
			hasTautology = true
		}
	}
	if !hasTautology {
		t.Error("expected tautology finding for AND 1=1")
	}
}

func TestDetect_BooleanInjection_ORWithoutTautology(t *testing.T) {
	// 'x' OR something -- should detect boolean injection without tautology
	findings := Detect("'x' OR admin", "query")
	hasBooleanInjection := false
	for _, f := range findings {
		if strings.Contains(f.Description, "boolean-based") || strings.Contains(f.Description, "Boolean-based") {
			hasBooleanInjection = true
		}
	}
	if !hasBooleanInjection {
		t.Error("expected boolean injection finding for 'x' OR")
	}
}

func BenchmarkDetect(b *testing.B) {
	input := "' UNION SELECT username, password FROM users WHERE id=1 OR 1=1 --"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Detect(input, "query")
	}
}
