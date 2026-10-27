package sqli

import (
	"testing"
	"unsafe"
)

// Large bodies tokenize into tens of thousands of tokens; growing Token
// slowed small inputs measurably (BenchmarkSQLiTokenizer/simple_sqli +38%
// at 48 bytes).
func TestTokenStaysCompact(t *testing.T) {
	if got := unsafe.Sizeof(Token{}); got > 32 {
		t.Fatalf("Token is %d bytes, want <= 32", got)
	}
}

func TestClassifyWordCaseInsensitive(t *testing.T) {
	for word, want := range map[string]TokenType{"select": TokenKeyword, "SeLeCt": TokenKeyword, "like": TokenOperator, "Sleep": TokenFunction} {
		c, ok := classifyWord(word)
		if !ok || c.typ != want {
			t.Errorf("classifyWord(%q) = %v %v, want %v", word, c.typ, ok, want)
		}
	}
	if _, ok := classifyWord("selection"); ok {
		t.Error("classifyWord matched a non-keyword")
	}
	toks := Tokenize("SeLeCt x")
	if got := tokenUpperValue(toks[0]); got != "SELECT" {
		t.Errorf("tokenUpperValue = %q, want SELECT", got)
	}
}
