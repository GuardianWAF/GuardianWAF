package sqli

import "strings"

// TokenType represents the type of a SQL token.
type TokenType int

const (
	TokenStringLiteral  TokenType = iota // 'value', "value"
	TokenNumericLiteral                  // 123, 0x1A, 0b1010
	TokenKeyword                         // SELECT, UNION, OR, AND, etc.
	TokenOperator                        // =, <>, !=, >=, <=, LIKE, IN, BETWEEN, IS
	TokenFunction                        // COUNT, SLEEP, CHAR, CONCAT, etc.
	TokenComment                         // --, #, /* */
	TokenParenOpen                       // (
	TokenParenClose                      // )
	TokenSemicolon                       // ;
	TokenComma                           // ,
	TokenWildcard                        // *
	TokenWhitespace                      // space, tab, newline
	TokenOther                           // anything else
)

// String returns a human-readable name for the token type.
func (t TokenType) String() string {
	switch t {
	case TokenStringLiteral:
		return "StringLiteral"
	case TokenNumericLiteral:
		return "NumericLiteral"
	case TokenKeyword:
		return "Keyword"
	case TokenOperator:
		return "Operator"
	case TokenFunction:
		return "Function"
	case TokenComment:
		return "Comment"
	case TokenParenOpen:
		return "ParenOpen"
	case TokenParenClose:
		return "ParenClose"
	case TokenSemicolon:
		return "Semicolon"
	case TokenComma:
		return "Comma"
	case TokenWildcard:
		return "Wildcard"
	case TokenWhitespace:
		return "Whitespace"
	case TokenOther:
		return "Other"
	default:
		return "Unknown"
	}
}

// Token represents a single token from the input.
type Token struct {
	Type  TokenType
	Value string
	Pos   int // position in input
}

// Tokenize parses the input string into a sequence of SQL tokens.
// It operates as a state machine: read char, classify, emit token, repeat.
// No regex is used on the hot path.
func Tokenize(input string) []Token {
	tokens := make([]Token, 0, 32)
	i := 0
	n := len(input)

	for i < n {
		ch := input[i]

		// 1. Whitespace
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			start := i
			for i < n && (input[i] == ' ' || input[i] == '\t' || input[i] == '\n' || input[i] == '\r') {
				i++
			}
			tokens = append(tokens, Token{Type: TokenWhitespace, Value: input[start:i], Pos: start})
			continue
		}

		// 2. String literals: single quote, double quote, backtick
		// For SQL injection detection, an unmatched opening quote is common
		// (e.g., "' OR 1=1 --"). We use a heuristic: if the content between
		// the opening and closing quote contains SQL keywords, treat the opening
		// quote as a standalone token (injection marker). This prevents the
		// tokenizer from swallowing injected SQL syntax inside a "string".
		if ch == '\'' || ch == '"' || ch == '`' {
			start := i
			quote := ch
			j := i + 1 // scan ahead
			closed := false
			containsSQLKeyword := false
			for j < n {
				c := input[j]
				if c == '\\' {
					j += 2
					if j > n {
						j = n
					}
					continue
				}
				if c == quote {
					if j+1 < n && input[j+1] == quote {
						j += 2
						continue
					}
					j++
					closed = true
					break
				}
				j++
			}

			if closed {
				// Check if the content between quotes looks like it contains SQL keywords.
				// This catches patterns like ' OR ' where the quote-delimited content
				// is actually injected SQL, not a real string value.
				inner := input[start+1 : j-1]
				containsSQLKeyword = containsSQLContent(inner)
			}

			if closed && !containsSQLKeyword {
				// Proper string literal with matching quotes and no SQL injection
				tokens = append(tokens, Token{Type: TokenStringLiteral, Value: input[start:j], Pos: start})
				i = j
			} else {
				// Either unterminated quote or the "string" contains SQL keywords
				// (likely injection). Emit just the quote as a string literal.
				tokens = append(tokens, Token{Type: TokenStringLiteral, Value: string(quote), Pos: start})
				i = start + 1
			}
			continue
		}

		// 3. Comments
		// -- single line comment
		if ch == '-' && i+1 < n && input[i+1] == '-' {
			start := i
			i += 2
			for i < n && input[i] != '\n' {
				i++
			}
			tokens = append(tokens, Token{Type: TokenComment, Value: input[start:i], Pos: start})
			continue
		}

		// # single line comment
		if ch == '#' {
			start := i
			i++
			for i < n && input[i] != '\n' {
				i++
			}
			tokens = append(tokens, Token{Type: TokenComment, Value: input[start:i], Pos: start})
			continue
		}

		// /* multi-line comment */
		if ch == '/' && i+1 < n && input[i+1] == '*' {
			start := i
			i += 2
			for i+1 < n {
				if input[i] == '*' && input[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
			// Handle unterminated comment
			if i >= n && !(i >= 2 && input[i-2] == '*' && input[i-1] == '/') {
				i = n
			}
			tokens = append(tokens, Token{Type: TokenComment, Value: input[start:i], Pos: start})
			continue
		}

		// 4. Numeric literals
		if isDigit(ch) || (ch == '0' && i+1 < n && (input[i+1] == 'x' || input[i+1] == 'X' || input[i+1] == 'b' || input[i+1] == 'B')) {
			start := i
			if ch == '0' && i+1 < n && (input[i+1] == 'x' || input[i+1] == 'X') {
				// Hex literal: 0x...
				i += 2
				for i < n && isHexDigit(input[i]) {
					i++
				}
			} else if ch == '0' && i+1 < n && (input[i+1] == 'b' || input[i+1] == 'B') {
				// Binary literal: 0b...
				i += 2
				for i < n && (input[i] == '0' || input[i] == '1') {
					i++
				}
			} else {
				// Decimal
				for i < n && isDigit(input[i]) {
					i++
				}
				// Handle decimal point
				if i < n && input[i] == '.' {
					i++
					for i < n && isDigit(input[i]) {
						i++
					}
				}
			}
			tokens = append(tokens, Token{Type: TokenNumericLiteral, Value: input[start:i], Pos: start})
			continue
		}

		// 5. Operators
		if ch == '=' {
			tokens = append(tokens, Token{Type: TokenOperator, Value: "=", Pos: i})
			i++
			continue
		}
		if ch == '!' && i+1 < n && input[i+1] == '=' {
			tokens = append(tokens, Token{Type: TokenOperator, Value: "!=", Pos: i})
			i += 2
			continue
		}
		if ch == '<' {
			if i+1 < n && input[i+1] == '>' {
				tokens = append(tokens, Token{Type: TokenOperator, Value: "<>", Pos: i})
				i += 2
				continue
			}
			if i+1 < n && input[i+1] == '=' {
				tokens = append(tokens, Token{Type: TokenOperator, Value: "<=", Pos: i})
				i += 2
				continue
			}
			tokens = append(tokens, Token{Type: TokenOperator, Value: "<", Pos: i})
			i++
			continue
		}
		if ch == '>' {
			if i+1 < n && input[i+1] == '=' {
				tokens = append(tokens, Token{Type: TokenOperator, Value: ">=", Pos: i})
				i += 2
				continue
			}
			tokens = append(tokens, Token{Type: TokenOperator, Value: ">", Pos: i})
			i++
			continue
		}

		// 6. Special single-char tokens
		if ch == '(' {
			tokens = append(tokens, Token{Type: TokenParenOpen, Value: "(", Pos: i})
			i++
			continue
		}
		if ch == ')' {
			tokens = append(tokens, Token{Type: TokenParenClose, Value: ")", Pos: i})
			i++
			continue
		}
		if ch == ';' {
			tokens = append(tokens, Token{Type: TokenSemicolon, Value: ";", Pos: i})
			i++
			continue
		}
		if ch == ',' {
			tokens = append(tokens, Token{Type: TokenComma, Value: ",", Pos: i})
			i++
			continue
		}
		if ch == '*' {
			tokens = append(tokens, Token{Type: TokenWildcard, Value: "*", Pos: i})
			i++
			continue
		}

		// 7. Words: keywords, functions, operator keywords, identifiers
		if isAlpha(ch) || ch == '_' || ch == '@' {
			start := i
			for i < n && (isAlpha(input[i]) || isDigit(input[i]) || input[i] == '_' || input[i] == '@' || input[i] == '.') {
				i++
			}
			word := input[start:i]
			upper := strings.ToUpper(word)

			if IsOperatorKeyword(upper) {
				tokens = append(tokens, Token{Type: TokenOperator, Value: word, Pos: start})
			} else if IsFunction(upper) {
				tokens = append(tokens, Token{Type: TokenFunction, Value: word, Pos: start})
			} else if IsKeyword(upper) {
				tokens = append(tokens, Token{Type: TokenKeyword, Value: word, Pos: start})
			} else {
				tokens = append(tokens, Token{Type: TokenOther, Value: word, Pos: start})
			}
			continue
		}

		// 8. Anything else: emit as single-char Other token
		tokens = append(tokens, Token{Type: TokenOther, Value: string(ch), Pos: i})
		i++
	}

	return tokens
}

// isDigit returns true if ch is an ASCII digit.
func isDigit(ch byte) bool {
	return ch >= '0' && ch <= '9'
}

// isAlpha returns true if ch is an ASCII letter.
func isAlpha(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

// isHexDigit returns true if ch is a valid hexadecimal digit.
func isHexDigit(ch byte) bool {
	return isDigit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}

// containsSQLContent checks if a string fragment (the inner content of a
// quoted string) contains SQL keywords or operators, which would indicate
// the "string" is actually injected SQL rather than a legitimate value.
// This is a lightweight scan that extracts words and checks them against
// the keyword/function/operator tables.
func containsSQLContent(s string) bool {
	upper := strings.ToUpper(s)
	n := len(upper)
	i := 0
	for i < n {
		// Skip non-alpha
		if !isAlpha(upper[i]) {
			i++
			continue
		}
		// Extract word
		start := i
		for i < n && (isAlpha(upper[i]) || upper[i] == '_') {
			i++
		}
		word := upper[start:i]
		// Check against the injection-relevant keyword sets
		if IsDangerousKeyword(word) || IsOperatorKeyword(word) {
			return true
		}
		// Check SQL functions (WAITFOR, DELAY, SLEEP, LOAD_FILE, OUTFILE, etc.)
		if IsDangerousFunction(word) {
			return true
		}
		// Check common SQL keywords used in injection contexts
		switch word {
		case "OR", "AND", "INTO", "FROM", "WHERE", "SET", "VALUES",
			"HAVING", "ORDER", "GROUP", "LIMIT", "OFFSET", "WAITFOR":
			return true
		}
	}
	return false
}
