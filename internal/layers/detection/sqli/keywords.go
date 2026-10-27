package sqli

// keywordSet is a set of SQL keywords for O(1) lookup.
// Using a map since the set is small enough and map lookup is fast.
type keywordSet map[string]bool

var sqlKeywords = keywordSet{
	"SELECT": true, "UNION": true, "OR": true, "AND": true,
	"DROP": true, "INSERT": true, "UPDATE": true, "DELETE": true,
	"FROM": true, "WHERE": true, "HAVING": true, "GROUP": true,
	"ORDER": true, "BY": true, "LIMIT": true, "INTO": true,
	"EXEC": true, "EXECUTE": true, "DECLARE": true, "SET": true,
	"TRUNCATE": true, "ALTER": true, "CREATE": true,
	"TABLE": true, "DATABASE": true, "INDEX": true,
	"JOIN": true, "LEFT": true, "RIGHT": true, "INNER": true,
	"OUTER": true, "CROSS": true, "ON": true, "AS": true,
	"DISTINCT": true, "ALL": true, "EXISTS": true, "NOT": true,
	"NULL": true, "LIKE": true, "IN": true, "BETWEEN": true,
	"IS": true, "CASE": true, "WHEN": true, "THEN": true,
	"ELSE": true, "END": true, "IF": true, "WHILE": true,
	"BEGIN": true, "COMMIT": true, "ROLLBACK": true,
	"GRANT": true, "REVOKE": true, "TOP": true, "OFFSET": true,
	"FETCH": true, "NEXT": true, "ROWS": true,
	"VALUES": true, "PROCEDURE": true, "FUNCTION": true,
	"TRIGGER": true, "VIEW": true, "WITH": true,
}

var sqlFunctions = keywordSet{
	"COUNT": true, "SUM": true, "AVG": true, "MIN": true, "MAX": true,
	"SLEEP": true, "BENCHMARK": true, "WAITFOR": true, "DELAY": true,
	"LOAD_FILE": true, "OUTFILE": true, "DUMPFILE": true,
	"CHAR": true, "CONCAT": true, "SUBSTRING": true, "SUBSTR": true,
	"ASCII": true, "ORD": true, "HEX": true, "UNHEX": true,
	"MD5": true, "SHA1": true, "SHA2": true,
	"CONVERT": true, "CAST": true,
	"LENGTH": true, "LEN": true, "TRIM": true, "REPLACE": true,
	"UPPER": true, "LOWER": true, "REVERSE": true,
	"COALESCE": true, "NULLIF": true, "IIF": true,
	"GETDATE": true, "NOW": true, "SYSDATE": true,
	"USER": true, "CURRENT_USER": true, "SYSTEM_USER": true,
	"VERSION": true, "@@VERSION": true,
	"EXTRACTVALUE": true, "UPDATEXML": true,
	"GROUP_CONCAT": true, "STRING_AGG": true,
	"INFORMATION_SCHEMA": true,
}

var sqlOperators = keywordSet{
	"LIKE": true, "IN": true, "BETWEEN": true, "IS": true,
	"NOT": true, "EXISTS": true,
}

// wordClass is the token type and classUpper index of a classified SQL word.
type wordClass struct {
	typ   TokenType
	class uint8
}

// maxClassifiedWordLen is the longest word in any keyword set.
const maxClassifiedWordLen = 24

// classUpper holds the canonical upper-case spelling of every classified
// word; index 0 is reserved for "not classified".
var classUpper = []string{""}

// wordClasses maps every upper-case keyword, function and operator to its
// token type. Operators take precedence over functions, functions over
// keywords, matching the tokenizer's historical order.
var wordClasses = func() map[string]wordClass {
	m := make(map[string]wordClass, len(sqlKeywords)+len(sqlFunctions))
	for _, set := range []struct {
		words keywordSet
		typ   TokenType
	}{{sqlKeywords, TokenKeyword}, {sqlFunctions, TokenFunction}, {sqlOperators, TokenOperator}} {
		for w := range set.words {
			if len(w) > maxClassifiedWordLen {
				panic("sqli: keyword longer than maxClassifiedWordLen: " + w)
			}
			c, ok := m[w]
			if !ok {
				if len(classUpper) > 255 {
					panic("sqli: more classified words than a uint8 class index holds")
				}
				c.class = uint8(len(classUpper)) // #nosec G115 -- bounded above
				classUpper = append(classUpper, w)
			}
			c.typ = set.typ
			m[w] = c
		}
	}
	return m
}()

// classifyWord looks word up case-insensitively without allocating.
func classifyWord(word string) (wordClass, bool) {
	if len(word) > maxClassifiedWordLen {
		return wordClass{}, false
	}
	var buf [maxClassifiedWordLen]byte
	for i := range len(word) {
		c := word[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		buf[i] = c
	}
	c, ok := wordClasses[string(buf[:len(word)])]
	return c, ok
}

// IsKeyword returns true if the word (uppercase) is a SQL keyword.
func IsKeyword(word string) bool { return sqlKeywords[word] }

// IsFunction returns true if the word (uppercase) is a SQL function.
func IsFunction(word string) bool { return sqlFunctions[word] }

// IsOperatorKeyword returns true if the word is a SQL operator keyword.
func IsOperatorKeyword(word string) bool { return sqlOperators[word] }

// IsDangerousKeyword returns true for keywords that are high-risk in user input.
func IsDangerousKeyword(word string) bool {
	switch word {
	case "UNION", "SELECT", "DROP", "DELETE", "TRUNCATE", "INSERT", "UPDATE",
		"EXEC", "EXECUTE", "ALTER", "CREATE", "GRANT", "REVOKE":
		return true
	}
	return false
}

// IsDangerousFunction returns true for functions commonly used in attacks.
func IsDangerousFunction(word string) bool {
	switch word {
	case "SLEEP", "BENCHMARK", "WAITFOR", "DELAY",
		"LOAD_FILE", "OUTFILE", "DUMPFILE",
		"CHAR", "CONCAT", "SUBSTRING", "SUBSTR",
		"EXTRACTVALUE", "UPDATEXML",
		"GROUP_CONCAT", "STRING_AGG":
		return true
	}
	return false
}
