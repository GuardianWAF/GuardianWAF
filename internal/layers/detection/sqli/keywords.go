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
