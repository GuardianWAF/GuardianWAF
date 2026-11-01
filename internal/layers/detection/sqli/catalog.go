package sqli

import (
	"regexp"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/textmatch"
)

// sysCatalog matches a database system catalog that application queries never
// read from user input: information_schema, SQLite and SQL Server catalogs,
// Oracle dictionary views, the MySQL account table and PostgreSQL catalogs.
var sysCatalog = regexp.MustCompile(`\b(?:information_schema\s*\.\s*(?:tables|columns|schemata|routines|views|statistics|user_privileges|processlist)|sqlite_master|sqlite_schema|sys\.(?:objects|columns|tables|databases|sql_logins)|sysobjects|syscolumns|sysdatabases|master\.\.sysdatabases|all_tab_columns|all_tables|user_tables|dba_users|mysql\.user|pg_catalog\s*\.|pg_tables|pg_shadow|pg_user)\b`)

// checkCatalogRecon flags a SELECT against a system catalog: the schema
// discovery step of every injection tool. The word "select" is required so a
// sentence that names a catalog (documentation, a question about
// information_schema) does not block.
func checkCatalogRecon(input, location string) []engine.Finding {
	// Gate on the raw input, ignoring case, before paying for a lowercased copy.
	if !catalogGate.ContainsFold(input) {
		return nil
	}
	lower := strings.ToLower(input)
	if !strings.Contains(lower, "select") {
		return nil
	}
	m := sysCatalog.FindString(lower)
	if m == "" || !selectWord.MatchString(lower) {
		return nil
	}
	return []engine.Finding{makeFinding(75, engine.SeverityHigh,
		"SELECT against a database system catalog (schema discovery)", m, location, 0.85)}
}

// catalogGate holds the literals every catalog name contains, so the expression
// below runs only on inputs that mention one.
var catalogGate = textmatch.New([]string{
	"information_schema", "sqlite_master", "sqlite_schema", "sys.objects", "sys.columns",
	"sys.tables", "sys.databases", "sys.sql_logins", "sysobjects", "syscolumns",
	"sysdatabases", "all_tab_columns", "all_tables", "user_tables", "dba_users",
	"mysql.user", "pg_catalog", "pg_tables", "pg_shadow", "pg_user",
})

var selectWord = regexp.MustCompile(`\bselect\b[^;]{0,200}\bfrom\b`)

// logicalTautology matches a quote breakout joined by || or && to an equality
// of the same operand: admin' || '1'=='1, x' && 'a'='a. Oracle and PostgreSQL
// read || as string concatenation or OR, MySQL (ANSI mode) as OR, and
// NoSQL/JavaScript backends as OR; all authenticate the attacker.
var logicalTautology = regexp.MustCompile(`(?i)['"]\s*(?:\|\||&&)\s*['"]?([\w.]+)['"]?\s*={1,3}\s*['"]?([\w.]+)`)

func checkLogicalTautology(input, location string) []engine.Finding {
	if (!strings.Contains(input, "||") && !strings.Contains(input, "&&")) ||
		(!strings.Contains(input, "'") && !strings.Contains(input, `"`)) {
		return nil
	}
	m := logicalTautology.FindStringSubmatch(input)
	if m == nil || !strings.EqualFold(m[1], m[2]) {
		return nil
	}
	return []engine.Finding{makeFinding(60, engine.SeverityHigh,
		"Boolean injection joined by || or && with a tautology", m[0], location, 0.85)}
}
