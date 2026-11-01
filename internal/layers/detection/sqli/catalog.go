package sqli

import (
	"regexp"
	"strings"

	"github.com/guardianwaf/guardianwaf/internal/engine"
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

var selectWord = regexp.MustCompile(`\bselect\b[^;]{0,200}\bfrom\b`)
