package sqli

import "testing"

func catalogTotal(in string) int {
	t := 0
	for _, f := range Detect(in, "query") {
		t += f.Score
	}
	return t
}

func TestCatalogRecon(t *testing.T) {
	for _, a := range []string{
		`(select group_concat(table_name,0x3a,column_name,0x5c6e) from information_schema.columns where table_schema=database())`,
		`1 union select table_name from information_schema.tables`,
		`' and 1=(select count(*) from sqlite_master)--`,
		`x' union select name from sysobjects where xtype='U'--`,
		`select username,password from mysql.user`,
		`select tablename from pg_catalog.pg_tables`,
		`select owner from all_tables`,
	} {
		if got := catalogTotal(a); got < 50 {
			t.Errorf("Detect(%q) = %d, want >= 50", a, got)
		}
	}
	for _, b := range []string{
		`how do I list tables? information_schema.tables is the answer`,
		`information_schema documentation`,
		`the sqlite_master table stores the schema`,
		`please select the file from the list`,
		`select your plan from the menu`,
		`mysql.user is a table in the mysql database`,
	} {
		if got := catalogTotal(b); got >= 50 {
			t.Errorf("Detect(%q) = %d, want < 50", b, got)
		}
	}
}

func TestSubqueryAndLogicalForms(t *testing.T) {
	for _, a := range []string{
		`1' || (SELECT 1 FROM dual)||'`,
		`1' RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))--`,
		`1 AND 1=(SELECT COUNT(*) FROM tablenames); --`,
		`admin' || '1'=='1`,
		`x' && 'a'='a`,
		`' || 1==1 --`,
	} {
		if got := catalogTotal(a); got < 50 {
			t.Errorf("Detect(%q) = %d, want >= 50", a, got)
		}
	}
	for _, b := range []string{
		`Q&A: what is the difference between == and ===?`,
		`== and === differ in type coercion`,
		`(select your plan from the menu)`,
		`please (select a size from the list) before continuing`,
		`x = y || z is a short-circuit idiom in JavaScript`,
		`use && and || to combine conditions`,
		`Tom's 'cat' || 'dog' debate`,
	} {
		if got := catalogTotal(b); got >= 50 {
			t.Errorf("Detect(%q) = %d, want < 50", b, got)
		}
	}
}

func TestCookieProseKeepsLowScore(t *testing.T) {
	for _, b := range []string{
		`I need to update my address and drop off a package`,
		`salt and pepper, then update the recipe and drop the garlic`,
	} {
		if !(isSQLishPattern(b) == false) {
			t.Errorf("isSQLishPattern(%q) = true, want false", b)
		}
	}
	for _, a := range []string{`admin OR 1=1`, `x AND 1`, `a OR 'b'='b`, `x AND (select 1)`, `1 UNION SELECT 1`, `a OR -1=-1`} {
		if !isSQLishPattern(a) {
			t.Errorf("isSQLishPattern(%q) = false, want true", a)
		}
	}
}
