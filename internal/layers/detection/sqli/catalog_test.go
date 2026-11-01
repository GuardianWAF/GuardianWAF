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
