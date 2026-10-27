package sqli

import "testing"

func sqliScore(input string) int {
	total := 0
	for _, f := range Detect(input, "body") {
		total += f.Score
	}
	return total
}

// Regression: every distinct SQL keyword scored 10 and three or more added a
// 30-point bonus, so English prose naming the words blocked a request on its
// own. "the new select menu, an improved update flow ... the drop in latency"
// in a JSON field scored 60.
func TestProseKeywordsStayBelowBlockThreshold(t *testing.T) {
	for _, prose := range []string{
		"Our quarterly update covers the new select menu, an improved update flow for orders, and the drop in latency after moving the cache.",
		"You can create, update or delete a post, select a theme, drop a pin on the map, grant access to editors and alter the layout.",
		"Execute the plan: insert the new slide, truncate the intro and create a union of both teams.",
	} {
		if got := sqliScore(prose); got >= 50 {
			t.Errorf("prose scored %d, want < 50: %q", got, prose)
		}
	}
}

func TestSQLClausesKeepKeywordBonus(t *testing.T) {
	for _, attack := range []string{
		"1 UNION SELECT username, password FROM users",
		"x'; DROP TABLE users; DELETE FROM sessions --",
		"UPDATE users SET role='admin'; INSERT INTO log VALUES (1); SELECT * FROM t",
	} {
		if got := sqliScore(attack); got < 50 {
			t.Errorf("attack scored %d, want >= 50: %q", got, attack)
		}
	}
}

func TestCountSQLClauses(t *testing.T) {
	for in, want := range map[string]bool{
		"select menu and update flow":   false,
		"the drop in latency":           false,
		"delete from the list":          true,
		"UNION ALL SELECT 1":            true,
		"select * where":                true,
		"select name, id from users":    true,
		"update users set a=1":          true,
		"drop table users":              true,
		"exec xp_cmdshell 'dir'":        true,
		"grant all privileges on db":    true,
		"grant access to editors":       false,
		"1; delete everything":          true,
		"insert the slide into the doc": false,
	} {
		if got := countSQLClauses(filterSignificant(Tokenize(in)), 1) == 1; got != want {
			t.Errorf("countSQLClauses(%q) > 0 = %v, want %v", in, got, want)
		}
	}
}
