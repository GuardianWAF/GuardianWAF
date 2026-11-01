package xxe

import "testing"

func xxeTotal(in string) int {
	t := 0
	for _, f := range Detect(in, "body") {
		t += f.Score
	}
	return t
}

func TestEncodingEvasion(t *testing.T) {
	for _, a := range []string{
		"<?xml version=\"1.0\" encoding=\"UTF-7\"?>\n+ADwAIQ-DOCTYPE foo+AFs +ADwAIQ-ELEMENT foo ANY +AD4",
		`<?xml version="1.0" encoding='utf-7' ?><a/>`,
		`+ADwAIQ-DOCTYPE foo`,
		`<?xml version="1.0"?><xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:include schemaLocation="http://attacker.example/x.xsd"/></xs:schema>`,
		`<xsd:import namespace="a" schemaLocation="file:///etc/passwd"/>`,
		`<?xml version="1.0" encoding="utf-8" standalone="no" ?><xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:include namespace="http://xxe.example.com/"/></xs:schema>`,
		`<?xml version="1.0" encoding="utf-8" standalone="no" ?><x xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://xxe.example.com/"/>`,
	} {
		if got := xxeTotal(a); got < 50 {
			t.Errorf("Detect(%q) = %d, want >= 50", a, got)
		}
	}
	for _, b := range []string{
		`<?xml version="1.0" encoding="UTF-8"?><a/>`,
		`<?xml version="1.0" encoding="utf-16"?><a/>`,
		`<project xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd"/>`,
		`<xs:include schemaLocation="common.xsd"/>`,
		`UTF-7 is an old encoding used by some mail systems`,
		`1+1=2, so 2+2=4`,
	} {
		if got := xxeTotal(b); got >= 50 {
			t.Errorf("Detect(%q) = %d, want < 50", b, got)
		}
	}
}
