package nosqli

import (
	"fmt"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func jsScore(in string) int {
	t := 0
	for _, f := range Detect(in, "query") {
		t += f.Score
	}
	return t
}

func TestJSInjectionAttacks(t *testing.T) {
	for _, a := range []string{
		`', $or: [ {}, { 'order':'order`,
		`x'}, {$and: [ {}, {'a':'a`,
		`0;var date=new Date(); do{curDate = new Date();}while(curDate-date<10000)`,
		`;var date = new Date(); do{curDate = new Date();}while(curDate-date`,
		`db.injection.insert({success:1});`,
		`db.users.remove({})`,
		`db.dropDatabase()`,
		`db.getSiblingDB('admin').createUser({user:'x'})`,
		`__proto__[isAdmin]=true`,
		`{"__proto__": {"isAdmin": true}}`,
		`constructor.prototype.isAdmin=true`,
		`constructor[prototype][x]=1`,
		`__proto__[v-if]=_c.constructor('alert(1)')()`,
	} {
		if got := jsScore(a); got < 50 {
			t.Errorf("Detect(%q) = %d, want >= 50", a, got)
		}
	}
}

func TestJSInjectionBenign(t *testing.T) {
	for _, b := range []string{
		`{"$or": [{"a": 1}, {"b": 2}]}`, // quoted key: a normal filter
		`db.users.find({age: 30})`,      // read, not a change
		`the __proto__ property is deprecated`,
		`use constructor injection instead of setters`,
		`while waiting for the date to be confirmed`,
		`do the thing while the time allows`,
		`while (i < 10) { i++ }`,
		`we ran "db" in the lab and inserted samples`,
		`Date.now() is a monotonic-ish clock`,
		`a, or: either one`,
	} {
		if got := jsScore(b); got >= 50 {
			t.Errorf("Detect(%q) = %d, want < 50", b, got)
		}
	}
}

func TestJSONFieldWrittenWithUnicodeEscapes(t *testing.T) {
	// Every character of the payload as a \uXXXX escape, as GoTestWAF sends it.
	payload := `db.injection.insert%28%7Bsuccess:1%7D%29%3B`
	var esc string
	for _, r := range payload {
		esc += fmt.Sprintf(`\u%04x`, r)
	}
	ctx := &engine.RequestContext{
		ContentType:          "application/json",
		BodyString:           `{"test": true, "k": "` + esc + `"}`,
		BodyFields:           []string{"test", "k", payload},
		NormalizedBodyFields: []string{"test", "k", "db.injection.insert({success:1});"},
	}
	if res := NewDetector(true, 1.0).Process(ctx); res.Score < 50 {
		t.Fatalf("JSON field with unicode escapes scored %d, want >= 50", res.Score)
	}
}
