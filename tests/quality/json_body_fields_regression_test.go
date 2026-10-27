package quality

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Regression: text detectors read JSON bodies as raw text, so a payload in a
// field value hid inside the JSON string syntax ({"username":"admin' --"}
// scored 0) while ordinary values were misread (a markdown "# Title" after
// the opening quote looked like quote-then-comment and blocked).
func TestJSONBodyFieldsAreInspectedDecoded(t *testing.T) {
	eng := newPipeline(t)
	attacks := []string{"admin' --", "') OR ('1'='1", ";id", "${''.getClass().forName('java.lang.Runtime')}"}
	for i, payload := range attacks {
		r := placements["jsonfield"](payload)
		browserHeaders(r, i+1)
		if ev := eng.Check(r); ev.Action != engine.ActionBlock {
			t.Errorf("JSON field %q: action=%v score=%d, want block", payload, ev.Action, ev.Score)
		}
	}
	benign := []string{
		`{"markdown":"# Title\n\nSome **bold** text and a [link](https://example.com)."}`,
		`{"color":"#ff6600","note":"Leave at the back door; the dog's friendly :)"}`,
		`{"comment":"My surname is \"O'Connor\" and the form says it's invalid."}`,
	}
	for i, body := range benign {
		r := httptest.NewRequest(http.MethodPost, "/api/items", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		browserHeaders(r, 100+i)
		if ev := eng.Check(r); ev.Action == engine.ActionBlock {
			t.Errorf("benign JSON %s blocked: score=%d", body, ev.Score)
		}
	}
}
