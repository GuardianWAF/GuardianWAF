package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestRuntimeRejectsStartupOnlyConfig(t *testing.T) {
	for _, body := range []string{
		`{"tls":{"listen":":10443"}}`,
		`{"tls":{"http_redirect":false}}`,
		`{"docker":{"socket_path":"/tmp/alternate-docker.sock"}}`,
		`{"ai_analysis":{"min_score":99}}`,
		`{"alerting":{"enabled":true}}`,
		`{"waf":{"challenge":{"enabled":false}}}`,
	} {
		t.Run(body, func(t *testing.T) {
			d := cfgAuditDashboard(t)
			old := d.engine.Config()
			rr := cfgAuditPut(t, d, body)
			if rr.Code != http.StatusConflict {
				t.Fatalf("PROBLEM CONFIRMED: EXPECTED: startup-only patch rejected with409; ACTUAL: status=%d body=%s", rr.Code, rr.Body.String())
			}
			if !reflect.DeepEqual(old, d.engine.Config()) {
				t.Fatal("rejected update changed running config")
			}
		})
	}
}

func TestRuntimeLiveModeAndThresholdControl(t *testing.T) {
	d := cfgAuditDashboard(t)
	rr := cfgAuditPut(t, d, `{"mode":"monitor","waf":{"detection":{"threshold":{"block":75}}}}`)
	if rr.Code != http.StatusOK || d.engine.Config().Mode != "monitor" || d.engine.Config().WAF.Detection.Threshold.Block != 75 {
		t.Fatalf("live control failed: %d %s", rr.Code, rr.Body.String())
	}
}

func TestRuntimeAcceptsUnchangedStartupFieldsFromConfigForm(t *testing.T) {
	d := cfgAuditDashboard(t)
	rr := httptest.NewRecorder()
	d.handleGetConfig(rr, httptest.NewRequest(http.MethodGet, "/api/v1/config", nil))
	var form map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &form); err != nil {
		t.Fatal(err)
	}
	form["mode"] = "monitor"
	data, err := json.Marshal(form)
	if err != nil {
		t.Fatal(err)
	}
	got := cfgAuditPut(t, d, string(data))
	if got.Code != http.StatusOK || d.engine.Config().Mode != "monitor" {
		t.Fatalf("unchanged startup fields must allow live form edits: %d %s", got.Code, got.Body.String())
	}
}
