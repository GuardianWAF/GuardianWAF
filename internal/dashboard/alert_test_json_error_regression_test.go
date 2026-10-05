package dashboard

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAlertingTestDecodeErrorSingleResponse(t *testing.T) {
	calls := 0
	d := &Dashboard{}
	d.SetAlertingTestFn(func(string) error { calls++; return nil })
	for _, tc := range []struct {
		body    string
		status  int
		message string
	}{
		{`{"target":`, 400, "invalid JSON"},
		{`{"target":"ordinary"} {}`, 400, "invalid JSON"},
		{`{"target":"` + strings.Repeat("x", maxRequestBody) + `"}`, 413, "request body too large"},
		{`{}`, 400, "target is required"},
	} {
		rr := httptest.NewRecorder()
		d.handleTestAlert(rr, httptest.NewRequest("POST", "/api/v1/alerting/test", strings.NewReader(tc.body)))
		var response map[string]string
		if rr.Code != tc.status || json.Unmarshal(rr.Body.Bytes(), &response) != nil || response["error"] != tc.message {
			t.Fatalf("status=%d body=%q want status=%d error=%q", rr.Code, rr.Body.String(), tc.status, tc.message)
		}
	}
	if calls != 0 {
		t.Fatal("invalid request dispatched an alert")
	}
	rr := httptest.NewRecorder()
	d.handleTestAlert(rr, httptest.NewRequest("POST", "/api/v1/alerting/test", strings.NewReader(`{"target":"ordinary"}`)))
	if rr.Code != 200 || !json.Valid(rr.Body.Bytes()) || calls != 1 {
		t.Fatal("valid dispatch changed")
	}
}
