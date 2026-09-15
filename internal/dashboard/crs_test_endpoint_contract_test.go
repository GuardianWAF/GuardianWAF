package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/crs"
)

// TestCRSTestEndpoint_ReflectsRealEvaluation pins the CRS test endpoint's
// honesty contract: POST /api/crs/test must run the layer's real evaluation
// pipeline and report what it returns. The previous crsAdapter.Process was a
// hardcoded pass stub (score 0, action "pass", no findings) that
// manufactured a clean result for every request — an operator probing
// whether CRS catches an attack always saw a pass, so broken rule loads or
// disabled layers looked identical to a working CRS.
func TestCRSTestEndpoint_ReflectsRealEvaluation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.conf")
	rules := `SecRule ARGS:password "@contains secret" "id:1001,phase:1,deny,status:403,msg:'flagged value in ARGS',severity:'CRITICAL'"`
	if err := os.WriteFile(path, []byte(rules+"\n"), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	layer := crs.NewLayer(&crs.Config{Enabled: true, ParanoiaLevel: 1, AnomalyThreshold: 5})
	if err := layer.LoadRules(path); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	// Setup sanity: the real layer blocks the attack through the real
	// pipeline (rules loaded; ARGS populated from the request URI).
	req := httptest.NewRequest(http.MethodGet, "/login?password=secret123", nil)
	sanity := &engine.RequestContext{Method: req.Method, Headers: req.Header, Request: req}
	if res := layer.Process(sanity); res.Action != engine.ActionBlock {
		t.Fatalf("setup: real layer did not block the attack (action %v, score %d)", res.Action, res.Score)
	}

	d := &Dashboard{crsLayer: layer, mux: http.NewServeMux()}
	h := NewCRSHandler(d)

	post := func(target string) map[string]any {
		body := `{"method":"GET","path":"` + target + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/crs/test", strings.NewReader(body))
		w := httptest.NewRecorder()
		h.handleTest(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("handleTest %q: %d %s", target, w.Code, w.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode %q: %v", target, err)
		}
		return resp
	}

	attack := post("/login?password=secret123")
	score, _ := attack["score"].(float64)
	action, _ := attack["action"].(string)
	findings, _ := attack["findings"].([]any)
	if score <= 0 || action == "pass" || len(findings) == 0 {
		t.Fatalf("CRS test endpoint manufactures a pass for a rule-blocking attack: score=%v action=%q findings=%v",
			attack["score"], action, findings)
	}

	benign := post("/login?password=hello")
	if bscore, _ := benign["score"].(float64); bscore != 0 {
		t.Fatalf("benign request must score 0, got %v", benign)
	}
}
