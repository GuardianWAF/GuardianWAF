package dashboard

// Regression tests for round 15/25: handlePatchDetail's PUT must honor the
// bool returned by EnablePatchBy/DisablePatchBy. The pre-fix implementation
// ignored it and answered {"enabled": <requested>} with 200 regardless, so a
// PUT against a nonexistent or typo'd patch ID returned fake success while
// the patch state never changed — the operator's emergency enable/kill-switch
// flow failed silently. The sibling DELETE got the honest contract (404 when
// the layer reports the patch missing) in round 63; PUT mirrors it here.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type putRecordingVP struct {
	enableCalls  []string
	disableCalls []string
	enableOK     bool
	disableOK    bool
}

func (s *putRecordingVP) GetActivePatches() []*VirtualPatchInfo { return nil }
func (s *putRecordingVP) GetPatch(id string) *VirtualPatchInfo  { return nil }
func (s *putRecordingVP) AddPatch(patch *VirtualPatchInfo)      {}
func (s *putRecordingVP) EnablePatch(id string) bool            { return s.EnablePatchBy(id, "test") }
func (s *putRecordingVP) EnablePatchBy(id, actor string) bool {
	s.enableCalls = append(s.enableCalls, id+"/"+actor)
	return s.enableOK
}
func (s *putRecordingVP) DisablePatch(id string) bool { return s.DisablePatchBy(id, "test") }
func (s *putRecordingVP) DisablePatchBy(id, actor string) bool {
	s.disableCalls = append(s.disableCalls, id+"/"+actor)
	return s.disableOK
}
func (s *putRecordingVP) GetStats() VirtualPatchStats { return VirtualPatchStats{} }
func (s *putRecordingVP) TriggerUpdate()              {}

func putPatchDetail(t *testing.T, stub *putRecordingVP, id string, body string) *httptest.ResponseRecorder {
	t.Helper()
	d := &Dashboard{virtualPatchOverride: stub}
	h := &VirtualPatchHandler{dashboard: d}
	req := httptest.NewRequest(http.MethodPut, "/api/virtualpatch/patches/"+id, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.handlePatchDetail(rec, req)
	return rec
}

func TestVirtualPatchPutUnknownIDDisableReturns404(t *testing.T) {
	// Unknown patch ID: the layer reports false (nothing changed).
	stub := &putRecordingVP{enableOK: false, disableOK: false}

	rec := putPatchDetail(t, stub, "typo-or-nonexistent", `{"enabled": false}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("PUT on an unknown patch ID answered HTTP %d with body %q while DisablePatchBy returned false (the patch state never changed) — want 404 like the sibling DELETE", rec.Code, rec.Body.String())
	}
}

func TestVirtualPatchPutUnknownIDEnableReturns404(t *testing.T) {
	// Enable direction against an unknown patch ID: same fake success.
	stub := &putRecordingVP{enableOK: false, disableOK: false}

	rec := putPatchDetail(t, stub, "typo-or-nonexistent", `{"enabled": true}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("PUT (enable) on an unknown patch ID answered HTTP %d with body %q while EnablePatchBy returned false (the patch was never applied) — want 404 like the sibling DELETE", rec.Code, rec.Body.String())
	}
}

func TestVirtualPatchPutSuccessControl(t *testing.T) {
	// Control: a real patch ID (the layer reports true) stays a 200 and must
	// reach the layer with the dashboard actor.
	stub := &putRecordingVP{enableOK: true, disableOK: true}

	rec := putPatchDetail(t, stub, "real-patch", `{"enabled": true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT on an existing patch answered HTTP %d, want 200 — the fix broke the happy path", rec.Code)
	}
	if len(stub.enableCalls) != 1 || stub.enableCalls[0] != "real-patch/dashboard" {
		t.Fatalf("EnablePatchBy calls = %v, want [real-patch/dashboard]", stub.enableCalls)
	}
}
