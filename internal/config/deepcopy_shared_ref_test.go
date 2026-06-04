package config

import "testing"

// TestDeepCopy_NoSharedReferences locks in the fixes for three shared-reference
// bugs where DeepCopy used a shallow copy()/pointer assignment, so mutating a
// hot-reload snapshot also mutated the live config:
//   - AlertingConfig.Emails (nested To/Events slices were shared)
//   - ComplianceConfig.ScheduledReports (nested Format slices were shared)
//   - Config.AllowPrivateUpstreams (*bool pointer was shared — SSRF gate)
func TestDeepCopy_NoSharedReferences(t *testing.T) {
	orig := &Config{}
	priv := false
	orig.AllowPrivateUpstreams = &priv
	orig.Alerting.Emails = []EmailConfig{{
		Name:   "ops",
		To:     []string{"a@x.com"},
		Events: []string{"block"},
	}}
	orig.Compliance.ScheduledReports = []ScheduledReportConfig{{
		ID:     "r1",
		Format: []string{"json"},
	}}

	cp := orig.DeepCopy()

	// AllowPrivateUpstreams: distinct pointer, mutation isolated.
	if cp.AllowPrivateUpstreams == orig.AllowPrivateUpstreams {
		t.Fatal("AllowPrivateUpstreams shares the same *bool pointer")
	}
	*cp.AllowPrivateUpstreams = true
	if *orig.AllowPrivateUpstreams {
		t.Fatal("mutating copied AllowPrivateUpstreams leaked into original (SSRF gate)")
	}

	// Email nested slices: independent.
	cp.Alerting.Emails[0].To[0] = "evil@x.com"
	cp.Alerting.Emails[0].Events[0] = "tampered"
	if orig.Alerting.Emails[0].To[0] != "a@x.com" {
		t.Fatal("Email.To slice is shared between copy and original")
	}
	if orig.Alerting.Emails[0].Events[0] != "block" {
		t.Fatal("Email.Events slice is shared between copy and original")
	}

	// ScheduledReports nested slice: independent.
	cp.Compliance.ScheduledReports[0].Format[0] = "csv"
	if orig.Compliance.ScheduledReports[0].Format[0] != "json" {
		t.Fatal("ScheduledReport.Format slice is shared between copy and original")
	}
}
