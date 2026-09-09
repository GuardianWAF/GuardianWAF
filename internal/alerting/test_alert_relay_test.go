package alerting

// Regression: Manager.TestAlert relayed nothing — both delivery branches
//
// Defect: Manager.TestAlert returns nil for every existing target — both
// delivery branches (m.send for webhooks, m.SendEmail for emails) discard
// the delivery result internally (stats+log only), so a test-alert reports
// success whether or not the alert actually delivered. Round-81 wired the
// dashboard to this method; the false "ok" now flows all the way to the
// operator.

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/config"
)

func TestAlertRelaysDeliveryFailure(t *testing.T) {
	m := NewManagerWithEmail(nil, []config.EmailConfig{{
		Name:     "test-email",
		SMTPHost: "127.0.0.1",
		SMTPPort: 2525, // closed port: delivery fails instantly
		From:     "waf@guardianwaf.test",
		To:       []string{"ops@guardianwaf.test"},
	}})

	if err := m.TestAlert("test-email"); err == nil {
		t.Fatalf("FAIL: TestAlert returned nil for an email target whose SMTP delivery failed — both delivery branches discard the result, so a broken alert target can never be detected through the test path")
	}
}
