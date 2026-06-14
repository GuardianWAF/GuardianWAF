package ato

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func TestAttemptTrackerMapsStayBounded(t *testing.T) {
	tracker := NewAttemptTracker()
	tracker.maxEntries = 2
	now := time.Now()

	for i := 0; i < 5; i++ {
		tracker.RecordAttempt(&LoginAttempt{
			IP:       net.ParseIP(fmt.Sprintf("192.0.2.%d", i+1)),
			Email:    fmt.Sprintf("user-%d@example.com", i),
			Password: fmt.Sprintf("password-%d", i),
			Time:     now,
		})
	}

	stats := tracker.Stats()
	if stats["tracked_ips"] > tracker.maxEntries {
		t.Fatalf("tracked IPs = %d, want <= %d", stats["tracked_ips"], tracker.maxEntries)
	}
	if stats["tracked_emails"] > tracker.maxEntries {
		t.Fatalf("tracked emails = %d, want <= %d", stats["tracked_emails"], tracker.maxEntries)
	}
	if stats["tracked_passwords"] > tracker.maxEntries {
		t.Fatalf("tracked passwords = %d, want <= %d", stats["tracked_passwords"], tracker.maxEntries)
	}
	if len(tracker.ipToEmails) > tracker.maxEntries {
		t.Fatalf("ipToEmails entries = %d, want <= %d", len(tracker.ipToEmails), tracker.maxEntries)
	}
	if len(tracker.emailToIPs) > tracker.maxEntries {
		t.Fatalf("emailToIPs entries = %d, want <= %d", len(tracker.emailToIPs), tracker.maxEntries)
	}
}

func TestAttemptTrackerInnerSetsStayBounded(t *testing.T) {
	tracker := NewAttemptTracker()
	tracker.maxEntries = 2
	now := time.Now()
	ip := net.ParseIP("192.0.2.200")

	for i := 0; i < 5; i++ {
		tracker.RecordAttempt(&LoginAttempt{
			IP:    ip,
			Email: fmt.Sprintf("target-%d@example.com", i),
			Time:  now,
		})
	}
	if got := len(tracker.ipToEmails[ip.String()]); got > tracker.maxEntries {
		t.Fatalf("emails per IP = %d, want <= %d", got, tracker.maxEntries)
	}

	tracker = NewAttemptTracker()
	tracker.maxEntries = 2
	email := "shared@example.com"
	for i := 0; i < 5; i++ {
		tracker.RecordAttempt(&LoginAttempt{
			IP:    net.ParseIP(fmt.Sprintf("198.51.100.%d", i+1)),
			Email: email,
			Time:  now,
		})
	}
	if got := len(tracker.emailToIPs[email]); got > tracker.maxEntries {
		t.Fatalf("IPs per email = %d, want <= %d", got, tracker.maxEntries)
	}
}

func TestAttemptTrackerBlockListsRespectMaxEntries(t *testing.T) {
	tracker := NewAttemptTracker()
	tracker.maxEntries = 2
	until := time.Now().Add(time.Hour)

	for i := 0; i < 5; i++ {
		tracker.BlockIP(net.ParseIP(fmt.Sprintf("203.0.113.%d", i+1)), until, "test")
		tracker.BlockEmail(fmt.Sprintf("blocked-%d@example.com", i), until, "test")
	}

	stats := tracker.Stats()
	if stats["tracked_ips"] > tracker.maxEntries || stats["blocked_ips"] > tracker.maxEntries {
		t.Fatalf("blocked IP state exceeded cap: stats=%v max=%d", stats, tracker.maxEntries)
	}
	if stats["tracked_emails"] > tracker.maxEntries || stats["blocked_emails"] > tracker.maxEntries {
		t.Fatalf("blocked email state exceeded cap: stats=%v max=%d", stats, tracker.maxEntries)
	}
}
