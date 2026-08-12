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
	tracker.maxInnerEntries = 2
	now := time.Now()
	ip := net.ParseIP("192.0.2.200")

	for i := 0; i < 5; i++ {
		tracker.RecordAttempt(&LoginAttempt{
			IP:    ip,
			Email: fmt.Sprintf("target-%d@example.com", i),
			Time:  now,
		})
	}
	if got := len(tracker.ipToEmails[ip.String()]); got > tracker.maxInnerEntries {
		t.Fatalf("emails per IP = %d, want <= %d", got, tracker.maxInnerEntries)
	}

	tracker = NewAttemptTracker()
	tracker.maxEntries = 2
	tracker.maxInnerEntries = 2
	email := "shared@example.com"
	for i := 0; i < 5; i++ {
		tracker.RecordAttempt(&LoginAttempt{
			IP:    net.ParseIP(fmt.Sprintf("198.51.100.%d", i+1)),
			Email: email,
			Time:  now,
		})
	}
	if got := len(tracker.emailToIPs[email]); got > tracker.maxInnerEntries {
		t.Fatalf("IPs per email = %d, want <= %d", got, tracker.maxInnerEntries)
	}
}

func TestAttemptTrackerBlockListsAlwaysRecorded(t *testing.T) {
	tracker := NewAttemptTracker()
	tracker.maxEntries = 2
	until := time.Now().Add(time.Hour)

	// All 5 IPs/emails are actively blocked — none can be evicted.
	// The tracker must still record every block, growing past the cap
	// rather than silently dropping a security-critical block.
	for i := 0; i < 5; i++ {
		tracker.BlockIP(net.ParseIP(fmt.Sprintf("203.0.113.%d", i+1)), until, "test")
		tracker.BlockEmail(fmt.Sprintf("blocked-%d@example.com", i), until, "test")
	}

	stats := tracker.Stats()
	if stats["blocked_ips"] != 5 {
		t.Fatalf("all 5 blocked IPs must be tracked, got %d", stats["blocked_ips"])
	}
	if stats["blocked_emails"] != 5 {
		t.Fatalf("all 5 blocked emails must be tracked, got %d", stats["blocked_emails"])
	}

	// Verify each block is actually enforceable
	for i := 0; i < 5; i++ {
		blocked, _ := tracker.IsIPBlocked(net.ParseIP(fmt.Sprintf("203.0.113.%d", i+1)))
		if !blocked {
			t.Fatalf("IP 203.0.113.%d should be blocked", i+1)
		}
		blocked, _ = tracker.IsEmailBlocked(fmt.Sprintf("blocked-%d@example.com", i))
		if !blocked {
			t.Fatalf("email blocked-%d should be blocked", i)
		}
	}
}

func TestAttemptTrackerEvictsOldestNotBlocked(t *testing.T) {
	tracker := NewAttemptTracker()
	tracker.maxEntries = 3
	now := time.Now()

	// Fill with 3 IPs — first one is oldest
	for i := 0; i < 3; i++ {
		tracker.RecordAttempt(&LoginAttempt{
			IP:   net.ParseIP(fmt.Sprintf("10.0.0.%d", i+1)),
			Time: now.Add(time.Duration(i) * time.Minute),
		})
	}

	// 4th IP should evict the oldest (10.0.0.1)
	tracker.RecordAttempt(&LoginAttempt{
		IP:   net.ParseIP("10.0.0.99"),
		Time: now.Add(10 * time.Minute),
	})

	stats := tracker.Stats()
	if stats["tracked_ips"] > tracker.maxEntries {
		t.Fatalf("tracked IPs = %d, want <= %d", stats["tracked_ips"], tracker.maxEntries)
	}
	if _, exists := tracker.ipAttempts["10.0.0.1"]; exists {
		t.Fatal("oldest IP 10.0.0.1 should have been evicted")
	}
	if _, exists := tracker.ipAttempts["10.0.0.99"]; !exists {
		t.Fatal("newest IP 10.0.0.99 should be present")
	}
}

func TestAttemptTrackerDoesNotEvictActiveBlocks(t *testing.T) {
	tracker := NewAttemptTracker()
	tracker.maxEntries = 2
	until := time.Now().Add(time.Hour)

	// Fill with 2 actively-blocked IPs
	tracker.BlockIP(net.ParseIP("10.0.0.1"), until, "attack")
	tracker.BlockIP(net.ParseIP("10.0.0.2"), until, "attack")

	// 3rd blocked IP — both existing are still blocked so neither is evictable,
	// but the new block MUST still be recorded for security.
	tracker.BlockIP(net.ParseIP("10.0.0.3"), until, "attack")

	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		blocked, _ := tracker.IsIPBlocked(net.ParseIP(ip))
		if !blocked {
			t.Fatalf("IP %s must remain blocked", ip)
		}
	}
}
