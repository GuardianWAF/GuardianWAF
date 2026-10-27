package ato

import (
	"net"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestMonitorReportsBruteForceWithoutPersistingBan(t *testing.T) {
	layer, err := NewLayer(&Config{Enabled: true, LoginPaths: []string{"/login"}, BruteForce: BruteForceConfig{Enabled: true, Window: time.Hour, MaxAttemptsPerIP: 1, MaxAttemptsPerEmail: 100, BlockDuration: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("192.0.2.1")
	layer.tracker.RecordAttempt(&LoginAttempt{IP: ip, Email: "user@example.com", Time: time.Now()})
	ctx := &engine.RequestContext{ClientIP: ip, Path: "/login", Method: "POST", BodyString: `{"email":"user@example.com"}`, ObserveOnly: true}
	if result := layer.Process(ctx); result.Action != engine.ActionBlock {
		t.Fatal("monitor failed to observe brute force")
	}
	if blocked, _ := layer.tracker.IsIPBlocked(ip); blocked {
		t.Fatal("monitor persisted an IP ban")
	}
	ctx.ObserveOnly = false
	layer.Process(ctx)
	if blocked, _ := layer.tracker.IsIPBlocked(ip); !blocked {
		t.Fatal("enforce control failed to persist an IP ban")
	}
}
