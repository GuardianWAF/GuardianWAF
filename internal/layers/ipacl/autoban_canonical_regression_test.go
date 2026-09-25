package ipacl

// Regression (round 2026-09-24-r26-autoban-canonical): AddAutoBan stored bans
// under the RAW argument string while isAutoBanned looks up ip.String() of the
// engine-resolved client (canonical form) — a ban added as "2001:0DB8::1"
// never blocked the client resolved as "2001:db8::1" (phantom enforcement:
// ActiveBans showed an active ban that did not block). AddAutoBan, LoadBans,
// and RemoveAutoBan now canonicalize at the store boundary; LoadBans also
// skips non-IP entries left by pre-validation legacy persistence files.

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestAutoBanCanonicalEnforcement(t *testing.T) {
	l, err := NewLayer(&Config{
		Enabled: true,
		AutoBan: AutoBanConfig{Enabled: true},
	})
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}

	l.AddAutoBan("2001:0DB8::1", "ai verdict", time.Minute)
	if !l.isAutoBanned("2001:db8::1") {
		t.Fatal("non-canonically-spelled ban not enforced against the canonical client")
	}

	res := l.Process(&engine.RequestContext{ClientIP: net.ParseIP("2001:db8::1")})
	if res.Action != engine.ActionBlock {
		t.Fatalf("Process did not block the auto-banned client: %v", res.Action)
	}

	// Removal by canonical spelling clears the canonical key.
	l.RemoveAutoBan("2001:db8::1")
	if l.isAutoBanned("2001:db8::1") {
		t.Fatal("ban survived canonical removal")
	}
}

func TestLoadBansSkipsGarbageAndCanonicalizes(t *testing.T) {
	l, err := NewLayer(&Config{
		Enabled: true,
		AutoBan: AutoBanConfig{Enabled: true},
	})
	if err != nil {
		t.Fatalf("NewLayer: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "bans.json")
	content := `[
		{"ip":"2001:0DB8::9","reason":"legacy spelling","expires_at":"2099-01-01T00:00:00Z","count":1},
		{"ip":"not-an-ip","reason":"pre-validation garbage","expires_at":"2099-01-01T00:00:00Z","count":1}
	]`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write bans file: %v", err)
	}

	l.LoadBans(path)

	if !l.isAutoBanned("2001:db8::9") {
		t.Fatal("valid persisted ban not loaded/enforced")
	}
	if l.isAutoBanned("not-an-ip") {
		t.Fatal("garbage key loaded from legacy file")
	}
}
