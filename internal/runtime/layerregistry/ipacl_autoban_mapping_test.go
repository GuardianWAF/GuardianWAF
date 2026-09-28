package layerregistry

// Regression (round 2026-09-28-layerregistry-ipacl-autoban-mapping): buildIPACL
// mapped only AutoBan{Enabled, DefaultTTL, MaxTTL} — config.AutoBanConfig's
// persist_path, persist_interval, and max_auto_ban_entries were silently
// dropped, so serve-mode auto-ban persistence never ran (LoadBans requires a
// non-empty PersistPath; NewLayer skips it otherwise) and the ban-entry cap
// was silently unlimited. The prior round-78 "all 16 builders faithful"
// verdict missed the nested AutoBan sub-struct; this failing-then-passing
// proof is the corrective evidence. Serve mode is the sole consumer of the
// builder — cmd/guardianwaf only type-asserts the registry-built layer.

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/layers/ipacl"
)

func ctxWithClientIP(t *testing.T, ip string) *engine.RequestContext {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	ctx := engine.AcquireContext(r, 1, 1<<20)
	ctx.ClientIP = net.ParseIP(ip)
	return ctx
}

// Defect case 1: a bans file referenced by auto_ban.persist_path must be
// loaded at build time — the banned IP must be blocked by the built layer.
func TestBuildIPACL_PersistedBansLoaded(t *testing.T) {
	dir := t.TempDir()
	bansPath := filepath.Join(dir, "bans.json")
	seed := []map[string]any{{
		"ip":         "203.0.113.77",
		"reason":     "seeded-by-regression",
		"expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
		"count":      1,
	}}
	data, err := json.Marshal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bansPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.WAF.IPACL.Enabled = true
	cfg.WAF.IPACL.AutoBan.Enabled = true
	cfg.WAF.IPACL.AutoBan.PersistPath = bansPath
	cfg.WAF.IPACL.AutoBan.PersistInterval = 30 * time.Second

	built, ok, err := BuildLayer("ip_acl", cfg)
	if err != nil || !ok {
		t.Fatalf("BuildLayer(ip_acl): ok=%v err=%v", ok, err)
	}
	layer := built.Layer.(*ipacl.Layer)
	defer layer.Stop()

	// Defect assertion: the persisted ban must block its IP.
	if res := layer.Process(ctxWithClientIP(t, "203.0.113.77")); res.Action != engine.ActionBlock {
		t.Fatalf("FAIL: banned IP from persist_path got %s, want ActionBlock (LoadBans never ran)", res.Action)
	}
	// Control: an unbanned IP passes.
	if res := layer.Process(ctxWithClientIP(t, "198.51.100.5")); res.Action != engine.ActionPass {
		t.Fatalf("FAIL: clean IP got %s, want ActionPass", res.Action)
	}
}

// Defect case 2: max_auto_ban_entries must reach the layer — the ban store
// never holds more than the cap (pre-fix it was silently unlimited).
func TestBuildIPACL_MaxAutoBanEntriesRespected(t *testing.T) {
	cfg := &config.Config{}
	cfg.WAF.IPACL.Enabled = true
	cfg.WAF.IPACL.AutoBan.Enabled = true
	cfg.WAF.IPACL.AutoBan.MaxAutoBanEntries = 2

	built, ok, err := BuildLayer("ip_acl", cfg)
	if err != nil || !ok {
		t.Fatalf("BuildLayer(ip_acl): ok=%v err=%v", ok, err)
	}
	layer := built.Layer.(*ipacl.Layer)
	defer layer.Stop()

	for _, ip := range []string{"10.1.1.1", "10.1.1.2", "10.1.1.3"} {
		layer.AddAutoBan(ip, "regression", time.Hour)
	}
	if got := len(layer.ActiveBans()); got > 2 {
		t.Fatalf("FAIL: %d active bans with max_auto_ban_entries=2 (silently unlimited)", got)
	}
}

// Control: the pre-existing blacklist mapping keeps working through the same
// seam (guards against over-correcting the fix).
func TestBuildIPACL_BlacklistStillMapped(t *testing.T) {
	cfg := &config.Config{}
	cfg.WAF.IPACL.Enabled = true
	cfg.WAF.IPACL.Blacklist = []string{"203.0.113.77"}

	built, ok, err := BuildLayer("ip_acl", cfg)
	if err != nil || !ok {
		t.Fatalf("BuildLayer(ip_acl): ok=%v err=%v", ok, err)
	}
	layer := built.Layer.(*ipacl.Layer)
	defer layer.Stop()

	if res := layer.Process(ctxWithClientIP(t, "203.0.113.77")); res.Action != engine.ActionBlock {
		t.Fatalf("FAIL: blacklisted IP got %s, want ActionBlock", res.Action)
	}
}
