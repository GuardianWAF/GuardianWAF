package ipacl

// Regression (new-series round 10): the ban-persistence loop must not take
// the process down on a non-positive persist interval.
//
// NewLayer starts the persistence goroutine with the operator-supplied
// interval. Before the fix it floored only a ZERO value:
//
//	interval := cfgCopy.AutoBan.PersistInterval
//	if interval == 0 {
//	    interval = 30 * time.Second
//	}
//	go l.persistLoop(interval)
//
// persistLoop calls time.NewTicker(interval), and time.NewTicker PANICS on a
// non-positive interval. A negative persist_interval therefore panicked inside
// an unrecovered goroutine — which takes the whole WAF process down, instead
// of the interval being floored the way every other interval in this codebase
// is (the AI analyzer self-defaults AutoBlockTTL<=0, the threat-intel feed
// defaults a non-positive refresh, the health checker defaults a non-positive
// interval, and so on). The floor is now `interval <= 0`.
//
// A panic in a goroutine cannot be observed from the test that triggers it (it
// kills the test binary), so the crash is driven in a child process and the
// parent asserts on the child's exit — the standard Go pattern for crash
// regressions.

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const ipaclPersistChildEnv = "GWAF_IPACL_PERSIST_CHILD"

func TestPersistLoopSurvivesNonPositiveInterval(t *testing.T) {
	if os.Getenv(ipaclPersistChildEnv) == "1" {
		// Child: build the layer exactly as the layer registry does, with a
		// non-positive persist interval.
		layer, err := NewLayer(&Config{
			Enabled: true,
			AutoBan: AutoBanConfig{
				Enabled:           true,
				DefaultTTL:        time.Hour,
				MaxAutoBanEntries: 100,
				PersistPath:       filepath.Join(os.TempDir(), "gwaf-persist-bans.json"),
				PersistInterval:   -5 * time.Second,
			},
		})
		if err != nil {
			os.Exit(3)
		}
		// Give the persistence goroutine time to start (and, pre-fix, panic).
		time.Sleep(200 * time.Millisecond)
		layer.Stop()
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestPersistLoopSurvivesNonPositiveInterval")
	cmd.Env = append(os.Environ(), ipaclPersistChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building the IP-ACL layer with a non-positive auto-ban persist interval "+
			"crashed the process: %v\n%s", err, out)
	}
}
