package botdetect

import (
	"strings"
	"testing"
)

func TestMoreScannerUserAgents(t *testing.T) {
	for _, ua := range []string{
		"Fuzz Faster U Fool v2.0.0",
		"feroxbuster/2.10.0",
		"WPScan v3.8.25 (https://wpscan.com/)",
		"Mozilla/5.0 (compatible; Nessus) mercuryboard_user_agent_sql_injection.nasl'",
		"commix/3.9",
	} {
		if _, ok := matchKnownScanner(strings.ToLower(ua)); !ok {
			t.Errorf("%q not recognised as a scanner", ua)
		}
	}
	for _, ua := range []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
		"curl/8.5.0",
		"Go-http-client/2.0",
	} {
		if s, ok := matchKnownScanner(strings.ToLower(ua)); ok {
			t.Errorf("%q wrongly matched scanner %q", ua, s)
		}
	}
}
