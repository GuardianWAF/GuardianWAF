package botdetect

import "testing"

// FuzzUAParser drives ParseUserAgent with arbitrary UA strings.
// Properties: never panics; DeviceType stays inside the documented enum;
// IsBot exactly tracks DeviceType=="bot"; Browser and OS are never empty.
func FuzzUAParser(f *testing.F) {
	// Certification-pinned browser-ordering shapes (round 28 / 2026-09-18-r7).
	f.Add("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91")
	f.Add("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0")
	f.Add("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.50")
	f.Add("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/1.61")
	f.Add("Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36")
	f.Add("Mozilla/5.0 (Linux; U; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36 UCBrowser/15.4.5")
	f.Add("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0")
	f.Add("Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1")
	f.Add("Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)")
	// Bots and CLIs.
	f.Add("Googlebot/2.1 (+http://www.google.com/bot.html)")
	f.Add("sqlmap/1.7.11#stable (https://sqlmap.org)")
	f.Add("curl/8.4.0")
	f.Add("Wget/1.21.3 (linux-gnu)")
	// Hostile and edge shapes.
	f.Add("")
	f.Add("Edg/")
	f.Add("Chrome/")
	f.Add("OS ")
	f.Add("Android Android Android")
	f.Add("Version/")
	f.Add("rv:")
	f.Add("\x00\x01\x02 edg/ \x7f")
	f.Add("Mozilla/5.0 " + string(make([]byte, 64)) + " Safari/")
	f.Add("iPhone iPad Android Windows Mac OS X cros ubuntu freebsd")

	f.Fuzz(func(t *testing.T, ua string) {
		p := ParseUserAgent(ua)

		switch p.DeviceType {
		case "desktop", "mobile", "tablet", "bot", "cli", "unknown":
		default:
			t.Fatalf("DeviceType %q outside documented enum", p.DeviceType)
		}
		if p.IsBot != (p.DeviceType == "bot") {
			t.Fatalf("IsBot=%v but DeviceType=%q", p.IsBot, p.DeviceType)
		}
		if p.Browser == "" {
			t.Fatal("Browser empty")
		}
		if p.OS == "" {
			t.Fatal("OS empty")
		}
	})
}
