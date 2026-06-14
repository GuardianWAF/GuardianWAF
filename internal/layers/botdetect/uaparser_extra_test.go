package botdetect

import (
	"testing"
)

func TestDetectBotName(t *testing.T) {
	tests := []struct {
		ua       string
		expected string
	}{
		{"googlebot/2.1", "Googlebot"},
		{"compatible; bingbot/2.0", "Bingbot"},
		{"compatible; yandexbot/3.0", "YandexBot"},
		{"compatible; baiduspider/2.0", "Baiduspider"},
		{"duckduckbot/1.0", "DuckDuckBot"},
		{"facebookexternalhit/1.1", "Facebook"},
		{"twitterbot/1.0", "Twitterbot"},
		{"linkedinbot/1.0", "LinkedInBot"},
		{"applebot/0.1", "Applebot"},
		{"semrushbot/7", "SemrushBot"},
		{"ahrefsbot/7.0", "AhrefsBot"},
		{"sqlmap/1.5", "sqlmap"},
		{"nikto/2.1.6", "Nikto"},
		{"nmap scripting engine", "Nmap"},
		{"nuclei/2.9", "Nuclei"},
		{"burpsuite pro", "BurpSuite"},
		{"masscan/1.3", "Masscan"},
		{"zgrab/0.x", "ZGrab"},
		{"dirbuster/1.0", "DirBuster"},
		{"gobuster/3.1", "GoBuster"},
		{"wfuzz/3.1", "WFuzz"},
		{"ffuf/2.0", "FFUF"},
		{"myspider/1.0", "Spider"},
		{"mycrawler/1.0", "Crawler"},
		{"somebot/1.0", "Bot"},
		{"unknownagent/1.0", "Bot"},
	}
	for _, tt := range tests {
		got := detectBotName(tt.ua)
		if got != tt.expected {
			t.Errorf("detectBotName(%q) = %q, want %q", tt.ua, got, tt.expected)
		}
	}
}

func TestDetectBrowser(t *testing.T) {
	tests := []struct {
		ua      string
		browser string
		hasVer  bool
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0", "Edge", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0", "Opera", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.50", "Vivaldi", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Brave Chrome/120.0.0.0 Safari/537.36", "Brave", false},
		{"Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36", "Samsung Internet", true},
		{"Mozilla/5.0 (Linux; U; Android 11) AppleWebKit/537.36 (KHTML, like Gecko) UCBrowser/13.4.0.1306 Mobile Safari/537.36", "UC Browser", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", "Firefox", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Chrome", true},
		{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chromium/120.0.0.0 Safari/537.36", "Chromium", true},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15", "Safari", true},
		{"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)", "Internet Explorer", true},
		{"Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko", "Internet Explorer", true},
		{"some-unknown-agent/1.0", "Unknown", false},
	}
	for _, tt := range tests {
		lower := toLower(tt.ua)
		name, ver := detectBrowser(tt.ua, lower)
		if name != tt.browser {
			t.Errorf("detectBrowser(%q) name = %q, want %q", tt.ua[:min(40, len(tt.ua))], name, tt.browser)
		}
		if tt.hasVer && ver == "" {
			t.Errorf("detectBrowser(%q) expected version, got empty", tt.ua[:min(40, len(tt.ua))])
		}
	}
}

func TestDetectOS(t *testing.T) {
	tests := []struct {
		ua       string
		expected string
	}{
		{"Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36", "Android 13"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X)", "iOS 17.2"},
		{"Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X)", "iPadOS 17.2"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Windows 10/11"},
		{"Mozilla/5.0 (Windows NT 6.3; WOW64)", "Windows 8.1"},
		{"Mozilla/5.0 (Windows NT 6.1; Win64; x64)", "Windows 7"},
		{"Mozilla/5.0 (compatible; Windows; U; Windows 95)", "Windows"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "macOS 10.15.7"},
		{"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0)", "Chrome OS"},
		{"Mozilla/5.0 (X11; Ubuntu; Linux x86_64)", "Ubuntu Linux"},
		{"Mozilla/5.0 (X11; Fedora; Linux x86_64)", "Fedora Linux"},
		{"Mozilla/5.0 (X11; Linux x86_64)", "Linux"},
		{"Mozilla/5.0 (X11; FreeBSD amd64)", "FreeBSD"},
		{"SomeWeirdAgent/1.0", "Unknown"},
	}
	for _, tt := range tests {
		lower := toLower(tt.ua)
		got := detectOS(tt.ua, lower)
		if got != tt.expected {
			t.Errorf("detectOS(%q) = %q, want %q", tt.ua[:min(40, len(tt.ua))], got, tt.expected)
		}
	}
}

func TestDetectDeviceType(t *testing.T) {
	tests := []struct {
		lower    string
		os       string
		expected string
	}{
		{"mozilla/5.0 (ipad; cpu os 17_2)", "iPadOS 17.2", "tablet"},
		{"mozilla/5.0 (tablet; android 13)", "Android 13", "tablet"},
		{"mozilla/5.0 (iphone; cpu iphone os 17_2)", "iOS 17.2", "mobile"},
		{"mozilla/5.0 (linux; android 13; pixel 7) mobile", "Android 13", "mobile"},
		{"mozilla/5.0 (windows nt 10.0; win64; x64)", "Windows 10/11", "desktop"},
		{"mozilla/5.0 (macintosh; intel mac os x)", "macOS 10.15.7", "desktop"},
		{"mozilla/5.0 (x11; linux x86_64)", "Linux", "desktop"},
		{"mozilla/5.0 (x11; cros x86_64)", "Chrome OS", "desktop"},
		{"mozilla/5.0 (x11; freebsd amd64)", "FreeBSD", "desktop"},
		{"mozilla/5.0 (x11; ubuntu; linux)", "Ubuntu Linux", "desktop"},
		{"mozilla/5.0 (x11; fedora; linux)", "Fedora Linux", "desktop"},
		{"somebot/1.0", "Unknown", "unknown"},
	}
	for _, tt := range tests {
		got := detectDeviceType(tt.lower, tt.os)
		if got != tt.expected {
			t.Errorf("detectDeviceType(%q, %q) = %q, want %q", tt.lower[:min(30, len(tt.lower))], tt.os, got, tt.expected)
		}
	}
}

func TestDetectCLIName(t *testing.T) {
	tests := []struct {
		ua       string
		expected string
	}{
		{"curl/8.4.0", "curl"},
		{"wget/1.21", "wget"},
		{"httpie/3.2.1", "HTTPie"},
		{"libwww-perl/6.72", "libwww-perl"},
		{"python-requests/2.31.0", "Python Requests"},
		{"python-urllib/3.11", "Python urllib"},
		{"go-http-client/2.0", "Go HTTP"},
		{"okhttp/4.12.0", "OkHttp"},
		{"unknown-cli-tool/1.0", "CLI"},
	}
	for _, tt := range tests {
		got := detectCLIName(toLower(tt.ua))
		if got != tt.expected {
			t.Errorf("detectCLIName(%q) = %q, want %q", tt.ua, got, tt.expected)
		}
	}
}

func TestIsCLI(t *testing.T) {
	if !isCLI("curl/8.4.0") {
		t.Error("curl should be CLI")
	}
	if !isCLI("python-requests/2.31") {
		t.Error("python-requests should be CLI")
	}
	if isCLI("mozilla/5.0 chrome/120") {
		t.Error("chrome should not be CLI")
	}
}

func TestExtractVersion(t *testing.T) {
	tests := []struct {
		ua       string
		prefixes []string
		expected string
	}{
		{"Chrome/120.0.0.0 Safari/537.36", []string{"Chrome/"}, "120.0.0.0"},
		{"Firefox/121.0", []string{"Firefox/"}, "121.0"},
		{"no-match-here", []string{"Firefox/"}, ""},
		{"rv:11.0) like Gecko", []string{"MSIE ", "rv:"}, "11.0"},
	}
	for _, tt := range tests {
		got := extractVersion(tt.ua, tt.prefixes...)
		if got != tt.expected {
			t.Errorf("extractVersion(%q, %v) = %q, want %q", tt.ua, tt.prefixes, got, tt.expected)
		}
	}
}

func TestExtractOSVersion(t *testing.T) {
	tests := []struct {
		ua       string
		prefix   string
		expected string
	}{
		{"Android 13; Pixel", "Android ", " 13"},
		{"Mac OS X 10_15_7)", "Mac OS X ", " 10_15_7"},
		{"no match here", "Android ", ""},
		{"Android ; nothing", "Android ", ""},
	}
	for _, tt := range tests {
		got := extractOSVersion(tt.ua, tt.prefix)
		if got != tt.expected {
			t.Errorf("extractOSVersion(%q, %q) = %q, want %q", tt.ua, tt.prefix, got, tt.expected)
		}
	}
}

// toLower is a test helper to lowercase a string.
func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}
