package botdetect

import "strings"

// ParsedUA holds the structured result of User-Agent string parsing.
type ParsedUA struct {
	Browser    string // e.g., "Chrome", "Firefox", "Safari", "Edge", "Opera", "curl"
	BrVersion  string // e.g., "120.0", "121.0"
	OS         string // e.g., "Windows 11", "macOS", "Linux", "Android 14", "iOS 17"
	DeviceType string // "desktop", "mobile", "tablet", "bot", "cli", "unknown"
	IsBot      bool
}

// ParseUserAgent extracts browser, OS, device type, and bot status from a UA string.
// Zero external dependencies — uses only string matching heuristics.
func ParseUserAgent(ua string) ParsedUA {
	if ua == "" {
		return ParsedUA{Browser: "Unknown", OS: "Unknown", DeviceType: "unknown", IsBot: false}
	}

	lower := strings.ToLower(ua)
	p := ParsedUA{}

	// --- Bot detection ---
	p.IsBot = isBot(lower)
	if p.IsBot {
		p.Browser = detectBotName(lower)
		p.DeviceType = "bot"
		p.OS = "Unknown"
		return p
	}

	// --- CLI tools ---
	if isCLI(lower) {
		p.Browser = detectCLIName(lower)
		p.DeviceType = "cli"
		p.OS = "Unknown"
		return p
	}

	// --- OS detection (order matters) ---
	p.OS = detectOS(ua, lower)

	// --- Device type ---
	p.DeviceType = detectDeviceType(lower, p.OS)

	// --- Browser detection (order matters due to UA string overloading) ---
	p.Browser, p.BrVersion = detectBrowser(ua, lower)

	return p
}

// --- Bot detection ---

func isBot(lower string) bool {
	botPatterns := []string{
		"googlebot", "bingbot", "yandexbot", "baiduspider", "duckduckbot",
		"slurp", "facebot", "facebookexternalhit", "twitterbot", "linkedinbot",
		"applebot", "mj12bot", "semrushbot", "ahrefsbot", "dotbot",
		"spider", "crawler", "scraper", "bot/", "bot;",
		"sqlmap", "nikto", "nmap", "nuclei", "burpsuite", "masscan",
		"zgrab", "dirbuster", "gobuster", "wfuzz", "ffuf",
	}
	for _, pat := range botPatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

func detectBotName(lower string) string {
	bots := []struct{ pattern, name string }{
		{"googlebot", "Googlebot"},
		{"bingbot", "Bingbot"},
		{"yandexbot", "YandexBot"},
		{"baiduspider", "Baiduspider"},
		{"duckduckbot", "DuckDuckBot"},
		{"facebookexternalhit", "Facebook"},
		{"twitterbot", "Twitterbot"},
		{"linkedinbot", "LinkedInBot"},
		{"applebot", "Applebot"},
		{"semrushbot", "SemrushBot"},
		{"ahrefsbot", "AhrefsBot"},
		{"sqlmap", "sqlmap"},
		{"nikto", "Nikto"},
		{"nmap", "Nmap"},
		{"nuclei", "Nuclei"},
		{"burpsuite", "BurpSuite"},
		{"masscan", "Masscan"},
		{"zgrab", "ZGrab"},
		{"dirbuster", "DirBuster"},
		{"gobuster", "GoBuster"},
		{"wfuzz", "WFuzz"},
		{"ffuf", "FFUF"},
	}
	for _, b := range bots {
		if strings.Contains(lower, b.pattern) {
			return b.name
		}
	}
	if strings.Contains(lower, "spider") {
		return "Spider"
	}
	if strings.Contains(lower, "crawler") {
		return "Crawler"
	}
	if strings.Contains(lower, "bot") {
		return "Bot"
	}
	return "Bot"
}

// --- CLI tools ---

func isCLI(lower string) bool {
	cliPatterns := []string{"curl/", "wget/", "httpie/", "libwww-perl", "python-requests", "python-urllib", "go-http-client", "java/", "okhttp/"}
	for _, pat := range cliPatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

func detectCLIName(lower string) string {
	tools := []struct{ pattern, name string }{
		{"curl/", "curl"},
		{"wget/", "wget"},
		{"httpie/", "HTTPie"},
		{"libwww-perl", "libwww-perl"},
		{"python-requests", "Python Requests"},
		{"python-urllib", "Python urllib"},
		{"go-http-client", "Go HTTP"},
		{"okhttp/", "OkHttp"},
	}
	for _, t := range tools {
		if strings.Contains(lower, t.pattern) {
			return t.name
		}
	}
	return "CLI"
}

// --- OS detection ---

func detectOS(ua, lower string) string {
	// Mobile OS first (more specific)
	if strings.Contains(lower, "android") {
		return "Android" + extractOSVersion(ua, "Android ")
	}
	if strings.Contains(lower, "iphone") || strings.Contains(lower, "ipad") {
		ver := extractOSVersion(ua, "OS ")
		ver = strings.ReplaceAll(ver, "_", ".")
		if strings.Contains(lower, "ipad") {
			return "iPadOS" + ver
		}
		return "iOS" + ver
	}

	// Desktop OS
	if strings.Contains(lower, "windows") {
		if strings.Contains(ua, "Windows NT 10.0") {
			// Windows 10 or 11 — check for newer builds
			return "Windows 10/11"
		}
		if strings.Contains(ua, "Windows NT 6.3") {
			return "Windows 8.1"
		}
		if strings.Contains(ua, "Windows NT 6.1") {
			return "Windows 7"
		}
		return "Windows"
	}
	if strings.Contains(lower, "macintosh") || strings.Contains(lower, "mac os x") {
		ver := extractOSVersion(ua, "Mac OS X ")
		ver = strings.ReplaceAll(ver, "_", ".")
		return "macOS" + ver
	}
	if strings.Contains(lower, "cros") {
		return "Chrome OS"
	}
	if strings.Contains(lower, "linux") {
		if strings.Contains(lower, "ubuntu") {
			return "Ubuntu Linux"
		}
		if strings.Contains(lower, "fedora") {
			return "Fedora Linux"
		}
		return "Linux"
	}
	if strings.Contains(lower, "freebsd") {
		return "FreeBSD"
	}
	return "Unknown"
}

func extractOSVersion(ua, prefix string) string {
	idx := strings.Index(ua, prefix)
	if idx < 0 {
		return ""
	}
	start := idx + len(prefix)
	end := start
	for end < len(ua) && (ua[end] >= '0' && ua[end] <= '9' || ua[end] == '.' || ua[end] == '_') {
		end++
	}
	if end > start {
		return " " + ua[start:end]
	}
	return ""
}

// --- Device type ---

func detectDeviceType(lower, os string) string {
	// Tablet check first (iPad UA contains "Mobile" too)
	if strings.Contains(lower, "tablet") || strings.Contains(lower, "ipad") {
		return "tablet"
	}
	if strings.Contains(lower, "mobile") || strings.Contains(lower, "iphone") ||
		(strings.Contains(lower, "android") && !strings.Contains(lower, "tablet")) {
		return "mobile"
	}
	if strings.HasPrefix(os, "Windows") || strings.HasPrefix(os, "macOS") ||
		strings.HasPrefix(os, "Linux") || strings.HasPrefix(os, "Chrome OS") ||
		strings.HasPrefix(os, "FreeBSD") || strings.HasPrefix(os, "Ubuntu") ||
		strings.HasPrefix(os, "Fedora") {
		return "desktop"
	}
	return "unknown"
}

// --- Browser detection ---

func detectBrowser(ua, lower string) (name, version string) {
	// Order matters: check specific browsers before generic ones
	// Edge (Chromium-based) must be checked before Chrome
	if strings.Contains(lower, "edg/") || strings.Contains(lower, "edge/") {
		return "Edge", extractVersion(ua, "Edg/", "Edge/")
	}
	// Opera / OPR
	if strings.Contains(lower, "opr/") || strings.Contains(lower, "opera") {
		return "Opera", extractVersion(ua, "OPR/", "Opera/")
	}
	// Vivaldi
	if strings.Contains(lower, "vivaldi/") {
		return "Vivaldi", extractVersion(ua, "Vivaldi/")
	}
	// Brave
	if strings.Contains(lower, "brave") {
		return "Brave", extractVersion(ua, "Brave/")
	}
	// Samsung Internet
	if strings.Contains(lower, "samsungbrowser/") {
		return "Samsung Internet", extractVersion(ua, "SamsungBrowser/")
	}
	// UC Browser
	if strings.Contains(lower, "ucbrowser/") {
		return "UC Browser", extractVersion(ua, "UCBrowser/")
	}
	// Firefox (must be before Chrome since Chrome UA sometimes contains "like Gecko")
	if strings.Contains(lower, "firefox/") {
		return "Firefox", extractVersion(ua, "Firefox/")
	}
	// Chrome (must be after Edge/Opera/Vivaldi/Brave which also contain "Chrome/")
	if strings.Contains(lower, "chrome/") && !strings.Contains(lower, "chromium") {
		return "Chrome", extractVersion(ua, "Chrome/")
	}
	if strings.Contains(lower, "chromium/") {
		return "Chromium", extractVersion(ua, "Chromium/")
	}
	// Safari (must be last — many browsers claim Safari compatibility)
	if strings.Contains(lower, "safari/") && !strings.Contains(lower, "chrome") {
		return "Safari", extractVersion(ua, "Version/")
	}
	// IE
	if strings.Contains(lower, "msie") || strings.Contains(lower, "trident/") {
		return "Internet Explorer", extractVersion(ua, "MSIE ", "rv:")
	}
	return "Unknown", ""
}

func extractVersion(ua string, prefixes ...string) string {
	for _, prefix := range prefixes {
		idx := strings.Index(ua, prefix)
		if idx < 0 {
			continue
		}
		start := idx + len(prefix)
		end := start
		for end < len(ua) && (ua[end] >= '0' && ua[end] <= '9' || ua[end] == '.') {
			end++
		}
		if end > start {
			return ua[start:end]
		}
	}
	return ""
}
