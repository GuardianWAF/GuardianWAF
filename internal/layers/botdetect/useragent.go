package botdetect

import (
	"strings"
)

// knownScanners lists User-Agent substrings associated with security scanning tools.
var knownScanners = []string{
	"sqlmap", "nikto", "nmap", "masscan", "nuclei", "httpx",
	"dirbuster", "gobuster", "ffuf", "wfuzz", "burpsuite",
	"acunetix", "nessus", "openvas", "w3af", "zap",
	"arachni", "skipfish", "whatweb", "wafw00f",
}

// knownGoodBots lists User-Agent substrings for legitimate crawlers.
var knownGoodBots = []string{
	"googlebot", "bingbot", "yandexbot", "baiduspider",
	"duckduckbot", "slurp", "facebot", "twitterbot",
	"linkedinbot", "discordbot", "telegrambot",
}

// outdatedBrowserIndicators lists tokens that indicate outdated browsers.
var outdatedBrowserIndicators = []struct {
	token      string
	maxVersion int
}{
	{"msie 6", 0},
	{"msie 7", 0},
	{"msie 8", 0},
	{"msie 9", 0},
	{"chrome/4", 49},
	{"firefox/3", 39},
}

// AnalyzeUserAgent analyzes the User-Agent header and returns a threat score and description.
func AnalyzeUserAgent(ua string) (score int, description string) {
	// Empty User-Agent
	if ua == "" {
		return 40, "empty User-Agent header"
	}

	lower := strings.ToLower(ua)

	// Check for known scanner tools
	for _, scanner := range knownScanners {
		if strings.Contains(lower, scanner) {
			return 85, "known scanner tool: " + scanner
		}
	}

	// User-Agent length check
	if len(ua) > 512 {
		return 20, "excessively long User-Agent"
	}

	// Check for bot/crawler strings
	if strings.Contains(lower, "bot") || strings.Contains(lower, "crawler") || strings.Contains(lower, "spider") {
		// Check if it is a known good bot
		for _, goodBot := range knownGoodBots {
			if strings.Contains(lower, goodBot) {
				return 0, "known good bot: " + goodBot
			}
		}
		return 30, "unknown bot or crawler"
	}

	// Check for outdated browsers
	for _, indicator := range outdatedBrowserIndicators {
		if strings.Contains(lower, indicator.token) {
			return 25, "outdated browser detected"
		}
	}

	// Check for curl, wget, and similar tools
	if strings.HasPrefix(lower, "curl/") || strings.HasPrefix(lower, "wget/") || strings.HasPrefix(lower, "libwww-perl") {
		return 15, "command-line HTTP client"
	}

	// Normal browser
	return 0, "normal browser"
}
