// Package fingerprint provides browser fingerprinting for bot detection.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// Data represents browser fingerprint data.
type Data struct {
	Canvas     string `json:"canvas,omitempty"`
	WebGL      string `json:"webgl,omitempty"`
	Fonts      []string `json:"fonts,omitempty"`
	Plugins    []string `json:"plugins,omitempty"`
	Screen     ScreenInfo `json:"screen"`
	Timezone   string `json:"timezone"`
	Language   string `json:"language"`
	Platform   string `json:"platform"`
	UserAgent  string `json:"ua"`
}

// ScreenInfo represents screen information.
type ScreenInfo struct {
	Width      int `json:"width"`
	Height     int `json:"height"`
	ColorDepth int `json:"colorDepth"`
	PixelRatio float64 `json:"pixelRatio"`
}

// Fingerprinter generates browser fingerprints.
type Fingerprinter struct{}

// New creates a new fingerprinter.
func New() *Fingerprinter {
	return &Fingerprinter{}
}

// ExtractFromRequest extracts fingerprint data from HTTP request.
func (f *Fingerprinter) ExtractFromRequest(req *http.Request) *Data {
	return &Data{
		UserAgent: req.UserAgent(),
		Language:  req.Header.Get("Accept-Language"),
		Platform:  extractPlatform(req.UserAgent()),
		Timezone:  req.Header.Get("X-Timezone"), // Custom header from JS
	}
}

// Generate creates a fingerprint hash from data.
func (f *Fingerprinter) Generate(data *Data) string {
	// Combine multiple factors
	components := []string{
		data.UserAgent,
		data.Language,
		data.Platform,
		data.Timezone,
		data.Canvas,
		data.WebGL,
		fmt.Sprintf("%dx%d", data.Screen.Width, data.Screen.Height),
	}

	input := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])[:32]
}

// Analyze analyzes fingerprint for bot indicators.
func (f *Fingerprinter) Analyze(data *Data) *Analysis {
	analysis := &Analysis{
		Score:      50,
		Indicators: []string{},
	}

	// Check for missing data
	if data.Canvas == "" && data.WebGL == "" {
		analysis.Score -= 20
		analysis.Indicators = append(analysis.Indicators, "missing_fingerprint_data")
	}

	// Check for headless browser signatures
	if isHeadless(data.UserAgent) {
		analysis.Score -= 30
		analysis.Indicators = append(analysis.Indicators, "headless_browser")
	}

	// Check for automation signatures
	if hasAutomationSignature(data) {
		analysis.Score -= 40
		analysis.Indicators = append(analysis.Indicators, "automation_detected")
	}

	// Check for unusual screen size
	if data.Screen.Width == 0 || data.Screen.Height == 0 {
		analysis.Score -= 10
		analysis.Indicators = append(analysis.Indicators, "missing_screen_info")
	}

	if analysis.Score < 0 {
		analysis.Score = 0
	}
	if analysis.Score > 100 {
		analysis.Score = 100
	}

	// Determine if this is a bot based on score
	analysis.IsBot = analysis.Score < 50

	return analysis
}

// Analysis contains fingerprint analysis.
type Analysis struct {
	Score      int
	Hash       string
	Indicators []string
	IsBot      bool
}

// extractPlatform extracts platform from User-Agent.
func extractPlatform(ua string) string {
	ua = strings.ToLower(ua)

	if strings.Contains(ua, "windows") {
		return "Windows"
	}
	if strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os") {
		return "macOS"
	}
	// Check mobile platforms before Linux
	if strings.Contains(ua, "android") {
		return "Android"
	}
	if strings.Contains(ua, "ios") || strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") {
		return "iOS"
	}
	// Generic Linux (not Android)
	if strings.Contains(ua, "linux") {
		return "Linux"
	}

	return "Unknown"
}

// isHeadless checks for headless browser signatures.
func isHeadless(ua string) bool {
	ua = strings.ToLower(ua)
	headlessIndicators := []string{
		"headlesschrome",
		"headless",
		"phantomjs",
		"selenium",
		"webdriver",
		"puppeteer",
		"playwright",
	}

	for _, indicator := range headlessIndicators {
		if strings.Contains(ua, indicator) {
			return true
		}
	}
	return false
}

// hasAutomationSignature checks for automation signatures.
func hasAutomationSignature(data *Data) bool {
	// Check for common automation patterns
	if data.Canvas == "undefined" || data.WebGL == "undefined" {
		return true
	}

	// Check for missing plugins (automation tools often don't implement this)
	if len(data.Plugins) == 0 {
		return true
	}

	return false
}
