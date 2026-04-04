package fingerprint

import (
	"net/http"
	"testing"
)

func TestNew(t *testing.T) {
	f := New()
	if f == nil {
		t.Fatal("expected fingerprinter, got nil")
	}
}

func TestFingerprinter_ExtractFromRequest(t *testing.T) {
	tests := []struct {
		name      string
		req       *http.Request
		wantAgent string
		wantLang  string
		wantPlat  string
	}{
		{
			name: "basic request",
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com/", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0)")
				req.Header.Set("Accept-Language", "en-US,en;q=0.9")
				return req
			}(),
			wantAgent: "Mozilla/5.0 (Windows NT 10.0)",
			wantLang:  "en-US,en;q=0.9",
			wantPlat:  "Windows",
		},
		{
			name: "macOS user agent",
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com/", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
				return req
			}(),
			wantAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
			wantPlat:  "macOS",
		},
		{
			name: "Linux user agent",
			req: func() *http.Request {
				req, _ := http.NewRequest("GET", "http://example.com/", nil)
				req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
				return req
			}(),
			wantAgent: "Mozilla/5.0 (X11; Linux x86_64)",
			wantPlat:  "Linux",
		},
		{
			name:      "minimal request",
			req:       &http.Request{},
			wantAgent: "",
			wantLang:  "",
			wantPlat:  "Unknown",
		},
	}

	f := New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := f.ExtractFromRequest(tt.req)

			if data.UserAgent != tt.wantAgent {
				t.Errorf("UserAgent = %v, want %v", data.UserAgent, tt.wantAgent)
			}
			if data.Language != tt.wantLang {
				t.Errorf("Language = %v, want %v", data.Language, tt.wantLang)
			}
			if data.Platform != tt.wantPlat {
				t.Errorf("Platform = %v, want %v", data.Platform, tt.wantPlat)
			}
		})
	}
}

func TestFingerprinter_Generate(t *testing.T) {
	f := New()

	tests := []struct {
		name string
		data *Data
		wantLen int
	}{
		{
			name: "full data",
			data: &Data{
				UserAgent: "Mozilla/5.0",
				Language:  "en-US",
				Platform:  "Windows",
				Timezone:  "America/New_York",
				Canvas:    "canvas-hash",
				WebGL:     "webgl-hash",
				Screen:    ScreenInfo{Width: 1920, Height: 1080, ColorDepth: 24, PixelRatio: 1},
			},
			wantLen: 32,
		},
		{
			name: "minimal data",
			data: &Data{
				UserAgent: "",
				Language:  "",
				Platform:  "Unknown",
				Screen:    ScreenInfo{Width: 0, Height: 0},
			},
			wantLen: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := f.Generate(tt.data)

			if len(hash) != tt.wantLen {
				t.Errorf("hash length = %d, want %d", len(hash), tt.wantLen)
			}

			// Same data should produce same hash
			hash2 := f.Generate(tt.data)
			if hash != hash2 {
				t.Error("same data should produce same hash")
			}

			// Different data should produce different hash
			if tt.name == "full data" {
				modifiedData := *tt.data
				modifiedData.Canvas = "different-hash"
				hash3 := f.Generate(&modifiedData)
				if hash == hash3 {
					t.Error("different data should produce different hash")
				}
			}
		})
	}
}

func TestFingerprinter_Analyze(t *testing.T) {
	f := New()

	tests := []struct {
		name     string
		data     *Data
		isBot    bool
		minScore int
		maxScore int
	}{
		{
			name: "normal browser",
			data: &Data{
				UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				Canvas:    "some-canvas-data",
				WebGL:     "some-webgl-data",
				Screen:    ScreenInfo{Width: 1920, Height: 1080},
				Plugins:   []string{"plugin1", "plugin2"},
			},
			isBot:    false,
			minScore: 0,
			maxScore: 100,
		},
		{
			name: "headless browser",
			data: &Data{
				UserAgent: "Mozilla/5.0 (HeadlessChrome/91.0)",
				Canvas:    "canvas-data",
				Screen:    ScreenInfo{Width: 1920, Height: 1080},
				Plugins:   []string{"plugin1"},
			},
			isBot:    true,
			minScore: 0,
			maxScore: 100,
		},
		{
			name: "missing fingerprint data",
			data: &Data{
				UserAgent: "Mozilla/5.0",
				Canvas:    "",
				WebGL:     "",
				Screen:    ScreenInfo{Width: 0, Height: 0},
				Plugins:   []string{},
			},
			isBot:    true,
			minScore: 0,
			maxScore: 50,
		},
		{
			name: "automation detected",
			data: &Data{
				UserAgent: "Mozilla/5.0",
				Canvas:    "undefined",
				WebGL:     "undefined",
				Screen:    ScreenInfo{Width: 1920, Height: 1080},
				Plugins:   []string{},
			},
			isBot:    true,
			minScore: 0,
			maxScore: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := f.Analyze(tt.data)

			if analysis == nil {
				t.Fatal("expected analysis, got nil")
			}

			if analysis.IsBot != tt.isBot {
				t.Errorf("IsBot = %v, want %v", analysis.IsBot, tt.isBot)
			}

			if analysis.Score < tt.minScore || analysis.Score > tt.maxScore {
				t.Errorf("Score = %d, want between %d and %d", analysis.Score, tt.minScore, tt.maxScore)
			}

			if analysis.Score < 0 {
				t.Error("Score should not be negative")
			}
			if analysis.Score > 100 {
				t.Error("Score should not exceed 100")
			}
		})
	}
}

func TestExtractPlatform(t *testing.T) {
	tests := []struct {
		ua   string
		want string
	}{
		{"Mozilla/5.0 (Windows NT 10.0)", "Windows"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "macOS"},
		{"Mozilla/5.0 (X11; Linux x86_64)", "Linux"},
		{"Mozilla/5.0 (Linux; Android 10)", "Android"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 14_0)", "iOS"},
		{"Mozilla/5.0 (iPad; CPU OS 14_0)", "iOS"},
		{"Some random browser", "Unknown"},
		{"", "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.ua, func(t *testing.T) {
			got := extractPlatform(tt.ua)
			if got != tt.want {
				t.Errorf("extractPlatform(%q) = %v, want %v", tt.ua, got, tt.want)
			}
		})
	}
}

func TestIsHeadless(t *testing.T) {
	tests := []struct {
		ua   string
		want bool
	}{
		{"Mozilla/5.0 (HeadlessChrome/91.0)", true},
		{"Mozilla/5.0 (Headless)", true},
		{"PhantomJS/2.1.1", true},
		{"Mozilla/5.0 (Selenium/Chrome)", true},
		{"Mozilla/5.0 Chrome/91.0 WebDriver", true},
		{"Mozilla/5.0 (Puppeteer/Chrome)", true},
		{"Mozilla/5.0 (Playwright/Chrome)", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", false},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X)", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ua, func(t *testing.T) {
			got := isHeadless(tt.ua)
			if got != tt.want {
				t.Errorf("isHeadless(%q) = %v, want %v", tt.ua, got, tt.want)
			}
		})
	}
}

func TestHasAutomationSignature(t *testing.T) {
	tests := []struct {
		name string
		data *Data
		want bool
	}{
		{
			name: "undefined canvas",
			data: &Data{Canvas: "undefined", Plugins: []string{"plugin"}},
			want: true,
		},
		{
			name: "undefined webgl",
			data: &Data{WebGL: "undefined", Plugins: []string{"plugin"}},
			want: true,
		},
		{
			name: "no plugins",
			data: &Data{Canvas: "data", WebGL: "data", Plugins: []string{}},
			want: true,
		},
		{
			name: "normal browser",
			data: &Data{Canvas: "data", WebGL: "data", Plugins: []string{"plugin1", "plugin2"}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasAutomationSignature(tt.data)
			if got != tt.want {
				t.Errorf("hasAutomationSignature() = %v, want %v", got, tt.want)
			}
		})
	}
}
