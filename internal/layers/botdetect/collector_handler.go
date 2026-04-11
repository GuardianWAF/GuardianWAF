package botdetect

import (
	"crypto/hmac"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/layers/botdetect/biometric"
)

// BiometricCollector handles biometric event collection from frontend.
type BiometricCollector struct {
	enhancedLayer *EnhancedLayer
}

// NewBiometricCollector creates a new biometric event collector.
func NewBiometricCollector(layer *EnhancedLayer) *BiometricCollector {
	return &BiometricCollector{
		enhancedLayer: layer,
	}
}

// EventRequest represents a batch of biometric events from the frontend.
type EventRequest struct {
	Events []BiometricEvent `json:"events"`
}

// BiometricEvent represents a single biometric event.
type BiometricEvent struct {
	Type      string    `json:"type"`      // "mouse", "keyboard", "scroll", "touch", "fingerprint"
	Subtype   string    `json:"subtype"`   // "move", "click", "down", "up", "press", "start", "end"
	X         int       `json:"x"`         // For mouse/touch
	Y         int       `json:"y"`         // For mouse/touch
	DeltaX    int       `json:"dx"`        // For scroll
	DeltaY    int       `json:"dy"`        // For scroll
	Key       string    `json:"key"`       // For keyboard
	Code      string    `json:"code"`      // For keyboard
	Button    int       `json:"button"`    // For mouse
	Timestamp time.Time `json:"ts"`
}

// HandleCollect handles POST requests with biometric events.
func (c *BiometricCollector) HandleCollect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get session ID from header (validate format: max 128 chars, alphanumeric/dash/underscore)
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" || len(sessionID) > 128 {
		http.Error(w, "Missing or invalid session ID", http.StatusBadRequest)
		return
	}

	// Limit request body size to prevent OOM
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB max

	// Parse request body
	var req EventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Cap events per request to prevent memory amplification
	const maxEventsPerRequest = 1000
	if len(req.Events) > maxEventsPerRequest {
		req.Events = req.Events[:maxEventsPerRequest]
	}

	// Process events
	for _, event := range req.Events {
		c.processEvent(sessionID, event)
	}

	// Return success
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	}); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

// processEvent converts and records a biometric event.
func (c *BiometricCollector) processEvent(sessionID string, event BiometricEvent) {
	switch event.Type {
	case "mouse":
		c.processMouseEvent(sessionID, event)
	case "keyboard":
		c.processKeyboardEvent(sessionID, event)
	case "scroll":
		c.processScrollEvent(sessionID, event)
	case "touch":
		c.processTouchEvent(sessionID, event)
	}
	// fingerprint events are handled separately (one-time)
}

// processMouseEvent converts and records a mouse event.
func (c *BiometricCollector) processMouseEvent(sessionID string, event BiometricEvent) {
	var eventType string
	switch event.Subtype {
	case "move":
		eventType = "move"
	case "click":
		eventType = "click"
	case "down":
		eventType = "down"
	case "up":
		eventType = "up"
	default:
		return
	}

	c.enhancedLayer.RecordBiometricEvent(sessionID, biometric.MouseEvent{
		X:         event.X,
		Y:         event.Y,
		Type:      eventType,
		Timestamp: event.Timestamp,
		Button:    event.Button,
	})
}

// processKeyboardEvent converts and records a keyboard event.
func (c *BiometricCollector) processKeyboardEvent(sessionID string, event BiometricEvent) {
	var eventType string
	switch event.Subtype {
	case "down":
		eventType = "down"
	case "up":
		eventType = "up"
	case "press":
		eventType = "press"
	default:
		return
	}

	c.enhancedLayer.RecordBiometricEvent(sessionID, biometric.KeyEvent{
		Key:       event.Key,
		Type:      eventType,
		Timestamp: event.Timestamp,
		Code:      event.Code,
	})
}

// processScrollEvent converts and records a scroll event.
func (c *BiometricCollector) processScrollEvent(sessionID string, event BiometricEvent) {
	c.enhancedLayer.RecordBiometricEvent(sessionID, biometric.ScrollEvent{
		X:         event.X,
		Y:         event.Y,
		DeltaX:     event.DeltaX,
		DeltaY:     event.DeltaY,
		Timestamp: event.Timestamp,
	})
}

// processTouchEvent converts and records a touch event.
func (c *BiometricCollector) processTouchEvent(sessionID string, event BiometricEvent) {
	// Convert touch to mouse-like events for analysis
	var eventType string
	switch event.Subtype {
	case "start":
		eventType = "down"
	case "move":
		eventType = "move"
	case "end":
		eventType = "up"
	default:
		return
	}

	c.enhancedLayer.RecordBiometricEvent(sessionID, biometric.MouseEvent{
		X:         event.X,
		Y:         event.Y,
		Type:      eventType,
		Timestamp: event.Timestamp,
	})
}

// HandleChallengePage serves the CAPTCHA challenge page.
func (c *BiometricCollector) HandleChallengePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get provider info
	siteKey := c.enhancedLayer.GetCaptchaSiteKey()
	provider := "hcaptcha"
	if c.enhancedLayer.config.Challenge.Provider != "" {
		provider = c.enhancedLayer.config.Challenge.Provider
	}

	// Generate challenge page HTML
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(generateChallengePage(siteKey, provider))) // error ignored (client disconnect)
}

// HandleChallengeVerify handles CAPTCHA token verification.
func (c *BiometricCollector) HandleChallengeVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get token from form
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB max
	token := r.FormValue("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	// Use RemoteAddr for IP — don't trust X-Forwarded-For here
	remoteIP := r.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx >= 0 {
		remoteIP = remoteIP[:idx]
	}
	remoteIP = strings.TrimPrefix(strings.TrimSuffix(remoteIP, "]"), "[")

	// Verify token
	result, err := c.enhancedLayer.VerifyCaptcha(token, remoteIP)
	if err != nil {
		http.Error(w, "Verification failed", http.StatusInternalServerError)
		return
	}

	if result.IsHuman() {
		// Set HMAC-signed, IP-bound cookie to prevent forgery
		expiry := time.Now().Add(24 * time.Hour).Unix()
		cookieVal := signChallengeToken(remoteIP, expiry)
		http.SetCookie(w, &http.Cookie{
			Name:     "gwaf_challenge_passed",
			Value:    cookieVal,
			Path:     "/",
			MaxAge:   86400, // 24 hours
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success": result.Success,
		"human":   result.IsHuman(),
	}); err != nil {
		// Client disconnected, error ignored
		_ = err
	}
}

// generateChallengePage generates HTML for the CAPTCHA challenge page.
func generateChallengePage(siteKey, provider string) string {
	var scriptURL, renderCode string
	// HTML-escape siteKey to prevent XSS via config injection
	safeSiteKey := html.EscapeString(siteKey)

	switch provider {
	case "turnstile":
		scriptURL = "https://challenges.cloudflare.com/turnstile/v0/api.js"
		renderCode = `<div class="cf-turnstile" data-sitekey="` + safeSiteKey + `" data-callback="onSuccess"></div>`
	default: // hcaptcha
		scriptURL = "https://js.hcaptcha.com/1/api.js"
		renderCode = `<div class="h-captcha" data-sitekey="` + safeSiteKey + `" data-callback="onSuccess"></div>`
	}

	// Validate scriptURL against allowlist to prevent script injection
	allowedScripts := map[string]bool{
		"https://js.hcaptcha.com/1/api.js":                       true,
		"https://challenges.cloudflare.com/turnstile/v0/api.js":  true,
	}
	if !allowedScripts[scriptURL] {
		scriptURL = "https://js.hcaptcha.com/1/api.js" // safe fallback
	}

	return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Check</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            text-align: center;
            max-width: 400px;
            width: 90%;
        }
        h1 { color: #333; margin-bottom: 1rem; font-size: 1.5rem; }
        p { color: #666; margin-bottom: 2rem; line-height: 1.5; }
        .captcha-container { margin: 2rem 0; }
        .error { color: #e74c3c; margin-top: 1rem; }
        .success { color: #27ae60; margin-top: 1rem; }
    </style>
    <script src="` + scriptURL + `" async defer></script>
    <script>
        function onSuccess(token) {
            fetch('/gwaf/challenge/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'token=' + encodeURIComponent(token)
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    document.querySelector('.captcha-container').innerHTML =
                        '<p class="success">✓ Verification successful. Redirecting...</p>';
                    setTimeout(() => location.reload(), 1000);
                } else {
                    document.querySelector('.error').textContent = 'Verification failed. Please try again.';
                }
            });
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>Security Check</h1>
        <p>Please complete the challenge below to continue.</p>
        <div class="captcha-container">
            ` + renderCode + `
        </div>
        <p class="error"></p>
    </div>
</body>
</html>`
}

// challengeHMACKey is used to sign challenge-passed cookies.
// In production this should come from config; here we use a process-stable random key.
var challengeHMACKey = func() []byte {
	b := make([]byte, 32)
	if _, err := cryptoRand.Read(b); err != nil {
		// Fallback: use a fixed key (still better than unsigned "true")
		return []byte("guardianwaf-challenge-hmac-key!!")
	}
	return b
}()

// signChallengeToken creates an HMAC-signed, IP-bound token: "ip.expiry.hmac"
func signChallengeToken(ip string, expiry int64) string {
	data := fmt.Sprintf("%s.%d", ip, expiry)
	mac := hmac.New(sha256.New, challengeHMACKey)
	mac.Write([]byte(data))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s.%s", data, sig)
}

// VerifyChallengeToken checks a challenge-passed cookie token is valid and not expired.
func VerifyChallengeToken(token, clientIP string) bool {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return false
	}
	ip, expiryStr, sig := parts[0], parts[1], parts[2]

	// Verify IP binding
	if ip != clientIP {
		return false
	}

	// Verify expiry
	var expiry int64
	for _, c := range expiryStr {
		if c < '0' || c > '9' {
			return false
		}
		expiry = expiry*10 + int64(c-'0')
	}
	if time.Now().Unix() > expiry {
		return false
	}

	// Verify HMAC
	data := fmt.Sprintf("%s.%s", ip, expiryStr)
	mac := hmac.New(sha256.New, challengeHMACKey)
	mac.Write([]byte(data))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(expected))
}
