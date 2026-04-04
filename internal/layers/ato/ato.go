// Package ato provides Account Takeover Protection.
package ato

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// Config holds the configuration for the ATO Protection layer.
type Config struct {
	Enabled       bool                     `yaml:"enabled"`
	LoginPaths    []string                 `yaml:"login_paths"`
	BruteForce    BruteForceConfig         `yaml:"brute_force"`
	CredStuffing  CredentialStuffingConfig `yaml:"credential_stuffing"`
	PasswordSpray PasswordSprayConfig      `yaml:"password_spray"`
	Travel        ImpossibleTravelConfig   `yaml:"impossible_travel"`
	GeoDBPath     string                   `yaml:"geodb_path"`
}

// BruteForceConfig configures brute force detection.
type BruteForceConfig struct {
	Enabled             bool          `yaml:"enabled"`
	Window              time.Duration `yaml:"window"`
	MaxAttemptsPerIP    int           `yaml:"max_attempts_per_ip"`
	MaxAttemptsPerEmail int           `yaml:"max_attempts_per_email"`
	BlockDuration       time.Duration `yaml:"block_duration"`
}

// CredentialStuffingConfig configures credential stuffing detection.
type CredentialStuffingConfig struct {
	Enabled              bool          `yaml:"enabled"`
	DistributedThreshold int           `yaml:"distributed_threshold"` // Same email from X different IPs
	Window               time.Duration `yaml:"window"`
	BlockDuration        time.Duration `yaml:"block_duration"`
}

// PasswordSprayConfig configures password spray detection.
type PasswordSprayConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Threshold     int           `yaml:"threshold"` // Same password used X times
	Window        time.Duration `yaml:"window"`
	BlockDuration time.Duration `yaml:"block_duration"`
}

// ImpossibleTravelConfig configures impossible travel detection.
type ImpossibleTravelConfig struct {
	Enabled       bool          `yaml:"enabled"`
	MaxDistanceKm float64       `yaml:"max_distance_km"`
	MaxTimeHours  float64       `yaml:"max_time_hours"`
	BlockDuration time.Duration `yaml:"block_duration"`
}

// Layer implements engine.Layer for ATO protection.
type Layer struct {
	config      Config
	tracker     *AttemptTracker
	loginPathRe []*regexp.Regexp
	emailRe     *regexp.Regexp
	locationDB  *LocationDB
	lastLogin   map[string]*GeoLocation
	lastTime    map[string]time.Time
}

// NewLayer creates a new ATO Protection layer.
func NewLayer(cfg *Config) (*Layer, error) {
	l := &Layer{
		config:    *cfg,
		tracker:   NewAttemptTracker(),
		emailRe:   regexp.MustCompile(`(?i)^[\w.-]+@[\w.-]+\.\w+$`),
		lastLogin: make(map[string]*GeoLocation),
		lastTime:  make(map[string]time.Time),
	}

	// Compile login path regexes
	for _, path := range cfg.LoginPaths {
		re, err := regexp.Compile("^" + regexp.QuoteMeta(path) + "$")
		if err != nil {
			continue
		}
		l.loginPathRe = append(l.loginPathRe, re)
	}

	// Load GeoIP database for travel detection
	if cfg.Travel.Enabled && cfg.GeoDBPath != "" {
		l.locationDB = NewLocationDB()
		// Load GeoIP data from file
		// This is a simplified version - in production, use MaxMind DB-IP
	}

	return l, nil
}

// Name returns the layer name.
func (l *Layer) Name() string { return "ato_protection" }

// Process checks for ATO attack patterns.
func (l *Layer) Process(ctx *engine.RequestContext) engine.LayerResult {
	if !l.config.Enabled {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Only check login paths
	if !l.isLoginPath(ctx.Path) {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Only check POST requests
	if ctx.Method != "POST" {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Extract credentials from body
	email := l.extractEmail(ctx.BodyString)
	if email == "" {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Check if IP is already blocked
	if blocked, reason := l.tracker.IsIPBlocked(ctx.ClientIP); blocked {
		return l.blockResult(ctx, "ip_blocked", reason, 100)
	}

	// Check if email is already blocked
	if blocked, reason := l.tracker.IsEmailBlocked(email); blocked {
		return l.blockResult(ctx, "email_blocked", reason, 100)
	}

	// Check brute force
	if l.config.BruteForce.Enabled {
		if result := l.checkBruteForce(ctx, email); result.Action == engine.ActionBlock {
			return result
		}
	}

	// Check credential stuffing
	if l.config.CredStuffing.Enabled {
		if result := l.checkCredentialStuffing(ctx, email); result.Action == engine.ActionBlock {
			return result
		}
	}

	// Check password spray (requires password extraction)
	if l.config.PasswordSpray.Enabled {
		password := l.extractPassword(ctx.BodyString)
		if password != "" {
			if result := l.checkPasswordSpray(ctx, password); result.Action == engine.ActionBlock {
				return result
			}
		}
	}

	// Check impossible travel
	if l.config.Travel.Enabled {
		if result := l.checkImpossibleTravel(ctx, email); result.Action == engine.ActionBlock {
			return result
		}
	}

	// Record the attempt
	l.tracker.RecordAttempt(&LoginAttempt{
		IP:    ctx.ClientIP,
		Email: email,
		Time:  time.Now(),
	})

	return engine.LayerResult{Action: engine.ActionPass}
}

// PostProcess handles successful login (to clear counters).
func (l *Layer) PostProcess(ctx *engine.RequestContext, success bool) {
	if !success || !l.config.Enabled {
		return
	}

	email := l.extractEmail(ctx.BodyString)
	l.tracker.ClearAttempt(ctx.ClientIP, email)
}

func (l *Layer) isLoginPath(path string) bool {
	for _, re := range l.loginPathRe {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func (l *Layer) checkBruteForce(ctx *engine.RequestContext, email string) engine.LayerResult {
	cfg := l.config.BruteForce

	// Check per-IP
	ipAttempts := l.tracker.GetIPAttempts(ctx.ClientIP, cfg.Window)
	if ipAttempts >= cfg.MaxAttemptsPerIP {
		// Block the IP
		l.tracker.BlockIP(ctx.ClientIP, time.Now().Add(cfg.BlockDuration), "brute_force")
		return l.blockResult(ctx, "brute_force", "too many attempts from IP", 80)
	}

	// Check per-email
	emailAttempts := l.tracker.GetEmailAttempts(email, cfg.Window)
	if emailAttempts >= cfg.MaxAttemptsPerEmail {
		// Block the email
		l.tracker.BlockEmail(email, time.Now().Add(cfg.BlockDuration), "brute_force")
		return l.blockResult(ctx, "brute_force", "too many attempts for email", 80)
	}

	return engine.LayerResult{Action: engine.ActionPass}
}

func (l *Layer) checkCredentialStuffing(ctx *engine.RequestContext, email string) engine.LayerResult {
	cfg := l.config.CredStuffing

	// Check how many different IPs have tried this email
	uniqueIPs := l.tracker.GetUniqueIPsForEmail(email)
	if uniqueIPs >= cfg.DistributedThreshold {
		// Block the email
		l.tracker.BlockEmail(email, time.Now().Add(cfg.BlockDuration), "credential_stuffing")
		return l.blockResult(ctx, "credential_stuffing", "distributed attack detected", 85)
	}

	return engine.LayerResult{Action: engine.ActionPass}
}

func (l *Layer) checkPasswordSpray(ctx *engine.RequestContext, password string) engine.LayerResult {
	cfg := l.config.PasswordSpray

	// Check how many times this password has been used
	useCount := l.tracker.GetPasswordUseCount(password)
	if useCount >= cfg.Threshold {
		// Block the IP
		l.tracker.BlockIP(ctx.ClientIP, time.Now().Add(cfg.BlockDuration), "password_spray")
		return l.blockResult(ctx, "password_spray", "common password attack", 75)
	}

	return engine.LayerResult{Action: engine.ActionPass}
}

func (l *Layer) checkImpossibleTravel(ctx *engine.RequestContext, email string) engine.LayerResult {
	cfg := l.config.Travel

	// Get current location
	currentLoc := l.getLocation(ctx.ClientIP)
	if currentLoc == nil {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Get last successful login location (would need session tracking)
	// This is a simplified implementation
	lastLoc := l.getLastLoginLocation(email)
	if lastLoc == nil {
		return engine.LayerResult{Action: engine.ActionPass}
	}

	// Calculate distance
	distance := haversineDistance(currentLoc, lastLoc)

	// Calculate time difference
	lastTime := l.getLastLoginTime(email)
	if lastTime.IsZero() {
		return engine.LayerResult{Action: engine.ActionPass}
	}
	timeDiff := time.Since(lastTime).Hours()

	// Check if travel is impossible
	if timeDiff > 0 && timeDiff <= cfg.MaxTimeHours {
		speed := distance / timeDiff // km/h
		// If speed > 1000 km/h (roughly speed of sound), it's impossible
		if speed > 1000 && distance > cfg.MaxDistanceKm {
			l.tracker.BlockIP(ctx.ClientIP, time.Now().Add(cfg.BlockDuration), "impossible_travel")
			return l.blockResult(ctx, "impossible_travel",
				fmt.Sprintf("travel of %.0f km in %.1f hours is impossible", distance, timeDiff), 90)
		}
	}

	return engine.LayerResult{Action: engine.ActionPass}
}

func (l *Layer) blockResult(ctx *engine.RequestContext, attackType, reason string, score int) engine.LayerResult {
	return engine.LayerResult{
		Action: engine.ActionBlock,
		Findings: []engine.Finding{{
			DetectorName: "ato_protection",
			Category:     "account_takeover",
			Severity:     engine.SeverityCritical,
			Score:        score,
			Description:  fmt.Sprintf("%s: %s", attackType, reason),
			MatchedValue: ctx.ClientIP.String(),
			Location:     "ip",
		}},
		Score: score,
	}
}

func (l *Layer) extractEmail(body string) string {
	// Try JSON format
	var jsonBody struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Login    string `json:"login"`
	}
	if json.Unmarshal([]byte(body), &jsonBody) == nil {
		email := jsonBody.Email
		if email == "" {
			email = jsonBody.Username
		}
		if email == "" {
			email = jsonBody.Login
		}
		if l.emailRe.MatchString(email) {
			return strings.ToLower(email)
		}
	}

	// Try form format
	pairs := strings.Split(body, "&")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			key := strings.ToLower(kv[0])
			if key == "email" || key == "username" || key == "login" {
				email := strings.ToLower(kv[1])
				if l.emailRe.MatchString(email) {
					return email
				}
			}
		}
	}

	return ""
}

func (l *Layer) extractPassword(body string) string {
	// Try JSON format
	var jsonBody struct {
		Password string `json:"password"`
		Pass     string `json:"pass"`
	}
	if json.Unmarshal([]byte(body), &jsonBody) == nil {
		if jsonBody.Password != "" {
			return jsonBody.Password
		}
		return jsonBody.Pass
	}

	// Try form format
	pairs := strings.Split(body, "&")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			key := strings.ToLower(kv[0])
			if key == "password" || key == "pass" {
				return kv[1]
			}
		}
	}

	return ""
}

func (l *Layer) getLocation(ip net.IP) *GeoLocation {
	if l.locationDB == nil {
		return nil
	}
	return l.locationDB.Lookup(ip)
}

func (l *Layer) getLastLoginLocation(email string) *GeoLocation {
	return l.lastLogin[email]
}

func (l *Layer) getLastLoginTime(email string) time.Time {
	return l.lastTime[email]
}

// Stats returns layer statistics.
func (l *Layer) Stats() map[string]any {
	return map[string]any{
		"enabled":       l.config.Enabled,
		"tracker_stats": l.tracker.Stats(),
	}
}

// Cleanup removes old tracking data.
func (l *Layer) Cleanup() {
	// Cleanup attempts older than 24 hours
	l.tracker.Cleanup(24 * time.Hour)
}

// haversineDistance calculates distance between two points in km.
func haversineDistance(loc1, loc2 *GeoLocation) float64 {
	const earthRadius = 6371 // km

	lat1 := loc1.Latitude * math.Pi / 180
	lat2 := loc2.Latitude * math.Pi / 180
	deltaLat := (loc2.Latitude - loc1.Latitude) * math.Pi / 180
	deltaLon := (loc2.Longitude - loc1.Longitude) * math.Pi / 180

	a := math.Sin(deltaLat/2)*math.Sin(deltaLat/2) +
		math.Cos(lat1)*math.Cos(lat2)*
			math.Sin(deltaLon/2)*math.Sin(deltaLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadius * c
}
