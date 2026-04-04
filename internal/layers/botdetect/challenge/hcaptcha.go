// Package challenge provides CAPTCHA challenge integrations.
package challenge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// HCaptchaProvider implements hCaptcha verification.
type HCaptchaProvider struct {
	secretKey string
	siteKey   string
	client    *http.Client
}

// HCaptchaConfig for provider setup.
type HCaptchaConfig struct {
	SecretKey string
	SiteKey   string
	Timeout   time.Duration
}

// NewHCaptcha creates a new hCaptcha provider.
func NewHCaptcha(cfg HCaptchaConfig) *HCaptchaProvider {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &HCaptchaProvider{
		secretKey: cfg.SecretKey,
		siteKey:   cfg.SiteKey,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// hCaptchaResponse from verification API.
type hCaptchaResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes,omitempty"`
	Score       float64  `json:"score,omitempty"` // Enterprise feature
	ScoreReason string   `json:"score_reason,omitempty"`
}

// VerifyToken verifies an hCaptcha token.
func (p *HCaptchaProvider) VerifyToken(token string, remoteIP string) (*VerificationResult, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}

	// Build request
	formData := url.Values{}
	formData.Set("secret", p.secretKey)
	formData.Set("response", token)
	if remoteIP != "" {
		formData.Set("remoteip", remoteIP)
	}

	// Send verification request
	resp, err := p.client.Post(
		"https://hcaptcha.com/siteverify",
		"application/x-www-form-urlencoded",
		bytes.NewBufferString(formData.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("verification request failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result hCaptchaResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Build verification result
	verResult := &VerificationResult{
		Success:    result.Success,
		Provider:   "hcaptcha",
		Timestamp:  result.ChallengeTS,
		Hostname:   result.Hostname,
		ErrorCodes: result.ErrorCodes,
		Score:      result.Score,
		Raw:        body,
	}

	if !result.Success {
		verResult.Error = fmt.Sprintf("Verification failed: %v", result.ErrorCodes)
	}

	return verResult, nil
}

// GetSiteKey returns the site key for frontend integration.
func (p *HCaptchaProvider) GetSiteKey() string {
	return p.siteKey
}

// GetScriptURL returns the hCaptcha script URL.
func (p *HCaptchaProvider) GetScriptURL() string {
	return "https://js.hcaptcha.com/1/api.js"
}

// TurnstileProvider implements CloudFlare Turnstile verification.
type TurnstileProvider struct {
	secretKey string
	siteKey   string
	client    *http.Client
}

// TurnstileConfig for provider setup.
type TurnstileConfig struct {
	SecretKey string
	SiteKey   string
	Timeout   time.Duration
}

// NewTurnstile creates a new Turnstile provider.
func NewTurnstile(cfg TurnstileConfig) *TurnstileProvider {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &TurnstileProvider{
		secretKey: cfg.SecretKey,
		siteKey:   cfg.SiteKey,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// turnstileResponse from verification API.
type turnstileResponse struct {
	Success    bool     `json:"success"`
	Timestamp  string   `json:"challenge_ts"`
	Hostname   string   `json:"hostname"`
	ErrorCodes []string `json:"error-codes,omitempty"`
	Action     string   `json:"action,omitempty"`
	CData      string   `json:"cdata,omitempty"`
}

// VerifyToken verifies a Turnstile token.
func (p *TurnstileProvider) VerifyToken(token string, remoteIP string) (*VerificationResult, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}

	// Build request
	formData := url.Values{}
	formData.Set("secret", p.secretKey)
	formData.Set("response", token)
	if remoteIP != "" {
		formData.Set("remoteip", remoteIP)
	}

	// Send verification request
	resp, err := p.client.Post(
		"https://challenges.cloudflare.com/turnstile/v0/siteverify",
		"application/x-www-form-urlencoded",
		bytes.NewBufferString(formData.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("verification request failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result turnstileResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Build verification result
	verResult := &VerificationResult{
		Success:    result.Success,
		Provider:   "turnstile",
		Timestamp:  result.Timestamp,
		Hostname:   result.Hostname,
		ErrorCodes: result.ErrorCodes,
		Raw:        body,
		Metadata: map[string]string{
			"action": result.Action,
			"cdata":  result.CData,
		},
	}

	if !result.Success {
		verResult.Error = fmt.Sprintf("Verification failed: %v", result.ErrorCodes)
	}

	return verResult, nil
}

// GetSiteKey returns the site key.
func (p *TurnstileProvider) GetSiteKey() string {
	return p.siteKey
}

// GetScriptURL returns the Turnstile script URL.
func (p *TurnstileProvider) GetScriptURL() string {
	return "https://challenges.cloudflare.com/turnstile/v0/api.js"
}

// VerificationResult contains CAPTCHA verification result.
type VerificationResult struct {
	Success    bool
	Provider   string
	Timestamp  string
	Hostname   string
	ErrorCodes []string
	Score      float64
	Error      string
	Raw        []byte
	Metadata   map[string]string
}

// IsHuman returns true if verification indicates human.
func (r *VerificationResult) IsHuman() bool {
	return r.Success && r.Error == ""
}

// Provider interface for CAPTCHA providers.
type Provider interface {
	VerifyToken(token string, remoteIP string) (*VerificationResult, error)
	GetSiteKey() string
	GetScriptURL() string
}
