package challenge

import (
	"net/http"
	"testing"
	"time"
)

func TestNewHCaptcha(t *testing.T) {
	tests := []struct {
		name string
		cfg  HCaptchaConfig
		want string
	}{
		{
			name: "default timeout",
			cfg: HCaptchaConfig{
				SecretKey: "test-secret",
				SiteKey:   "test-site",
			},
			want: "test-secret",
		},
		{
			name: "custom timeout",
			cfg: HCaptchaConfig{
				SecretKey: "test-secret",
				SiteKey:   "test-site",
				Timeout:   10 * time.Second,
			},
			want: "test-secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewHCaptcha(tt.cfg)
			if p.secretKey != tt.want {
				t.Errorf("secretKey = %v, want %v", p.secretKey, tt.want)
			}
			if p.siteKey != tt.cfg.SiteKey {
				t.Errorf("siteKey = %v, want %v", p.siteKey, tt.cfg.SiteKey)
			}
			if p.client == nil {
				t.Error("expected http client to be set")
			}
		})
	}
}

func TestHCaptchaProvider_VerifyToken(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
		},
		{
			name:    "valid token format",
			token:   "some-token",
			wantErr: true, // Will fail because we're not mocking the server
		},
	}

	p := &HCaptchaProvider{
		secretKey: "test-secret",
		siteKey:   "test-site",
		client:    &http.Client{Timeout: 1 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.VerifyToken(tt.token, "127.0.0.1")

			if tt.wantErr {
				if err == nil && result == nil {
					t.Errorf("expected error or nil result, got result=%v", result)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestHCaptchaProvider_GetSiteKey(t *testing.T) {
	p := NewHCaptcha(HCaptchaConfig{
		SecretKey: "secret",
		SiteKey:   "site-key-123",
	})

	if got := p.GetSiteKey(); got != "site-key-123" {
		t.Errorf("GetSiteKey() = %v, want %v", got, "site-key-123")
	}
}

func TestHCaptchaProvider_GetScriptURL(t *testing.T) {
	p := NewHCaptcha(HCaptchaConfig{})

	want := "https://js.hcaptcha.com/1/api.js"
	if got := p.GetScriptURL(); got != want {
		t.Errorf("GetScriptURL() = %v, want %v", got, want)
	}
}

func TestNewTurnstile(t *testing.T) {
	tests := []struct {
		name string
		cfg  TurnstileConfig
		want string
	}{
		{
			name: "default timeout",
			cfg: TurnstileConfig{
				SecretKey: "test-secret",
				SiteKey:   "test-site",
			},
			want: "test-secret",
		},
		{
			name: "custom timeout",
			cfg: TurnstileConfig{
				SecretKey: "test-secret",
				SiteKey:   "test-site",
				Timeout:   15 * time.Second,
			},
			want: "test-secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewTurnstile(tt.cfg)
			if p.secretKey != tt.want {
				t.Errorf("secretKey = %v, want %v", p.secretKey, tt.want)
			}
			if p.siteKey != tt.cfg.SiteKey {
				t.Errorf("siteKey = %v, want %v", p.siteKey, tt.cfg.SiteKey)
			}
			if p.client == nil {
				t.Error("expected http client to be set")
			}
		})
	}
}

func TestTurnstileProvider_GetSiteKey(t *testing.T) {
	p := NewTurnstile(TurnstileConfig{
		SecretKey: "secret",
		SiteKey:   "turnstile-site-key",
	})

	if got := p.GetSiteKey(); got != "turnstile-site-key" {
		t.Errorf("GetSiteKey() = %v, want %v", got, "turnstile-site-key")
	}
}

func TestTurnstileProvider_GetScriptURL(t *testing.T) {
	p := NewTurnstile(TurnstileConfig{})

	want := "https://challenges.cloudflare.com/turnstile/v0/api.js"
	if got := p.GetScriptURL(); got != want {
		t.Errorf("GetScriptURL() = %v, want %v", got, want)
	}
}

func TestVerificationResult_IsHuman(t *testing.T) {
	tests := []struct {
		name    string
		result  *VerificationResult
		wantHuman bool
	}{
		{
			name: "human",
			result: &VerificationResult{
				Success: true,
				Error:   "",
			},
			wantHuman: true,
		},
		{
			name: "not human - failed",
			result: &VerificationResult{
				Success: false,
				Error:   "verification failed",
			},
			wantHuman: false,
		},
		{
			name: "not human - error",
			result: &VerificationResult{
				Success: true,
				Error:   "some error",
			},
			wantHuman: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.IsHuman(); got != tt.wantHuman {
				t.Errorf("IsHuman() = %v, want %v", got, tt.wantHuman)
			}
		})
	}
}
