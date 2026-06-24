package ai

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/logging"
)

const maxAIProviderResponseBytes = 1 * 1024 * 1024

// Client is an OpenAI-compatible chat completions HTTP client.
// Most AI providers (OpenAI, Anthropic via proxy, Google, Groq, Together, etc.)
// support the OpenAI chat completions API format.
type Client struct {
	baseURL    string
	apiKey     string
	model      string
	maxTokens  int
	httpClient *http.Client
	log        *slog.Logger
}

// ClientConfig holds configuration for the AI client.
type ClientConfig struct {
	BaseURL              string
	APIKey               string
	Model                string
	MaxTokens            int
	Timeout              time.Duration
	TLSServerName        string // optional: override TLS server name for certificate verification
	AllowPrivateEndpoint bool   // allow localhost/private endpoints (for testing only)
}

// NewClient creates a new AI API client.
func NewClient(cfg ClientConfig) *Client {
	log := logging.NewLogger("ai")

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	maxTokens := cfg.MaxTokens
	if maxTokens == 0 {
		maxTokens = 2048
	}
	// Validate endpoint is not SSRF-vulnerable (private/internal IPs)
	if cfg.BaseURL != "" && !cfg.AllowPrivateEndpoint && !testAllowPrivate {
		if u, err := url.Parse(cfg.BaseURL); err == nil {
			if u.Scheme == "http" {
				log.Warn("AI endpoint uses HTTP — API key will be sent in cleartext. Use HTTPS.")
			}
			host := u.Hostname()
			if ip := net.ParseIP(host); ip != nil {
				if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
					log.Error("AI endpoint targets a private/loopback address", "host", host)
				}
			} else if strings.EqualFold(host, "localhost") {
				log.Error("AI endpoint targets localhost — SSRF risk", "host", host)
			} else {
				// Resolve hostname and validate all resulting IPs
				addrs, err := net.LookupHost(host)
				if err != nil {
					log.Error("AI endpoint hostname DNS lookup failed", "host", host, "error", err)
				}
				for _, addr := range addrs {
					if ip := net.ParseIP(addr); ip != nil {
						if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
							log.Error("AI endpoint hostname resolves to private/loopback address", "host", host, "addr", addr)
						}
					}
				}
			}
		}
	}

	// Build HTTP client with SSRF-safe DialContext
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if !cfg.AllowPrivateEndpoint && !testAllowPrivate {
		transport.DialContext = aiSSRFDialContext()
	}
	if cfg.TLSServerName != "" {
		transport.TLSClientConfig.ServerName = cfg.TLSServerName
	}

	return &Client{
		baseURL:   cfg.BaseURL,
		apiKey:    cfg.APIKey,
		model:     cfg.Model,
		maxTokens: maxTokens,
		log:       log,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				if cfg.AllowPrivateEndpoint || testAllowPrivate {
					return nil
				}
				if err := validateURLNotPrivate(req.URL.String()); err != nil {
					return fmt.Errorf("redirect URL rejected: %w", err)
				}
				return nil
			},
		},
	}
}

// NewClientValidated creates a client only after enforcing the outbound
// endpoint SSRF policy. Use this for operator-supplied provider configuration.
func NewClientValidated(cfg ClientConfig) (*Client, error) {
	if cfg.BaseURL != "" && !cfg.AllowPrivateEndpoint && !testAllowPrivate {
		if err := validateURLNotPrivate(cfg.BaseURL); err != nil {
			return nil, fmt.Errorf("invalid AI endpoint URL: %w", err)
		}
	}
	return NewClient(cfg), nil
}

// TokenUsage tracks token consumption for cost accounting.
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// chatRequest is the OpenAI chat completions request format.
type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatResponse is the OpenAI chat completions response format.
type chatResponse struct {
	ID      string `json:"id"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage TokenUsage `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

// Analyze sends a system prompt + user content to the AI and returns the response.
func (c *Client) Analyze(ctx context.Context, systemPrompt, userContent string) (string, TokenUsage, error) {
	reqBody := chatRequest{
		Model: c.model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userContent},
		},
		MaxTokens:   c.maxTokens,
		Temperature: 0.1, // low temperature for consistent analysis
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", TokenUsage{}, fmt.Errorf("marshaling request: %w", err)
	}

	url := c.baseURL + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", TokenUsage{}, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", TokenUsage{}, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := readAIProviderResponse(resp.Body)
	if err != nil {
		return "", TokenUsage{}, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", TokenUsage{}, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", TokenUsage{}, fmt.Errorf("parsing response: %w", err)
	}

	if chatResp.Error != nil {
		return "", TokenUsage{}, fmt.Errorf("API error: %s", chatResp.Error.Message)
	}

	if len(chatResp.Choices) == 0 {
		return "", chatResp.Usage, fmt.Errorf("empty response (no choices)")
	}

	return chatResp.Choices[0].Message.Content, chatResp.Usage, nil
}

func readAIProviderResponse(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxAIProviderResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxAIProviderResponseBytes {
		return nil, fmt.Errorf("AI provider response exceeds %d bytes", maxAIProviderResponseBytes)
	}
	return body, nil
}

// TestConnection tests the API key by sending a minimal request.
func (c *Client) TestConnection(ctx context.Context) error {
	_, _, err := c.Analyze(ctx, "Reply with exactly: ok", "Test connection")
	return err
}

// Note: Client is immutable after creation. Use Analyzer.UpdateProvider()
// to swap the entire client atomically for thread safety.

// aiSSRFDialContext returns a DialContext that validates resolved IPs at
// connection time to prevent DNS rebinding SSRF attacks.
func aiSSRFDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
			port = ""
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("SSRF dial: DNS lookup failed for %q: %w", host, err)
		}
		var validIP net.IP
		for _, ip := range ips {
			if !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() {
				validIP = ip
				break
			}
		}
		if validIP == nil {
			return nil, fmt.Errorf("SSRF dial: all IPs for %q are private/loopback", host)
		}
		target := net.JoinHostPort(validIP.String(), port)
		return dialer.DialContext(ctx, network, target)
	}
}
