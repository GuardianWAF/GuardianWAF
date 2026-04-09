package ai

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is an OpenAI-compatible chat completions HTTP client.
// Most AI providers (OpenAI, Anthropic via proxy, Google, Groq, Together, etc.)
// support the OpenAI chat completions API format.
type Client struct {
	baseURL    string
	apiKey     string
	model      string
	maxTokens  int
	httpClient *http.Client
}

// ClientConfig holds configuration for the AI client.
type ClientConfig struct {
	BaseURL       string
	APIKey        string
	Model         string
	MaxTokens     int
	Timeout       time.Duration
	TLSServerName string // optional: override TLS server name for certificate verification
}

// NewClient creates a new AI API client.
func NewClient(cfg ClientConfig) *Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	maxTokens := cfg.MaxTokens
	if maxTokens == 0 {
		maxTokens = 2048
	}
	// Warn if endpoint is not HTTPS (API key transmitted in cleartext)
	if cfg.BaseURL != "" {
		if u, err := url.Parse(cfg.BaseURL); err == nil {
			if u.Scheme == "http" {
				log.Printf("[ai] WARNING: AI endpoint uses HTTP — API key will be sent in cleartext. Use HTTPS.")
			}
			// Warn about internal endpoints (SSRF risk)
			host := u.Hostname()
			if ip := net.ParseIP(host); ip != nil {
				if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
					log.Printf("[ai] WARNING: AI endpoint targets a private/loopback address")
				}
			} else if strings.EqualFold(host, "localhost") {
				log.Printf("[ai] WARNING: AI endpoint targets localhost")
			}
		}
	}

	// Build HTTP client with optional TLS configuration
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	if cfg.TLSServerName != "" {
		transport.TLSClientConfig.ServerName = cfg.TLSServerName
	}

	return &Client{
		baseURL:   cfg.BaseURL,
		apiKey:    cfg.APIKey,
		model:     cfg.Model,
		maxTokens: maxTokens,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
	}
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

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024)) // 1MB max
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

// TestConnection tests the API key by sending a minimal request.
func (c *Client) TestConnection(ctx context.Context) error {
	_, _, err := c.Analyze(ctx, "Reply with exactly: ok", "Test connection")
	return err
}

// Note: Client is immutable after creation. Use Analyzer.UpdateProvider()
// to swap the entire client atomically for thread safety.
