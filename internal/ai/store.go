package ai

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const encKeyFile = "ai_enc_key" // file storing the auto-generated encryption key

const encPrefix = "enc:" // prefix for encrypted API keys on disk

const maxHistorySize = 100

// ProviderConfig holds the user's selected AI provider configuration.
type ProviderConfig struct {
	ProviderID   string `json:"provider_id"`
	ProviderName string `json:"provider_name"`
	ModelID      string `json:"model_id"`
	ModelName    string `json:"model_name"`
	APIKey       string `json:"api_key"`
	BaseURL      string `json:"base_url"`
}

// Verdict is an AI-generated threat assessment for a specific IP.
type Verdict struct {
	IP         string  `json:"ip"`
	Action     string  `json:"action"` // "block", "monitor", "safe"
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`
}

// AnalysisResult holds the outcome of a single batch AI analysis.
type AnalysisResult struct {
	ID              string    `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	EventCount      int       `json:"event_count"`
	Verdicts        []Verdict `json:"verdicts"`
	Summary         string    `json:"summary"`
	ThreatsDetected []string  `json:"threats_detected"`
	TokensUsed      int       `json:"tokens_used"`
	CostUSD         float64   `json:"cost_usd"`
	DurationMs      int64     `json:"duration_ms"`
	Model           string    `json:"model"`
	Error           string    `json:"error,omitempty"`
}

// UsageStats tracks AI API usage for cost control.
type UsageStats struct {
	TokensUsedHour    int64     `json:"tokens_used_hour"`
	TokensUsedDay     int64     `json:"tokens_used_day"`
	RequestsHour      int       `json:"requests_hour"`
	RequestsDay       int       `json:"requests_day"`
	TotalTokensUsed   int64     `json:"total_tokens_used"`
	TotalRequests     int       `json:"total_requests"`
	TotalCostUSD      float64   `json:"total_cost_usd"`
	HourResetAt       time.Time `json:"hour_reset_at"`
	DayResetAt        time.Time `json:"day_reset_at"`
	BlocksTriggered   int       `json:"blocks_triggered"`
	MonitorsTriggered int       `json:"monitors_triggered"`
}

// storeData is the on-disk JSON format.
type storeData struct {
	Config  ProviderConfig   `json:"config"`
	History []AnalysisResult `json:"history"`
	Usage   UsageStats       `json:"usage"`
}

// Store manages persistent storage for AI configuration and analysis history.
type Store struct {
	mu     sync.RWMutex
	path   string // directory path
	encKey []byte // AES-256 key for API key encryption (nil = plaintext)
	data storeData
}

// NewStore creates or loads an AI store from the given directory.
// Always succeeds — creates the directory and empty config if needed.
// Falls back to OS temp dir if the requested path is not writable.
func NewStore(dirPath string) *Store {
	if dirPath == "" {
		dirPath = "data/ai"
	}

	// Resolve to absolute
	if !filepath.IsAbs(dirPath) {
		if abs, err := filepath.Abs(dirPath); err == nil {
			dirPath = abs
		}
	}

	// Try creating the directory; fallback to temp if permission denied
	if err := os.MkdirAll(dirPath, 0o700); err != nil {
		fallback := filepath.Join(os.TempDir(), "guardianwaf", "ai")
		if fallbackErr := os.MkdirAll(fallback, 0o700); fallbackErr != nil {
				log.Printf("[WARN] AI store: cannot create fallback dir %s: %v", fallback, fallbackErr)
			}
		log.Printf("[WARN] AI store: cannot create %s (%v), falling back to %s — data may have weaker permissions", dirPath, err, fallback)
		dirPath = fallback
	}

	s := &Store{path: dirPath}

	// Auto-generate and persist encryption key for API key at-rest encryption.
	// This ensures API keys are always encrypted even without a dashboard API key.
	s.loadOrCreateEncKey()

	// Try loading existing config
	configFile := filepath.Join(dirPath, "ai_config.json")
	if data, err := os.ReadFile(configFile); err == nil {
		if unmarshalErr := json.Unmarshal(data, &s.data); unmarshalErr != nil {
			fmt.Printf("[ai-store] warning: failed to parse AI config: %v\n", unmarshalErr)
		}
		// Decrypt API key if encrypted with auto-generated key
		if s.encKey != nil && strings.HasPrefix(s.data.Config.APIKey, encPrefix) {
			if dec, err := decryptValue(s.data.Config.APIKey[len(encPrefix):], s.encKey); err == nil {
				s.data.Config.APIKey = dec
			}
		}
	} else {
		// First run — write empty config so file always exists
		empty, _ := json.MarshalIndent(s.data, "", "  ")
		if writeErr := os.WriteFile(configFile, empty, 0o600); writeErr != nil {
			log.Printf("[WARN] AI store: failed to write initial config: %v", writeErr)
		}
	}
	return s
}

// SetEncryptionKey sets the AES-256 key used to encrypt the API key at rest.
// Derives a 32-byte key from the provided secret using iterated HMAC-SHA256.
// If secret is empty, encryption is disabled (plaintext storage).
// When called on a store that has an unencrypted key, the next save will encrypt it.
func (s *Store) SetEncryptionKey(secret string) {
	if secret == "" {
		s.mu.Lock()
		s.encKey = nil
		s.mu.Unlock()
		return
	}
	// Salted key derivation with 10k iterations for brute-force resistance
	salt := []byte("guardianwaf-ai-enc-v1")
	derived := deriveStoreKey([]byte(secret), salt, 10000)
	s.mu.Lock()
	s.encKey = derived
	// Decrypt API key if it was stored encrypted
	if strings.HasPrefix(s.data.Config.APIKey, encPrefix) {
		if dec, err := decryptValue(s.data.Config.APIKey[len(encPrefix):], s.encKey); err == nil {
			s.data.Config.APIKey = dec
		}
	}
	s.mu.Unlock()
}

// encryptValue encrypts a plaintext string using AES-256-GCM.
// Returns base64-encoded nonce+ciphertext.
func encryptValue(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptValue decrypts a base64-encoded AES-256-GCM ciphertext.
func decryptValue(encoded string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// save writes stored data to disk.
func (s *Store) save() error {
	dir := s.path
	// Always resolve to absolute path
	if !filepath.IsAbs(dir) {
		if abs, err := filepath.Abs(dir); err == nil {
			dir = abs
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	// Create a copy of data for serialization — encrypt API key if encryption is enabled
	saveData := s.data
	if s.encKey != nil && saveData.Config.APIKey != "" && !strings.HasPrefix(saveData.Config.APIKey, encPrefix) {
		if enc, err := encryptValue(saveData.Config.APIKey, s.encKey); err == nil {
			saveData.Config.APIKey = encPrefix + enc
		}
	}

	data, err := json.MarshalIndent(saveData, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	target := filepath.Join(dir, "ai_config.json")
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		return fmt.Errorf("rename to %s: %w", target, err)
	}
	return nil
}

// Path returns the store directory path for debugging.
func (s *Store) Path() string { return s.path }

// GetConfig returns the current provider configuration.
func (s *Store) GetConfig() ProviderConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Config
}

// SetConfig updates the provider configuration and persists to disk.
func (s *Store) SetConfig(cfg ProviderConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Config = cfg
	return s.save()
}

// HasConfig returns true if a provider is configured with an API key.
func (s *Store) HasConfig() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Config.APIKey != "" && s.data.Config.BaseURL != ""
}

// AddResult appends an analysis result to history (ring buffer).
// AddResult appends an analysis result. Disk persistence is best-effort.
func (s *Store) AddResult(result AnalysisResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data.History = append(s.data.History, result)
	if len(s.data.History) > maxHistorySize {
		s.data.History = s.data.History[len(s.data.History)-maxHistorySize:]
	}

	// Update usage stats
	s.data.Usage.TotalTokensUsed += int64(result.TokensUsed)
	s.data.Usage.TotalRequests++
	s.data.Usage.TotalCostUSD += result.CostUSD

	for _, v := range result.Verdicts {
		switch v.Action {
		case "block":
			s.data.Usage.BlocksTriggered++
		case "monitor":
			s.data.Usage.MonitorsTriggered++
		}
	}

	return s.save()
}

// GetHistory returns the most recent N analysis results.
func (s *Store) GetHistory(n int) []AnalysisResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if n <= 0 || n > len(s.data.History) {
		n = len(s.data.History)
	}

	// Return most recent first
	result := make([]AnalysisResult, n)
	for i := range n {
		result[i] = s.data.History[len(s.data.History)-1-i]
	}
	return result
}

// GetUsage returns current usage stats, resetting hourly/daily counters if needed.
func (s *Store) GetUsage() UsageStats {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Reset hourly counters
	if now.After(s.data.Usage.HourResetAt) {
		s.data.Usage.TokensUsedHour = 0
		s.data.Usage.RequestsHour = 0
		s.data.Usage.HourResetAt = now.Truncate(time.Hour).Add(time.Hour)
	}

	// Reset daily counters
	if now.After(s.data.Usage.DayResetAt) {
		s.data.Usage.TokensUsedDay = 0
		s.data.Usage.RequestsDay = 0
		s.data.Usage.DayResetAt = now.Truncate(24 * time.Hour).Add(24 * time.Hour)
	}

	return s.data.Usage
}

// TrackUsage increments hourly and daily usage counters.
func (s *Store) TrackUsage(tokens int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Reset if needed
	if now.After(s.data.Usage.HourResetAt) {
		s.data.Usage.TokensUsedHour = 0
		s.data.Usage.RequestsHour = 0
		s.data.Usage.HourResetAt = now.Truncate(time.Hour).Add(time.Hour)
	}
	if now.After(s.data.Usage.DayResetAt) {
		s.data.Usage.TokensUsedDay = 0
		s.data.Usage.RequestsDay = 0
		s.data.Usage.DayResetAt = now.Truncate(24 * time.Hour).Add(24 * time.Hour)
	}

	s.data.Usage.TokensUsedHour += int64(tokens)
	s.data.Usage.TokensUsedDay += int64(tokens)
	s.data.Usage.RequestsHour++
	s.data.Usage.RequestsDay++
}

// WithinLimits checks if usage is within the configured limits.
func (s *Store) WithinLimits(maxTokensHour, maxTokensDay int64, maxReqsHour int) bool {
	usage := s.GetUsage()

	if maxTokensHour > 0 && usage.TokensUsedHour >= maxTokensHour {
		return false
	}
	if maxTokensDay > 0 && usage.TokensUsedDay >= maxTokensDay {
		return false
	}
	if maxReqsHour > 0 && usage.RequestsHour >= maxReqsHour {
		return false
	}
	return true
}

// loadOrCreateEncKey loads or auto-generates an encryption key file.
// The key is stored in a separate file (ai_enc_key) with 0600 permissions.
// This ensures API keys are always encrypted at rest, even without a dashboard API key.
func (s *Store) loadOrCreateEncKey() {
	keyPath := filepath.Join(s.path, encKeyFile)

	// Try loading existing key
	if data, err := os.ReadFile(keyPath); err == nil && len(data) == 32 {
		s.encKey = data
		return
	}

	// Generate new random key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Printf("[ai-store] WARNING: crypto/rand failed — API key encryption disabled: %v", err)
		return
	}

	// Persist the key
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		log.Printf("[ai-store] WARNING: failed to persist encryption key — API key may not survive restart: %v", err)
	}
	s.encKey = key
}

// deriveStoreKey performs PBKDF2-HMAC-SHA256 key derivation for the AI store.
func deriveStoreKey(password, salt []byte, iterations int) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	result := mac.Sum(nil)

	u := make([]byte, len(result))
	copy(u, result)

	for range iterations - 1 {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(u[:0])
		for i := range result {
			result[i] ^= u[i]
		}
	}
	return result
}
