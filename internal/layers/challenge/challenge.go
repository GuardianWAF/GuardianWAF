// Package challenge implements a JavaScript proof-of-work challenge for bot mitigation.
// When the WAF pipeline returns ActionChallenge, this package serves an HTML page
// that requires the client's browser to solve a SHA-256 proof-of-work puzzle.
// Upon successful solution, an HMAC-signed cookie is set so subsequent requests pass through.
package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Config holds the JS challenge configuration.
type Config struct {
	Enabled    bool
	Difficulty int           // number of leading zero bits required (default: 20 ≈ ~1M hashes)
	CookieTTL  time.Duration // how long the challenge cookie is valid
	CookieName string
	SecretKey  []byte // HMAC signing key

	// ClientIPExtractor optionally overrides the default RemoteAddr-based IP extraction.
	// Set this to a trusted-proxy-aware function (e.g., engine's extractClientIP) so
	// the challenge cookie is bound to the same IP used by the engine for validation.
	// If nil, defaults to parsing RemoteAddr directly.
	ClientIPExtractor func(*http.Request) net.IP
}

// DefaultConfig returns a production-safe default configuration.
func DefaultConfig() Config {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// CSPRNG failure — log warning and continue with insecure key.
		// This should never happen on a正常运行 system.
		// The process is likely running in a broken/forked state.
		log.Fatalf("FATAL: crypto/rand.Read failed — cannot generate secure challenge key: %v", err)
	}

	return Config{
		Enabled:    false,
		Difficulty: 20,
		CookieTTL:  1 * time.Hour,
		CookieName: "__gwaf_challenge",
		SecretKey:  key,
	}
}

// Service handles challenge page serving and solution verification.
type Service struct {
	config Config
}

// NewService creates a new challenge service.
func NewService(cfg Config) *Service {
	if len(cfg.SecretKey) == 0 {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			// CSPRNG failure — zero key is predictable, fail hard
			log.Fatalf("FATAL: crypto/rand.Read failed — cannot generate secure challenge key: %v", err)
		}
		cfg.SecretKey = key
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "__gwaf_challenge"
	}
	if cfg.CookieTTL == 0 {
		cfg.CookieTTL = 1 * time.Hour
	}
	if cfg.Difficulty == 0 {
		cfg.Difficulty = 20
	}
	return &Service{config: cfg}
}

// HasValidCookie checks whether the request carries a valid, non-expired challenge cookie.
func (s *Service) HasValidCookie(r *http.Request, clientIP net.IP) bool {
	cookie, err := r.Cookie(s.config.CookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	return s.verifyToken(cookie.Value, clientIP)
}

// ServeChallengePage writes the JS challenge HTML page to the response.
// The page contains inline JavaScript that solves a SHA-256 proof-of-work
// and submits the solution to the verification endpoint.
func (s *Service) ServeChallengePage(w http.ResponseWriter, r *http.Request) {
	challenge := s.generateChallenge()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("X-GuardianWAF-Challenge", "1")
	w.WriteHeader(http.StatusForbidden)

	page := buildChallengePage(challenge, s.config.Difficulty, r.URL.RequestURI())
	_, _ = w.Write([]byte(page))
}

// VerifyHandler returns an http.Handler for the challenge verification endpoint.
// POST /__guardianwaf/challenge/verify
// Form fields: challenge, nonce, redirect
func (s *Service) VerifyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB max
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		challenge := r.FormValue("challenge")
		nonce := r.FormValue("nonce")
		redirect := r.FormValue("redirect")

		if challenge == "" || nonce == "" {
			http.Error(w, "Missing fields", http.StatusBadRequest)
			return
		}

		// Verify the proof-of-work solution
		if !verifyPoW(challenge, nonce, s.config.Difficulty) {
			http.Error(w, "Invalid solution", http.StatusForbidden)
			return
		}

		// Generate signed cookie token
		var clientIP net.IP
		if s.config.ClientIPExtractor != nil {
			clientIP = s.config.ClientIPExtractor(r)
		} else {
			clientIP = extractClientIP(r)
		}
		token := s.generateToken(clientIP)

		http.SetCookie(w, &http.Cookie{
			Name:     s.config.CookieName,
			Value:    token,
			Path:     "/",
			MaxAge:   int(s.config.CookieTTL.Seconds()),
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
		})

		// Sanitize redirect path — must be a safe site-relative path
		if redirect == "" || redirect[0] != '/' || (len(redirect) > 1 && redirect[1] == '/') {
			redirect = "/"
		}

		http.Redirect(w, r, redirect, http.StatusSeeOther)
	})
}

// VerifyPath is the endpoint path for challenge verification.
const VerifyPath = "/__guardianwaf/challenge/verify"

// --- Token management ---

// generateToken creates an HMAC-signed token: hex(expiry|ip|hmac).
func (s *Service) generateToken(clientIP net.IP) string {
	expiry := time.Now().Add(s.config.CookieTTL).Unix()
	ip := "0.0.0.0"
	if clientIP != nil {
		ip = clientIP.String()
	}
	payload := fmt.Sprintf("%d|%s", expiry, ip)
	mac := s.computeHMAC(payload)
	return hex.EncodeToString([]byte(payload)) + "." + mac
}

// verifyToken validates an HMAC-signed token and checks expiration + IP binding.
func (s *Service) verifyToken(token string, clientIP net.IP) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}

	payloadBytes, err := hex.DecodeString(parts[0])
	if err != nil {
		return false
	}
	payload := string(payloadBytes)

	// Verify HMAC
	expectedMAC := s.computeHMAC(payload)
	if !hmac.Equal([]byte(parts[1]), []byte(expectedMAC)) {
		return false
	}

	// Parse payload: "expiry|ip"
	pparts := strings.SplitN(payload, "|", 2)
	if len(pparts) != 2 {
		return false
	}

	expiry, err := strconv.ParseInt(pparts[0], 10, 64)
	if err != nil {
		return false
	}
	if time.Now().Unix() > expiry {
		return false // expired
	}

	// Verify IP binding
	ip := "0.0.0.0"
	if clientIP != nil {
		ip = clientIP.String()
	}
	return pparts[1] == ip
}

// computeHMAC returns the hex-encoded HMAC-SHA256 of data.
func (s *Service) computeHMAC(data string) string {
	mac := hmac.New(sha256.New, s.config.SecretKey)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// --- PoW challenge ---

// generateChallenge creates a random challenge string for proof-of-work.
func (s *Service) generateChallenge() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback: read from crypto/rand reader directly
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			// crypto/rand unavailable — fail hard rather than using predictable nonce
			log.Fatalf("FATAL: crypto/rand and io.ReadFull both failed — cannot generate secure nonce: %v", err)
		}
	}
	return hex.EncodeToString(b)
}

// verifyPoW checks that SHA256(challenge + nonce) has the required leading zero bits.
func verifyPoW(challenge, nonce string, difficulty int) bool {
	data := challenge + nonce
	hash := sha256.Sum256([]byte(data))
	return hasLeadingZeroBits(hash[:], difficulty)
}

// hasLeadingZeroBits checks if a byte slice has at least n leading zero bits.
func hasLeadingZeroBits(hash []byte, n int) bool {
	fullBytes := n / 8
	remainBits := n % 8

	for i := range fullBytes {
		if hash[i] != 0 {
			return false
		}
	}

	if remainBits > 0 && fullBytes < len(hash) {
		mask := byte(0xFF << (8 - remainBits))
		if hash[fullBytes]&mask != 0 {
			return false
		}
	}

	return true
}

// --- IP extraction (local copy to avoid import cycle) ---
// Only trusts proxy headers (X-Forwarded-For, X-Real-IP) from RemoteAddr.
// Does not apply trusted proxy filtering here — the engine's extractClientIP
// handles that. This is a fallback for the challenge layer which only needs
// the direct peer IP for cookie binding.

func extractClientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}
