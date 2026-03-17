package dashboard

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

// AuthMiddleware checks for an API key in the X-GuardianWAF-Key header
// or the ?api_key= query parameter. If apiKey is empty, authentication
// is disabled and all requests pass through.
func AuthMiddleware(apiKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apiKey == "" {
			next.ServeHTTP(w, r)
			return
		}

		key := r.Header.Get("X-GuardianWAF-Key")
		if key == "" {
			key = r.URL.Query().Get("api_key")
		}

		if key != apiKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]string{
					"code":    "unauthorized",
					"message": "Invalid or missing API key",
				},
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GenerateAPIKey generates a random 32-byte hex-encoded API key (64 characters).
func GenerateAPIKey() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		// Extremely unlikely; return a deterministic fallback.
		return "0000000000000000000000000000000000000000000000000000000000000000"
	}
	return hex.EncodeToString(b)
}
