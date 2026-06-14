package main

import (
	cryptoRand "crypto/rand"
	"fmt"
)

var cryptoRandRead = cryptoRand.Read

// generateDashboardPassword creates a cryptographically secure random password for dashboard.
func generateDashboardPassword() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 24)
	if _, err := cryptoRandRead(b); err != nil {
		return "", fmt.Errorf("generate dashboard API key: crypto/rand failed: %w", err)
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b), nil
}
