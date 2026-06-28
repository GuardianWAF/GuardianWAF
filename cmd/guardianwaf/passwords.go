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
	for i := range b {
		for {
			var buf [1]byte
			if _, err := cryptoRandRead(buf[:]); err != nil {
				return "", fmt.Errorf("generate dashboard password: crypto/rand failed: %w", err)
			}
			if int(buf[0]) < 256-(256%len(charset)) {
				b[i] = charset[int(buf[0])%len(charset)]
				break
			}
		}
	}
	return string(b), nil
}
