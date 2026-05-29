package main

import (
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"runtime"
	"time"
)

// generateDashboardPassword creates a cryptographically secure random password for dashboard.
func generateDashboardPassword() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 24)
	if _, err := cryptoRand.Read(b); err != nil {
		// CSPRNG failure is extremely rare. Fall back to hash-based generation
		// which is still non-deterministic because it includes process state.
		h := sha256.Sum256([]byte(fmt.Sprintf("%d%d%v", time.Now().UnixNano(), os.Getpid(), envForEntropy())))
		for i := range b {
			b[i] = charset[int(h[i%len(h)])%len(charset)]
		}
		fmt.Printf("[WARN] crypto/rand unavailable, using fallback entropy source: %v\n", err)
	} else {
		for i := range b {
			b[i] = charset[int(b[i])%len(charset)]
		}
	}
	return string(b)
}

// envForEntropy returns a small amount of process-specific data to mix into
// fallback password generation. Not a replacement for CSPRNG.
func envForEntropy() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return fmt.Sprintf("%d-%d-%d-%d", time.Now().UnixNano(), os.Getpid(), m.Alloc, m.NumGC)
}
