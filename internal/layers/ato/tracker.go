// Package ato provides Account Takeover Protection features.
// It includes brute force detection, credential stuffing detection,
// password spray detection, and impossible travel detection.
package ato

import (
	"crypto/sha256"
	"net"
	"sync"
	"time"
)

// AttemptTracker tracks login attempts per IP and per email.
type AttemptTracker struct {
	mu             sync.RWMutex
	ipAttempts     map[string]*AttemptRecord  // IP -> attempts
	emailAttempts  map[string]*AttemptRecord  // Email -> attempts
	ipToEmails     map[string]map[string]bool // IP -> set of emails tried
	emailToIPs     map[string]map[string]bool // Email -> set of IPs used
	passwordHashes map[string]*PasswordRecord // Password hash -> record
}

// AttemptRecord tracks failed login attempts.
type AttemptRecord struct {
	mu           sync.RWMutex
	Attempts     []time.Time
	BlockedUntil time.Time
	BlockReason  string
}

// PasswordRecord tracks password usage for spray detection.
type PasswordRecord struct {
	mu        sync.RWMutex
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
	SourceIPs map[string]bool
}

// GeoLocation represents a geographic location.
type GeoLocation struct {
	Country   string
	City      string
	Latitude  float64
	Longitude float64
}

// LoginAttempt represents a login attempt for tracking.
type LoginAttempt struct {
	IP       net.IP
	Email    string
	Password string // Only for hash comparison, never stored
	Time     time.Time
	Location *GeoLocation
	Success  bool
}

// NewAttemptTracker creates a new attempt tracker.
func NewAttemptTracker() *AttemptTracker {
	return &AttemptTracker{
		ipAttempts:     make(map[string]*AttemptRecord),
		emailAttempts:  make(map[string]*AttemptRecord),
		ipToEmails:     make(map[string]map[string]bool),
		emailToIPs:     make(map[string]map[string]bool),
		passwordHashes: make(map[string]*PasswordRecord),
	}
}

// RecordAttempt records a failed login attempt.
func (t *AttemptTracker) RecordAttempt(attempt LoginAttempt) {
	t.mu.Lock()
	defer t.mu.Unlock()

	ip := attempt.IP.String()
	now := attempt.Time
	if now.IsZero() {
		now = time.Now()
	}

	// Record IP attempt
	ipRec := t.ipAttempts[ip]
	if ipRec == nil {
		ipRec = &AttemptRecord{Attempts: []time.Time{}}
		t.ipAttempts[ip] = ipRec
	}
	ipRec.mu.Lock()
	ipRec.Attempts = append(ipRec.Attempts, now)
	ipRec.mu.Unlock()

	// Record email attempt
	if attempt.Email != "" {
		emailRec := t.emailAttempts[attempt.Email]
		if emailRec == nil {
			emailRec = &AttemptRecord{Attempts: []time.Time{}}
			t.emailAttempts[attempt.Email] = emailRec
		}
		emailRec.mu.Lock()
		emailRec.Attempts = append(emailRec.Attempts, now)
		emailRec.mu.Unlock()

		// Track IP->Email mapping for credential stuffing
		if t.ipToEmails[ip] == nil {
			t.ipToEmails[ip] = make(map[string]bool)
		}
		t.ipToEmails[ip][attempt.Email] = true

		// Track Email->IP mapping
		if t.emailToIPs[attempt.Email] == nil {
			t.emailToIPs[attempt.Email] = make(map[string]bool)
		}
		t.emailToIPs[attempt.Email][ip] = true
	}

	// Record password hash for spray detection
	if attempt.Password != "" {
		hash := hashPassword(attempt.Password)
		pwRec := t.passwordHashes[hash]
		if pwRec == nil {
			pwRec = &PasswordRecord{
				FirstSeen: now,
				SourceIPs: make(map[string]bool),
			}
			t.passwordHashes[hash] = pwRec
		}
		pwRec.mu.Lock()
		pwRec.Count++
		pwRec.LastSeen = now
		pwRec.SourceIPs[ip] = true
		pwRec.mu.Unlock()
	}
}

// GetIPAttempts returns the number of attempts from an IP within the window.
func (t *AttemptTracker) GetIPAttempts(ip net.IP, window time.Duration) int {
	t.mu.RLock()
	rec, ok := t.ipAttempts[ip.String()]
	t.mu.RUnlock()

	if !ok {
		return 0
	}

	rec.mu.RLock()
	defer rec.mu.RUnlock()

	now := time.Now()
	cutoff := now.Add(-window)
	count := 0
	for _, t := range rec.Attempts {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

// GetEmailAttempts returns the number of attempts for an email within the window.
func (t *AttemptTracker) GetEmailAttempts(email string, window time.Duration) int {
	t.mu.RLock()
	rec, ok := t.emailAttempts[email]
	t.mu.RUnlock()

	if !ok {
		return 0
	}

	rec.mu.RLock()
	defer rec.mu.RUnlock()

	now := time.Now()
	cutoff := now.Add(-window)
	count := 0
	for _, t := range rec.Attempts {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

// GetUniqueIPsForEmail returns the number of unique IPs that tried an email.
func (t *AttemptTracker) GetUniqueIPsForEmail(email string) int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	ips := t.emailToIPs[email]
	if ips == nil {
		return 0
	}
	return len(ips)
}

// GetPasswordUseCount returns how many times a password has been used.
func (t *AttemptTracker) GetPasswordUseCount(password string) int {
	hash := hashPassword(password)

	t.mu.RLock()
	rec, ok := t.passwordHashes[hash]
	t.mu.RUnlock()

	if !ok {
		return 0
	}

	rec.mu.RLock()
	defer rec.mu.RUnlock()
	return rec.Count
}

// BlockIP blocks an IP until the specified time.
func (t *AttemptTracker) BlockIP(ip net.IP, until time.Time, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	ipStr := ip.String()
	rec := t.ipAttempts[ipStr]
	if rec == nil {
		rec = &AttemptRecord{}
		t.ipAttempts[ipStr] = rec
	}
	rec.mu.Lock()
	rec.BlockedUntil = until
	rec.BlockReason = reason
	rec.mu.Unlock()
}

// BlockEmail blocks an email until the specified time.
func (t *AttemptTracker) BlockEmail(email string, until time.Time, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	rec := t.emailAttempts[email]
	if rec == nil {
		rec = &AttemptRecord{}
		t.emailAttempts[email] = rec
	}
	rec.mu.Lock()
	rec.BlockedUntil = until
	rec.BlockReason = reason
	rec.mu.Unlock()
}

// IsIPBlocked checks if an IP is currently blocked.
func (t *AttemptTracker) IsIPBlocked(ip net.IP) (blocked bool, reason string) {
	t.mu.RLock()
	rec, ok := t.ipAttempts[ip.String()]
	t.mu.RUnlock()

	if !ok {
		return false, ""
	}

	rec.mu.RLock()
	defer rec.mu.RUnlock()

	if time.Now().Before(rec.BlockedUntil) {
		return true, rec.BlockReason
	}
	return false, ""
}

// IsEmailBlocked checks if an email is currently blocked.
func (t *AttemptTracker) IsEmailBlocked(email string) (blocked bool, reason string) {
	t.mu.RLock()
	rec, ok := t.emailAttempts[email]
	t.mu.RUnlock()

	if !ok {
		return false, ""
	}

	rec.mu.RLock()
	defer rec.mu.RUnlock()

	if time.Now().Before(rec.BlockedUntil) {
		return true, rec.BlockReason
	}
	return false, ""
}

// Cleanup removes old attempts to prevent memory bloat.
func (t *AttemptTracker) Cleanup(maxAge time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)

	// Cleanup IP attempts
	for ip, rec := range t.ipAttempts {
		rec.mu.Lock()
		var valid []time.Time
		for _, t := range rec.Attempts {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		rec.Attempts = valid
		rec.mu.Unlock()

		// Remove if empty and not blocked
		if len(valid) == 0 && time.Now().After(rec.BlockedUntil) {
			delete(t.ipAttempts, ip)
		}
	}

	// Cleanup email attempts
	for email, rec := range t.emailAttempts {
		rec.mu.Lock()
		var valid []time.Time
		for _, t := range rec.Attempts {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		rec.Attempts = valid
		rec.mu.Unlock()

		// Remove if empty and not blocked
		if len(valid) == 0 && time.Now().After(rec.BlockedUntil) {
			delete(t.emailAttempts, email)
		}
	}

	// Cleanup password hashes
	for hash, rec := range t.passwordHashes {
		rec.mu.Lock()
		if rec.LastSeen.Before(cutoff) {
			delete(t.passwordHashes, hash)
		}
		rec.mu.Unlock()
	}
}

// ClearAttempt clears attempts for an IP or email (after successful login).
func (t *AttemptTracker) ClearAttempt(ip net.IP, email string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if ip != nil {
		delete(t.ipAttempts, ip.String())
	}

	if email != "" {
		delete(t.emailAttempts, email)
	}
}

// Stats returns tracking statistics.
func (t *AttemptTracker) Stats() map[string]int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	blockedIPs := 0
	blockedEmails := 0
	now := time.Now()

	for _, rec := range t.ipAttempts {
		if now.Before(rec.BlockedUntil) {
			blockedIPs++
		}
	}

	for _, rec := range t.emailAttempts {
		if now.Before(rec.BlockedUntil) {
			blockedEmails++
		}
	}

	return map[string]int{
		"tracked_ips":       len(t.ipAttempts),
		"tracked_emails":    len(t.emailAttempts),
		"tracked_passwords": len(t.passwordHashes),
		"blocked_ips":       blockedIPs,
		"blocked_emails":    blockedEmails,
	}
}

// hashPassword creates a hash of the password for comparison.
func hashPassword(password string) string {
	h := sha256.Sum256([]byte(password))
	return string(h[:])
}
