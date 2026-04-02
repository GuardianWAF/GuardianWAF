// Package main provides a load testing and attack simulation tool for GuardianWAF.
// Run: go run main.go -target http://localhost:8088 -attacks attacks.json
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// AttackPayload represents a single attack payload
type AttackPayload struct {
	Category string
	Payload  string
}

// Stats tracks test statistics
type Stats struct {
	TotalRequests      atomic.Int64
	BlockedRequests    atomic.Int64
	PassedRequests     atomic.Int64
	LoggedRequests     atomic.Int64
	ChallengedRequests atomic.Int64
	Errors             atomic.Int64
	TotalLatency       atomic.Int64 // in microseconds
	MaxLatency         atomic.Int64
	MinLatency         atomic.Int64
}

var (
	stats    Stats
	payloads []AttackPayload
	client   *http.Client
)

func main() {
	target := flag.String("target", "http://localhost:8088", "Target WAF URL")
	duration := flag.Duration("duration", 30*time.Second, "Test duration")
	workers := flag.Int("workers", 10, "Number of concurrent workers")
	rate := flag.Int("rate", 50, "Requests per second per worker")
	attackFile := flag.String("attacks", "attacks.json", "Attack payloads JSON file")
	legitRatio := flag.Int("legit-ratio", 5, "1 in N requests is legitimate")
	mode := flag.String("mode", "mixed", "Test mode: mixed, attacks-only, legitimate-only, brute-force, credential-stuffing")
	flag.Parse()

	// Load attack payloads
	if err := loadPayloads(*attackFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading payloads: %v\n", err)
		os.Exit(1)
	}

	// Configure HTTP client
	client = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	fmt.Printf(`
╔══════════════════════════════════════════════════════════════╗
║           GuardianWAF Load Test & Attack Simulation          ║
╠══════════════════════════════════════════════════════════════╣
║  Target:        %-45s║
║  Duration:      %-45s║
║  Workers:       %-45d║
║  Rate:          %-45s║
║  Mode:          %-45s║
║  Legit Ratio:   %-45s║
║  Payloads:      %-45d║
╚══════════════════════════════════════════════════════════════╝

`, *target, *duration, *workers, fmt.Sprintf("%d req/s per worker", *rate), *mode, fmt.Sprintf("1 in %d", *legitRatio), len(payloads))

	// Initialize stats
	stats.MinLatency.Store(int64(^uint64(0) >> 1))

	// Start workers
	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	startTime := time.Now()

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			runWorker(workerID, *target, *rate, *legitRatio, *mode, stopCh)
		}(i)
	}

	// Progress reporter
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				elapsed := time.Since(startTime)
				total := stats.TotalRequests.Load()
				blocked := stats.BlockedRequests.Load()
				passed := stats.PassedRequests.Load()
				avgLatency := float64(0)
				if total > 0 {
					avgLatency = float64(stats.TotalLatency.Load()) / float64(total) / 1000
				}
				rps := float64(total) / elapsed.Seconds()
				fmt.Printf("\r[%6.1fs] Total: %d | Blocked: %d | Passed: %d | Errors: %d | RPS: %.0f | Avg: %.2fms   ",
					elapsed.Seconds(), total, blocked, passed, stats.Errors.Load(), rps, avgLatency)
			case <-stopCh:
				return
			}
		}
	}()

	// Wait for duration
	time.Sleep(*duration)
	close(stopCh)
	wg.Wait()

	// Print final results
	printResults(time.Since(startTime))
}

func loadPayloads(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	for category, p := range raw {
		switch items := p.(type) {
		case []any:
			for _, item := range items {
				switch v := item.(type) {
				case string:
					payloads = append(payloads, AttackPayload{Category: category, Payload: v})
				case map[string]any:
					// JSON objects (credential stuffing)
					if email, ok := v["email"].(string); ok {
						if pass, ok := v["password"].(string); ok {
							payloads = append(payloads, AttackPayload{
								Category: category,
								Payload:  fmt.Sprintf("email=%s&password=%s", email, pass),
							})
						}
					}
				}
			}
		}
	}

	return nil
}

func runWorker(workerID int, target string, rate int, legitRatio int, mode string, stopCh <-chan struct{}) {
	interval := time.Second / time.Duration(rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	legitCounter := 0

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			var req *http.Request

			switch mode {
			case "attacks-only":
				req = generateAttackRequest(target)
			case "legitimate-only":
				req = generateLegitimateRequest(target)
			case "brute-force":
				req = generateBruteForceRequest(target, workerID, legitCounter)
				legitCounter++
			case "credential-stuffing":
				req = generateCredentialStuffingRequest(target)
			default: // mixed
				legitCounter++
				if legitCounter%legitRatio == 0 {
					req = generateLegitimateRequest(target)
				} else {
					req = generateAttackRequest(target)
				}
			}

			if req == nil {
				continue
			}

			executeRequest(req)
		}
	}
}

func generateAttackRequest(target string) *http.Request {
	if len(payloads) == 0 {
		return nil
	}

	payload := payloads[rand.Intn(len(payloads))]
	method := "GET"
	path := "/"

	// Vary injection points based on category
	switch payload.Category {
	case "sqli", "xss", "lfi":
		// Inject in query parameters
		path = fmt.Sprintf("/search?q=%s&category=products", url.QueryEscape(payload.Payload))
	case "cmdi":
		// Inject in POST body
		method = "POST"
		path = "/api/exec"
		req, _ := http.NewRequestWithContext(context.Background(), method, target+path, bytes.NewBufferString(fmt.Sprintf(`{"command":"%q"}`, payload.Payload)))
		req.Header.Set("Content-Type", "application/json")
		return req
	case "ssrf":
		// Inject in URL parameter
		path = fmt.Sprintf("/proxy?url=%s", url.QueryEscape(payload.Payload))
	case "xxe":
		// Inject as XML body
		method = "POST"
		path = "/api/upload"
		req, _ := http.NewRequestWithContext(context.Background(), method, target+path, bytes.NewBufferString(payload.Payload))
		req.Header.Set("Content-Type", "application/xml")
		return req
	case "brute_force_single_ip", "credential_stuffing":
		method = "POST"
		path = "/login"
		req, _ := http.NewRequestWithContext(context.Background(), method, target+path, bytes.NewBufferString(payload.Payload))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}

	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, method, target+path, http.NoBody)
	addBrowserHeaders(req)
	return req
}

func generateLegitimateRequest(target string) *http.Request {
	paths := []string{
		"/",
		"/api/products",
		"/api/users/profile",
		"/search?q=laptop",
		"/category/electronics",
		"/about",
		"/contact",
		"/api/health",
		"/static/js/app.js",
		"/static/css/style.css",
	}

	path := paths[rand.Intn(len(paths))]
	req, _ := http.NewRequestWithContext(context.Background(), "GET", target+path, http.NoBody)
	addBrowserHeaders(req)

	// Sometimes add session cookie
	if rand.Intn(10) > 3 {
		req.AddCookie(&http.Cookie{
			Name:  "session",
			Value: fmt.Sprintf("sess_%d_%d", time.Now().Unix(), rand.Int63()),
		})
	}

	return req
}

func generateBruteForceRequest(target string, _, attempt int) *http.Request {
	// Same target email, different passwords - triggers brute force detection
	passwords := []string{"password123", "letmein", "qwerty", "123456", "admin", "welcome", "Password1!"}
	data := url.Values{}
	data.Set("email", "admin@example.com")
	data.Set("password", passwords[attempt%len(passwords)])

	req, _ := http.NewRequestWithContext(context.Background(), "POST", target+"/login", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func generateCredentialStuffingRequest(target string) *http.Request {
	// Different emails, same password - triggers credential stuffing detection
	emails := []string{
		"user1@gmail.com", "user2@yahoo.com", "user3@hotmail.com",
		"admin@company.com", "test@example.org", "john.doe@email.com",
	}
	data := url.Values{}
	data.Set("email", emails[rand.Intn(len(emails))])
	data.Set("password", "password123")

	req, _ := http.NewRequestWithContext(context.Background(), "POST", target+"/login", bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func addBrowserHeaders(req *http.Request) {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	}

	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")
}

func executeRequest(req *http.Request) {
	start := time.Now()

	resp, err := client.Do(req)
	latency := time.Since(start)

	stats.TotalRequests.Add(1)
	us := latency.Microseconds()
	stats.TotalLatency.Add(us)

	// Update min/max
	for {
		current := stats.MinLatency.Load()
		if us >= current || !stats.MinLatency.CompareAndSwap(current, us) {
			break
		}
	}
	for {
		current := stats.MaxLatency.Load()
		if us <= current || !stats.MaxLatency.CompareAndSwap(current, us) {
			break
		}
	}

	if err != nil {
		stats.Errors.Add(1)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	// Categorize response
	switch resp.StatusCode {
	case 200:
		stats.PassedRequests.Add(1)
	case 403:
		stats.BlockedRequests.Add(1)
	case 429:
		stats.ChallengedRequests.Add(1)
	case 401:
		stats.LoggedRequests.Add(1)
	default:
		if resp.StatusCode >= 400 {
			stats.BlockedRequests.Add(1)
		} else {
			stats.PassedRequests.Add(1)
		}
	}
}

func printResults(duration time.Duration) {
	total := stats.TotalRequests.Load()
	blocked := stats.BlockedRequests.Load()
	passed := stats.PassedRequests.Load()
	challenged := stats.ChallengedRequests.Load()
	logged := stats.LoggedRequests.Load()
	errors := stats.Errors.Load()

	var avgLatency float64
	if total > 0 {
		avgLatency = float64(stats.TotalLatency.Load()) / float64(total) / 1000 // ms
	}

	minLatency := stats.MinLatency.Load() / 1000
	maxLatency := stats.MaxLatency.Load() / 1000
	rps := float64(total) / duration.Seconds()

	blockRate := float64(0)
	if total > 0 {
		blockRate = float64(blocked) / float64(total) * 100
	}

	fmt.Printf(`

╔══════════════════════════════════════════════════════════════╗
║                      TEST RESULTS                            ║
╠══════════════════════════════════════════════════════════════╣
║  Duration:       %-43s║
║  Total Requests: %-43d║
║  Requests/sec:   %-43.0f║
╠══════════════════════════════════════════════════════════════╣
║  Passed:         %-43d║
║  Blocked (403):  %-43d║
║  Challenged(429):%-43d║
║  Logged (401):   %-43d║
║  Errors:         %-43d║
║  Block Rate:     %-43.1f%%║
╠══════════════════════════════════════════════════════════════╣
║  Latency (ms):                                               ║
║    Average:      %-43.2f║
║    Min:          %-43d║
║    Max:          %-43d║
╚══════════════════════════════════════════════════════════════╝
`, duration.Round(time.Millisecond), total, rps, passed, blocked, challenged, logged, errors, blockRate, avgLatency, minLatency, maxLatency)
}
