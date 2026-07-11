package main

import (
	"bytes"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func (b *lockedBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Len()
}

func (b *lockedBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.b.Reset()
}

type statsSnapshot struct {
	total, blocked, passed, logged, challenged, errors, totalLatency, maxLatency, minLatency int64
}

func snapshotStats() statsSnapshot {
	return statsSnapshot{
		total: stats.TotalRequests.Load(), blocked: stats.BlockedRequests.Load(),
		passed: stats.PassedRequests.Load(), logged: stats.LoggedRequests.Load(),
		challenged: stats.ChallengedRequests.Load(), errors: stats.Errors.Load(),
		totalLatency: stats.TotalLatency.Load(), maxLatency: stats.MaxLatency.Load(),
		minLatency: stats.MinLatency.Load(),
	}
}

func restoreStats(s statsSnapshot) {
	stats.TotalRequests.Store(s.total)
	stats.BlockedRequests.Store(s.blocked)
	stats.PassedRequests.Store(s.passed)
	stats.LoggedRequests.Store(s.logged)
	stats.ChallengedRequests.Store(s.challenged)
	stats.Errors.Store(s.errors)
	stats.TotalLatency.Store(s.totalLatency)
	stats.MaxLatency.Store(s.maxLatency)
	stats.MinLatency.Store(s.minLatency)
}

func resetGlobals(t *testing.T) {
	t.Helper()
	oldPayloads, oldClient, oldStats := payloads, client, snapshotStats()
	oldRandInt, oldRandRead, oldNow := randInt, randRead, now
	oldExit, oldEvery, oldSleep := exitProcess, reporterEvery, sleep
	oldStdout, oldStderr := stdout, stderr
	payloads = nil
	client = nil
	stats = Stats{}
	randInt = oldRandInt
	randRead = oldRandRead
	now = time.Now
	exitProcess = os.Exit
	reporterEvery = 2 * time.Second
	sleep = time.Sleep
	stdout, stderr = io.Discard, io.Discard
	t.Cleanup(func() {
		payloads, client = oldPayloads, oldClient
		restoreStats(oldStats)
		randInt, randRead, now = oldRandInt, oldRandRead, oldNow
		exitProcess, reporterEvery, sleep = oldExit, oldEvery, oldSleep
		stdout, stderr = oldStdout, oldStderr
	})
}

func fixedRandom(value int64) {
	randInt = func(io.Reader, *big.Int) (*big.Int, error) { return big.NewInt(value), nil }
}

func TestSecureRandomHelpers(t *testing.T) {
	resetGlobals(t)
	if got := secureIntn(0); got != 0 {
		t.Fatalf("secureIntn(0) = %d", got)
	}
	fixedRandom(3)
	if got := secureIntn(5); got != 3 {
		t.Fatalf("secureIntn(5) = %d", got)
	}
	randInt = func(io.Reader, *big.Int) (*big.Int, error) { return nil, errors.New("entropy") }
	now = func() time.Time { return time.Unix(0, 7) }
	if got := secureIntn(5); got != 2 {
		t.Fatalf("fallback secureIntn = %d", got)
	}

	randRead = func(p []byte) (int, error) {
		for i := range p {
			p[i] = byte(i)
		}
		return len(p), nil
	}
	if got := secureSessionID(); got != "sess_000102030405060708090a0b0c0d0e0f" {
		t.Fatalf("secureSessionID = %q", got)
	}
	randRead = func([]byte) (int, error) { return 0, errors.New("entropy") }
	if got := secureSessionID(); got != "sess_7" {
		t.Fatalf("fallback session ID = %q", got)
	}
}

func TestMainAndRun(t *testing.T) {
	t.Run("main exits on invalid flags", func(t *testing.T) {
		resetGlobals(t)
		oldArgs := os.Args
		os.Args = []string{"attack-simulation", "-bad-flag"}
		t.Cleanup(func() { os.Args = oldArgs })
		exited := 0
		exitProcess = func(code int) { exited = code }
		main()
		if exited != 2 {
			t.Fatalf("exit code = %d", exited)
		}
	})

	t.Run("load failure", func(t *testing.T) {
		resetGlobals(t)
		var errOut bytes.Buffer
		stderr = &errOut
		if code := run([]string{"-attacks", filepath.Join(t.TempDir(), "missing")}); code != 1 {
			t.Fatalf("run code = %d", code)
		}
		if !strings.Contains(errOut.String(), "Error loading payloads") {
			t.Fatalf("stderr = %q", errOut.String())
		}
	})

	t.Run("successful zero-worker run", func(t *testing.T) {
		resetGlobals(t)
		file := filepath.Join(t.TempDir(), "attacks.json")
		writeAttackPayloadFile(t, file, `{"xss":["x"]}`)
		var out bytes.Buffer
		stdout = &out
		nowTimes := []time.Time{time.Unix(10, 0), time.Unix(12, 0)}
		now = func() time.Time {
			v := nowTimes[0]
			nowTimes = nowTimes[1:]
			return v
		}
		sleep = func(time.Duration) {}
		if code := run([]string{"-attacks", file, "-workers", "0", "-duration", "0s"}); code != 0 {
			t.Fatalf("run code = %d", code)
		}
		if !strings.Contains(out.String(), "GuardianWAF") || !strings.Contains(out.String(), "TEST RESULTS") {
			t.Fatalf("output missing sections: %q", out.String())
		}
	})

	t.Run("successful worker run", func(t *testing.T) {
		resetGlobals(t)
		file := filepath.Join(t.TempDir(), "attacks.json")
		writeAttackPayloadFile(t, file, `{"xss":["x"]}`)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		sleep = func(time.Duration) { time.Sleep(2 * time.Millisecond) }
		if code := run([]string{"-target", server.URL, "-attacks", file, "-workers", "1", "-rate", "100000", "-duration", "1ms", "-mode", "attacks-only"}); code != 0 {
			t.Fatalf("run code = %d", code)
		}
	})
}

func TestReportProgress(t *testing.T) {
	resetGlobals(t)
	var out lockedBuffer
	stdout = &out
	reporterEvery = time.Millisecond
	stats.TotalRequests.Store(2)
	stats.BlockedRequests.Store(1)
	stats.PassedRequests.Store(1)
	stats.TotalLatency.Store(4000)
	now = func() time.Time { return time.Unix(2, 0) }
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { reportProgress(time.Unix(1, 0), stop); close(done) }()
	deadline := time.After(time.Second)
	for out.Len() == 0 {
		select {
		case <-deadline:
			t.Fatal("progress reporter did not tick")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	close(stop)
	<-done
	if !strings.Contains(out.String(), "Total: 2") || !strings.Contains(out.String(), "Avg: 2.00ms") {
		t.Fatalf("progress = %q", out.String())
	}

	out.Reset()
	stats = Stats{}
	stop = make(chan struct{})
	done = make(chan struct{})
	go func() { reportProgress(time.Unix(1, 0), stop); close(done) }()
	for out.Len() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(stop)
	<-done
}

func TestLoadPayloads(t *testing.T) {
	resetGlobals(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "attacks.json")
	writeAttackPayloadFile(t, path, `{
		"xss":["<script>",3,{"email":"a@example.com","password":"secret"},{"email":4},{"email":"missing"}],
		"ignored":{"not":"an array"}
	}`)
	dirty := filepath.Join(dir, "nested", "..", "attacks.json")
	if err := loadPayloads(dirty); err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 2 || payloads[1].Payload != "email=a@example.com&password=secret" {
		t.Fatalf("payloads = %#v", payloads)
	}
	if err := loadPayloads(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected read error")
	}
	bad := filepath.Join(dir, "bad.json")
	writeAttackPayloadFile(t, bad, "{")
	if err := loadPayloads(bad); err == nil {
		t.Fatal("expected JSON error")
	}
	if err := loadPayloads("bad\x00path"); err == nil {
		t.Fatal("expected NUL error")
	}
	if err := loadPayloads(""); err == nil {
		t.Fatal("expected empty path error")
	}
	clean, err := cleanAttackPayloadPath(dirty)
	if err != nil || clean != filepath.Clean(dirty) {
		t.Fatalf("clean = %q, %v", clean, err)
	}
}

func TestGenerateAttackRequests(t *testing.T) {
	resetGlobals(t)
	if req := generateAttackRequest("http://example.test"); req != nil {
		t.Fatalf("empty payload request = %v", req)
	}
	cases := []struct {
		category, payload, method, path, contentType string
	}{
		{"sqli", "' or 1=1", "GET", "/search", ""},
		{"xss", "<x>", "GET", "/search", ""},
		{"lfi", "../etc/passwd", "GET", "/search", ""},
		{"cmdi", "id", "POST", "/api/exec", "application/json"},
		{"ssrf", "http://localhost", "GET", "/proxy", ""},
		{"xxe", "<xml/>", "POST", "/api/upload", "application/xml"},
		{"brute_force_single_ip", "a=b", "POST", "/login", "application/x-www-form-urlencoded"},
		{"credential_stuffing", "a=b", "POST", "/login", "application/x-www-form-urlencoded"},
		{"other", "ignored", "GET", "/", ""},
	}
	fixedRandom(0)
	for _, tc := range cases {
		t.Run(tc.category, func(t *testing.T) {
			payloads = []AttackPayload{{Category: tc.category, Payload: tc.payload}}
			req := generateAttackRequest("http://example.test")
			if req.Method != tc.method || req.URL.Path != tc.path {
				t.Fatalf("request = %s %s", req.Method, req.URL)
			}
			if got := req.Header.Get("Content-Type"); got != tc.contentType {
				t.Fatalf("content type = %q", got)
			}
			if tc.method == "GET" && req.Header.Get("User-Agent") == "" {
				t.Fatal("browser headers missing")
			}
		})
	}
}

func TestGenerateLegitimateAndLoginRequests(t *testing.T) {
	resetGlobals(t)
	fixedRandom(0)
	req := generateLegitimateRequest("http://example.test")
	if req.URL.Path != "/" || len(req.Cookies()) != 0 {
		t.Fatalf("legitimate request = %v, cookies=%v", req.URL, req.Cookies())
	}

	randomValues := []int64{4, 0, 4}
	randInt = func(io.Reader, *big.Int) (*big.Int, error) {
		value := randomValues[0]
		randomValues = randomValues[1:]
		return big.NewInt(value), nil
	}
	randRead = func(p []byte) (int, error) { return len(p), nil }
	req = generateLegitimateRequest("https://example.test")
	cookie, err := req.Cookie("session")
	if err != nil || req.URL.Scheme != "https" || cookie.Value != "sess_00000000000000000000000000000000" {
		t.Fatalf("request URL/cookie = %s / %#v, %v", req.URL, cookie, err)
	}

	req = generateBruteForceRequest("http://example.test", 99, 8)
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "password=letmein") {
		t.Fatalf("brute force body = %q", body)
	}
	fixedRandom(2)
	req = generateCredentialStuffingRequest("http://example.test")
	body, _ = io.ReadAll(req.Body)
	if !strings.Contains(string(body), "user3%40hotmail.com") {
		t.Fatalf("credential body = %q", body)
	}
}

func TestRunWorkerModes(t *testing.T) {
	modes := []struct {
		name       string
		mode       string
		legitRatio int
	}{
		{name: "attacks-only", mode: "attacks-only", legitRatio: 1},
		{name: "legitimate-only", mode: "legitimate-only", legitRatio: 1},
		{name: "brute-force", mode: "brute-force", legitRatio: 1},
		{name: "credential-stuffing", mode: "credential-stuffing", legitRatio: 1},
		{name: "mixed-legitimate", mode: "mixed", legitRatio: 1},
		{name: "mixed-attack", mode: "mixed", legitRatio: 2},
	}
	for _, tc := range modes {
		t.Run(tc.name, func(t *testing.T) {
			resetGlobals(t)
			payloads = []AttackPayload{{Category: "xss", Payload: "x"}}
			fixedRandom(0)
			hit := make(chan struct{}, 10)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				select {
				case hit <- struct{}{}:
				default:
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			client = server.Client()
			stop := make(chan struct{})
			done := make(chan struct{})
			go func() { runWorker(1, server.URL, 100000, tc.legitRatio, tc.mode, stop); close(done) }()
			select {
			case <-hit:
				close(stop)
			case <-time.After(time.Second):
				close(stop)
				t.Fatal("worker did not issue request")
			}
			<-done
		})
	}

	t.Run("nil request then stop", func(t *testing.T) {
		resetGlobals(t)
		client = &http.Client{}
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() { runWorker(0, "http://example.test", 100000, 5, "attacks-only", stop); close(done) }()
		time.Sleep(time.Millisecond)
		close(stop)
		<-done
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestExecuteRequestResponses(t *testing.T) {
	statuses := []int{200, 403, 429, 401, 500, 302}
	for _, status := range statuses {
		t.Run(http.StatusText(status), func(t *testing.T) {
			resetGlobals(t)
			stats.MinLatency.Store(1 << 62)
			client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("body")), Header: make(http.Header)}, nil
			})}
			req, _ := http.NewRequest("GET", "http://example.test", nil)
			executeRequest(req)
			if stats.TotalRequests.Load() != 1 || stats.MinLatency.Load() == 1<<62 {
				t.Fatalf("total/min latency = %d/%d", stats.TotalRequests.Load(), stats.MinLatency.Load())
			}
		})
	}

	t.Run("transport error", func(t *testing.T) {
		resetGlobals(t)
		stats.MinLatency.Store(1 << 62)
		client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("network")
		})}
		req, _ := http.NewRequest("GET", "http://example.test", nil)
		executeRequest(req)
		if stats.Errors.Load() != 1 {
			t.Fatalf("errors = %d", stats.Errors.Load())
		}
	})
}

func TestPrintResults(t *testing.T) {
	resetGlobals(t)
	var out bytes.Buffer
	stdout = &out
	printResults(2 * time.Second)
	if !strings.Contains(out.String(), "Total Requests: 0") {
		t.Fatalf("zero output = %q", out.String())
	}
	out.Reset()
	stats.TotalRequests.Store(4)
	stats.BlockedRequests.Store(2)
	stats.PassedRequests.Store(1)
	stats.ChallengedRequests.Store(1)
	stats.LoggedRequests.Store(1)
	stats.Errors.Store(1)
	stats.TotalLatency.Store(8000)
	stats.MinLatency.Store(1000)
	stats.MaxLatency.Store(3000)
	printResults(2 * time.Second)
	if !strings.Contains(out.String(), "Block Rate:") || !strings.Contains(out.String(), "50.0") || !strings.Contains(out.String(), "%║") {
		t.Fatalf("results = %q", out.String())
	}
}

func writeAttackPayloadFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write attack payload file: %v", err)
	}
}
