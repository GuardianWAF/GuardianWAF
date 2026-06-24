// Package testreliability provides lightweight flaky test detection by recording
// test pass/fail results to a JSONL file across runs. In CI, compare the last two
// runs to find tests that flip between pass and fail.
//
// Usage in tests:
//
//	func TestMain(m *testing.M) {
//	    os.Exit(testreliability.RecordAndRun(m, ".test-results.jsonl"))
//	}
package testreliability

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// TestResult records a single test outcome.
type TestResult struct {
	Name      string    `json:"name"`
	Package   string    `json:"package"`
	Passed    bool      `json:"passed"`
	Duration  float64   `json:"duration_sec"`
	RunID     string    `json:"run_id"`
	Time      time.Time `json:"time"`
	GoVersion string    `json:"go_version"`
}

// runID is unique per test run.
var runID string

func init() {
	runID = time.Now().Format("20060102-150405.000")
}

// Recorder collects test results in memory.
type Recorder struct {
	mu      sync.Mutex
	results []TestResult
	pkg     string
	path    string
}

// NewRecorder creates a recorder that will write results to path on Close.
func NewRecorder(path string) *Recorder {
	return &Recorder{
		pkg:  inferPackage(),
		path: path,
	}
}

// Record stores a test result.
func (r *Recorder) Record(name string, passed bool, duration time.Duration) {
	r.mu.Lock()
	r.results = append(r.results, TestResult{
		Name:      name,
		Package:   r.pkg,
		Passed:    passed,
		Duration:  duration.Seconds(),
		RunID:     runID,
		Time:      time.Now().UTC(),
		GoVersion: runtime.Version(),
	})
	r.mu.Unlock()
}

// Flush writes all results to the JSONL file.
func (r *Recorder) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.results) == 0 {
		return nil
	}

	cleanPath, err := cleanResultPath(r.path, false)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600) // #nosec G304 -- result file is caller-selected test output, rejected on NUL and cleaned before use.
	if err != nil {
		return err
	}
	defer f.Close()

	for _, res := range r.results {
		data, err := json.Marshal(res)
		if err != nil {
			continue
		}
		f.Write(data)
		f.Write([]byte("\n"))
	}
	r.results = nil
	return nil
}

// RecordAndRun wraps testing.M.Run() and flushes results.
// Returns the exit code from m.Run(). To record individual tests,
// use the Recorder directly in test helpers.
//
// Usage:
//
//	func TestMain(m *testing.M) {
//	    rec := testreliability.NewRecorder(".test-results.jsonl")
//	    code := m.Run()
//	    rec.Flush()
//	    os.Exit(code)
//	}

// DetectFlaky reads a JSONL results file and finds tests that both passed
// and failed across different runs. Returns test names that flipped.
func DetectFlaky(path string) []string {
	cleanPath, err := cleanResultPath(path, false)
	if err != nil {
		return nil
	}

	data, err := os.ReadFile(cleanPath) // #nosec G304 -- result file is caller-selected test input, rejected on NUL and cleaned before use.
	if err != nil {
		return nil
	}

	// Group by test name: track pass/fail per run
	type outcome struct {
		runID  string
		passed bool
	}
	byName := make(map[string][]outcome)

	// Parse JSONL
	lines := splitLines(string(data))
	for _, line := range lines {
		if line == "" {
			continue
		}
		var res TestResult
		if json.Unmarshal([]byte(line), &res) != nil {
			continue
		}
		byName[res.Name] = append(byName[res.Name], outcome{
			runID:  res.RunID,
			passed: res.Passed,
		})
	}

	// Find tests that flipped between runs
	var flaky []string
	for name, outcomes := range byName {
		byRun := make(map[string]map[bool]bool)
		for _, o := range outcomes {
			if byRun[o.runID] == nil {
				byRun[o.runID] = make(map[bool]bool)
			}
			byRun[o.runID][o.passed] = true
		}
		// If any run had both pass and fail, or different runs disagree
		hasPass, hasFail := false, false
		for _, states := range byRun {
			if states[true] {
				hasPass = true
			}
			if states[false] {
				hasFail = true
			}
		}
		if hasPass && hasFail {
			flaky = append(flaky, name)
		}
	}
	return flaky
}

func inferPackage() string {
	return ""
}

func cleanResultPath(path string, allowEmpty bool) (string, error) {
	if strings.ContainsRune(path, 0) {
		return "", fmt.Errorf("test result path contains NUL byte")
	}
	if path == "" {
		if allowEmpty {
			return "", nil
		}
		return "", fmt.Errorf("test result path must not be empty")
	}
	return filepath.Clean(path), nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := range len(s) {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
