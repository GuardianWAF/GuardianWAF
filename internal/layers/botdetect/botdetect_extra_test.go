package botdetect

import (
	"sync"
	"testing"
	"time"
)

// TestComputeJA4_EmptyProtocol verifies that an empty Protocol defaults to "t".
func TestComputeJA4_EmptyProtocol(t *testing.T) {
	params := JA4Params{
		Protocol:         "",
		TLSVersion:       0x0304,
		SNI:              true,
		CipherSuites:     []uint16{0x1301},
		Extensions:       []uint16{0x001b},
		ALPN:             "h2",
		SupportedVersion: 0x0304,
	}
	fp := ComputeJA4(params)
	if fp.Full[0] != 't' {
		t.Errorf("expected protocol 't' for empty input, got %q", fp.Full[0])
	}
}

// TestComputeJA4_ManyExtensions verifies that >99 extensions are capped at 99.
func TestComputeJA4_ManyExtensions(t *testing.T) {
	exts := make([]uint16, 105)
	for i := range 105 {
		exts[i] = uint16(0x0001 + i)
	}
	params := JA4Params{
		Protocol:         "t",
		TLSVersion:       0x0304,
		SNI:              true,
		CipherSuites:     []uint16{0x1301},
		Extensions:       exts,
		ALPN:             "h2",
		SupportedVersion: 0x0304,
	}
	fp := ComputeJA4(params)
	parts := splitJA4(fp.Full)
	if parts[0][6:8] != "99" {
		t.Errorf("expected extension count '99', got %q in %s", parts[0][6:8], parts[0])
	}
}

// TestComputeJA4_OnlySigAlgs verifies the sigAlgList-only branch in ComputeJA4.
func TestComputeJA4_OnlySigAlgs(t *testing.T) {
	params := JA4Params{
		Protocol:         "t",
		TLSVersion:       0x0304,
		SNI:              true,
		CipherSuites:     []uint16{0x1301},
		Extensions:       []uint16{},
		ALPN:             "h2",
		SignatureAlgs:    []uint16{0x0403},
		SupportedVersion: 0x0304,
	}
	fp := ComputeJA4(params)
	parts := splitJA4(fp.Full)
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	if parts[2] == "000000000000" {
		t.Error("expected non-empty part C when only signature algorithms are present")
	}
}

// TestBehaviorTracker_UniquePathsThreshold exercises the UniquePathsPerMin branch.
func TestBehaviorTracker_UniquePathsThreshold(t *testing.T) {
	cfg := BehaviorConfig{
		Window:             1 * time.Minute,
		RPSThreshold:       0,
		UniquePathsPerMin:  5,
		ErrorRateThreshold: 0,
		TimingStdDevMs:     0,
	}
	tracker := newBehaviorTracker(cfg.Window)
	for i := range 10 {
		tracker.record("/path/"+string(rune('a'+i)), false, 10*time.Millisecond)
	}
	score, findings := tracker.analyze(cfg)
	if score == 0 {
		t.Error("expected non-zero score for excessive unique paths")
	}
	hasEnum := false
	for _, f := range findings {
		if f == "excessive path enumeration detected" {
			hasEnum = true
		}
	}
	if !hasEnum {
		t.Errorf("expected path enumeration finding, got %v", findings)
	}
}

// TestBehaviorManager_GetOrCreate_DoubleCheck exercises the double-check path
// inside getOrCreate when two goroutines race for the same IP.
func TestBehaviorManager_GetOrCreate_DoubleCheck(t *testing.T) {
	for attempt := 0; attempt < 50; attempt++ {
		bm := NewBehaviorManager(BehaviorConfig{Window: time.Minute})
		var wg sync.WaitGroup
		ready := make(chan struct{})
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-ready
				_ = bm.getOrCreate("1.2.3.4")
			}()
		}
		close(ready)
		wg.Wait()
		if bm.TrackerCount() != 1 {
			t.Fatalf("expected 1 tracker, got %d", bm.TrackerCount())
		}
	}
}
