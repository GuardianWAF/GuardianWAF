package challenge

import "testing"

// Regression: NewService defaulted only Difficulty == 0 and passed every other
// value straight through. A negative difficulty made hasLeadingZeroBits return
// true unconditionally (Go truncates -1/8 to 0 and -1%8 is negative), so the
// proof-of-work check auto-passed and bot mitigation was silently neutered. A
// difficulty above 256 indexed past the 32-byte SHA-256 hash and panicked in
// every verification request.
func TestNewServiceRejectsOutOfRangeDifficulty(t *testing.T) {
	for _, d := range []int{-1, -100, 257, 300, 4096} {
		if _, err := NewService(Config{Enabled: true, Difficulty: d}); err == nil {
			t.Fatalf("FAIL: NewService accepted difficulty %d (negative = PoW auto-passes; >256 = verification panic)", d)
		}
	}

	for _, d := range []int{0, 1, 20, 256} {
		svc, err := NewService(Config{Enabled: true, Difficulty: d})
		if err != nil {
			t.Fatalf("NewService(Difficulty: %d): %v", d, err)
		}
		if d == 0 && svc.config.Difficulty != 20 {
			t.Fatalf("difficulty 0 must default to 20, got %d", svc.config.Difficulty)
		}
	}
}

// TestHasLeadingZeroBitsNegativeDifficultyAutoPass pins the low-level
// semantics that made the constructor check necessary: negative difficulties
// trivially pass (the loop bounds truncate to zero and the remainder check is
// skipped). The constructor must therefore reject them before this is reached.
func TestHasLeadingZeroBitsNegativeDifficultyAutoPass(t *testing.T) {
	hash := make([]byte, 32) // all-zero hash
	if !hasLeadingZeroBits(hash, -1) {
		t.Fatalf("expected hasLeadingZeroBits(hash, -1) to trivially pass (pre-fix semantics)")
	}
}

// TestHasLeadingZeroBitsHighDifficultyPanics documents that hasLeadingZeroBits
// panics for difficulties above 256 (fullBytes exceeds the hash length). The
// constructor validation exists precisely to keep this unreachable.
func TestHasLeadingZeroBitsHighDifficultyPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatalf("expected hasLeadingZeroBits(hash, 300) to panic (index out of range)")
		}
	}()
	hash := make([]byte, 32)
	hasLeadingZeroBits(hash, 300)
}
