package smuggling

// Regression (round 2026-09-27-smuggling-distinctint-collapse): Vector 2's
// distinctInts mapped EVERY malformed Content-Length value to the shared
// sentinel -1, so distinctInts(["abc","xyz"]) == [-1] — two different
// malformed headers were NOT reported as distinct and produced no CL.CL
// finding, contradicting the function's own doc contract ("Invalid values are
// treated as distinct from each other") and the round-26 audit's recorded
// fail-safe behaviour. The sentinel also collided with the parseable value -1:
// ["-1","abc"] collapsed to [-1,-1] and produced no finding despite different
// values. distinctIntCount now compares parseable values numerically after
// trimming (unchanged) and treats each distinct malformed literal as its own
// value in a "raw:"-prefixed space that cannot collide with the "int:" space.

import (
	"strings"
	"testing"
)

func hasDuplicateCL(t *testing.T, values []string) bool {
	t.Helper()
	res := NewDetector(true, 1.0).Process(newCtx(map[string][]string{
		"Content-Length": values,
	}, "HTTP/1.1"))
	for _, f := range res.Findings {
		if strings.Contains(f.Description, "duplicate Content-Length") {
			return true
		}
	}
	return false
}

// Defect case 1: two DISTINCT malformed values must count as distinct — the
// old shared -1 sentinel collapsed them into one value and silenced Vector 2.
func TestDuplicateCL_DistinctMalformedValuesFlagged(t *testing.T) {
	if !hasDuplicateCL(t, []string{"abc", "xyz"}) {
		t.Fatal("two different malformed Content-Length values must be reported as distinct (CL.CL finding)")
	}
}

// Defect case 2: a parseable -1 must not collide with a malformed value under
// a shared sentinel — the values are different, so Vector 2 must fire.
func TestDuplicateCL_ParseableMinusOneNotCollapsedWithMalformed(t *testing.T) {
	if !hasDuplicateCL(t, []string{"-1", "abc"}) {
		t.Fatal("Content-Length -1 and a malformed value are different values; CL.CL finding expected")
	}
}

// Boundary: identical malformed text stays excluded, symmetric with the
// documented identical-valid exclusion (TestDetector_DuplicateContentLength_Same).
func TestDuplicateCL_IdenticalMalformedValuesNotFlagged(t *testing.T) {
	if hasDuplicateCL(t, []string{"abc", "abc"}) {
		t.Fatal("identical malformed Content-Length values must stay excluded")
	}
}

// Control: different parseable values keep triggering (pre-existing pin).
func TestDuplicateCL_DifferentValidControl(t *testing.T) {
	if !hasDuplicateCL(t, []string{"0", "100"}) {
		t.Fatal("different valid Content-Length values must trigger Vector 2")
	}
}

// Control: identical parseable values keep being excluded (pre-existing pin).
func TestDuplicateCL_IdenticalValidControl(t *testing.T) {
	if hasDuplicateCL(t, []string{"100", "100"}) {
		t.Fatal("identical valid Content-Length values must stay excluded")
	}
}

// Control: trimming keeps equal numbers equal (" 5" and "5" are the same value).
func TestDuplicateCL_TrimmedValuesEqual(t *testing.T) {
	if hasDuplicateCL(t, []string{" 5 ", "5"}) {
		t.Fatal("values equal after trimming must stay excluded")
	}
}
