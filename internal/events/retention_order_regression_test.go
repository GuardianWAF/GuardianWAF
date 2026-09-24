package events

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Regression (round 2026-09-18): cleanupRotated sorted rotated files by
// reversed STRING order. Within one wall-clock second the same-second
// collision suffixes (-1, -2, ... from the rotation collision fix) order
// lexicographically ("-9" > "-12"), and the plain name — the OLDEST of a
// batch — outranks every suffixed name because '.' > '-', so the sweep could
// delete a NEWER rotation while retaining stale ones. Ordering is now by
// parsed timestamp and numeric suffix (parseRotatedName).

func TestCleanupRotatedSameSecondSuffixOrder(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "events")
	ts := "20260918-120000"

	// Chronological batch: plain (oldest), -1, -2, ... -11 (newest).
	names := []string{"events-" + ts + ".jsonl"}
	for i := 1; i <= 11; i++ {
		names = append(names, "events-"+ts+"-"+strconv.Itoa(i)+".jsonl")
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	fs := &FileStore{}
	fs.cleanupRotated(base, ".jsonl")

	// The two oldest (plain, -1) are pruned; the ten newest (-2..-11) survive.
	deleted := map[string]bool{
		"events-" + ts + ".jsonl":   true,
		"events-" + ts + "-1.jsonl": true,
	}
	for _, n := range names {
		_, err := os.Stat(filepath.Join(dir, n))
		if deleted[n] && err == nil {
			t.Fatalf("%s retained although newer same-second rotations were kept", n)
		}
		if !deleted[n] && err != nil {
			t.Fatalf("%s deleted although it is among the %d newest same-second rotations", n, defaultMaxRotated)
		}
	}
}

// A later second with a low suffix is newer than an earlier second with a
// high suffix — the timestamp dominates, the suffix only breaks same-second
// ties.
func TestCleanupRotatedTimestampDominatesSuffix(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "events")

	// Eleven files in second ...120000 (suffixes -1..-11) plus one file in the
	// newer second ...120001. Retention 10: the newer-second file must
	// survive; the older second's earliest files are pruned first.
	keep := "events-20260918-120001-1.jsonl"
	var names []string
	for i := 1; i <= 11; i++ {
		names = append(names, "events-20260918-120000-"+strconv.Itoa(i)+".jsonl")
	}
	names = append(names, keep)
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	fs := &FileStore{}
	fs.cleanupRotated(base, ".jsonl")

	if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
		t.Fatalf("newer-second file pruned although the older second had files to prune first: %v", err)
	}
	for i := 1; i <= 2; i++ {
		name := "events-20260918-120000-" + strconv.Itoa(i) + ".jsonl"
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Fatalf("%s survived although the older second had files to prune first", name)
		}
	}
}

// Names outside the rotation naming contract are never retention candidates:
// only parsed contract rotations participate, so non-contract files in the
// events dir survive every sweep.
func TestCleanupRotatedIgnoresNonContractNames(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "events")

	junk := "events-not-a-timestamp.jsonl"
	if err := os.WriteFile(filepath.Join(dir, junk), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= defaultMaxRotated; i++ {
		name := fmt.Sprintf("events-20260918-1200%02d.jsonl", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	fs := &FileStore{}
	fs.cleanupRotated(base, ".jsonl")

	if _, err := os.Stat(filepath.Join(dir, junk)); err != nil {
		t.Fatalf("non-contract file touched by the retention sweep: %v", err)
	}
	for i := 1; i <= defaultMaxRotated; i++ {
		name := fmt.Sprintf("events-20260918-1200%02d.jsonl", i)
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("parsed rotation %s pruned although retention capacity was not exceeded: %v", name, err)
		}
	}
}

// The filed risk, end to end: an operator file matching the sweep's catch-all
// glob is never a retention candidate — the cut lands on the oldest rotation
// instead.
func TestCleanupRotatedExemptsOperatorFilesFromRetention(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "events")
	ts := "20260918-120000"

	names := []string{"events-" + ts + ".jsonl"} // oldest rotation
	for i := 1; i <= 10; i++ {
		names = append(names, "events-"+ts+"-"+strconv.Itoa(i)+".jsonl")
	}
	opFile := "events-notes.jsonl"
	names = append(names, opFile)
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	fs := &FileStore{}
	fs.cleanupRotated(base, ".jsonl")

	if _, err := os.Stat(filepath.Join(dir, opFile)); err != nil {
		t.Fatalf("operator file %s deleted by the retention sweep", opFile)
	}
	// 11 contract rotations, retention 10: the oldest rotation is pruned, the
	// ten suffixed ones survive.
	if _, err := os.Stat(filepath.Join(dir, names[0])); err == nil {
		t.Fatalf("oldest rotation retained although contract rotations exceeded retention capacity")
	}
	for i := 1; i <= 10; i++ {
		name := "events-" + ts + "-" + strconv.Itoa(i) + ".jsonl"
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("suffixed rotation %s pruned although it is among the newest: %v", name, err)
		}
	}
}
