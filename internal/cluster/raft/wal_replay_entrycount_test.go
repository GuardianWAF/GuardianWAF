package raft

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The WAL decoder bounds payloads at 16 MB (decodeWALRecord) and record sizes
// at 32 MB (maxWALRecordSize) specifically so a corrupt record cannot cause an
// oversized allocation during replay. The WALSnapshot branch bypasses that
// design: its corruption-controlled entryCount (uint32) drives
// make([]LogEntry, 0, entryCount) before any validation — a CRC-valid record
// with entryCount=0xFFFFFFFF attempts a ~171 GB allocation inside Replay,
// which runs in New() at startup. On default Linux the reservation is
// virtual-only and transient; on Windows, strict-overcommit Linux, or
// commit-charged containers it is a hard failure — crash-looping the node on
// every boot. Either way the allocation itself is measurable and must not
// happen: Replay must reject the record at validation time.
func TestReplay_CorruptSnapshotEntryCountFailsCleanly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "raft.wal")

	// Craft a CRC-valid WAL: magic header + one WALSnapshot record whose
	// entryCount field is 0xFFFFFFFF while the payload is tiny (14 bytes).
	var payload []byte
	payload = append(payload, byte(WALSnapshot))
	payload = binary.BigEndian.AppendUint64(payload, 5)          // term
	payload = binary.BigEndian.AppendUint16(payload, 0)          // votedFor: ""
	payload = binary.BigEndian.AppendUint32(payload, 0xFFFFFFFF) // entryCount — absurd

	rec := make([]byte, 0, 4+len(payload)+4)
	rec = binary.BigEndian.AppendUint32(rec, uint32(len(payload)))
	rec = append(rec, payload...)
	rec = binary.BigEndian.AppendUint32(rec, crc32sum(payload))

	var buf bytes.Buffer
	buf.WriteString(magicWALHeader)
	buf.Write(rec)

	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	wal, err := OpenWAL(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer wal.Close()

	ps := NewPersistentState()

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("FAIL: Replay panicked on a corrupt snapshot entryCount (attempted a ~171 GB allocation): %v — a corrupt WAL file must fail replay cleanly, never crash the node at startup", rec)
		}
	}()

	// Replay's documented recovery contract: a corrupt record stops replay at
	// the last valid record (truncating the torn tail) and returns nil. The
	// DEFECT is the oversized allocation the corrupt count used to trigger
	// before that stop — it must never happen.
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	_ = wal.Replay(ps)

	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc

	if allocated > 1<<30 {
		t.Fatalf("FAIL: Replay allocated %d bytes (%.1f GB) from a 13-byte corrupt record — entryCount bypasses the WAL's oversized-allocation protection", allocated, float64(allocated)/(1<<30))
	}
	if allocated > 1<<20 {
		t.Fatalf("FAIL: Replay allocated %d MB from a 13-byte corrupt record — exceeds any sane validation overhead", allocated>>20)
	}
}
