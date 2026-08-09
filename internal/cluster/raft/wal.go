package raft

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// WAL record types.
type WALRecordType uint8

const (
	WALState    WALRecordType = 1 // term/votedFor change
	WALLog      WALRecordType = 2 // log entry append
	WALTruncate WALRecordType = 3 // log truncation from index
	WALSnapshot WALRecordType = 4 // full-state snapshot (compaction)
)

// WALRecord is a single durable record in the Write-Ahead Log.
// Only the fields relevant to Type are populated.
type WALRecord struct {
	Type     WALRecordType
	Term     uint64     // WALState, WALSnapshot: current term
	VotedFor string     // WALState, WALSnapshot: voted-for candidate ID
	Entry    LogEntry   // WALLog: the appended entry
	Index    uint64     // WALTruncate: truncation start index (1-based)
	Entries  []LogEntry // WALSnapshot: all surviving log entries after compaction
}

// WAL is a binary append-only Write-Ahead Log that persists Raft state
// mutations (term changes, votes, log entries, truncations) to disk so
// the node can recover after a crash or restart.
//
// The WAL is written to a single file: <dataDir>/raft.wal. Each record is
// length-prefixed and checksummed (CRC32) for crash recovery. On startup,
// the file is replayed sequentially to reconstruct the in-memory state.
//
// The WAL is safe for concurrent use — all operations are guarded by a mutex.
type WAL struct {
	mu          sync.Mutex
	file        *os.File
	path        string
	dataDir     string
	recordCount int // incremented on each AppendRecord, reset by Compact
}

// magicWALHeader identifies the WAL file format.
const magicWALHeader = "GWAFWAL1"

// maxWALRecordSize bounds a single WAL record (32 MB). Records larger than
// this are rejected to prevent a corrupt/truncated length prefix from causing
// an oversized allocation during replay.
const maxWALRecordSize = 32 * 1024 * 1024

// OpenWAL opens (or creates) a WAL file in the given directory. If the file
// already exists, it is opened for append. The directory is created if it
// does not exist.
func OpenWAL(dataDir string) (*WAL, error) {
	if dataDir == "" {
		return nil, errors.New("wal: data directory is required")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("wal: create data dir %s: %w", dataDir, err)
	}
	path := filepath.Join(dataDir, "raft.wal")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 -- path is operator-configured data_dir joined with a fixed filename
	if err != nil {
		return nil, fmt.Errorf("wal: open %s: %w", path, err)
	}

	// If the file is empty, write the magic header.
	info, _ := f.Stat()
	if info != nil && info.Size() == 0 {
		if _, err := f.Write([]byte(magicWALHeader)); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("wal: write header: %w", err)
		}
	}

	wal := &WAL{file: f, path: path, dataDir: dataDir}
	wal.recordCount = wal.countRecords()
	return wal, nil
}

// countRecords reads the WAL file sequentially to count valid records.
// This is a lightweight scan (no state application) used by OpenWAL to
// initialize recordCount so ShouldCompact() works immediately after restart.
func (w *WAL) countRecords() int {
	if _, err := w.file.Seek(0, 0); err != nil {
		return 0
	}
	defer w.file.Seek(0, 2) // restore append position // #nosec G104 -- best-effort

	// Read and validate magic header.
	header := make([]byte, len(magicWALHeader))
	if _, err := io.ReadFull(w.file, header); err != nil {
		return 0
	}
	if string(header) != magicWALHeader {
		return 0
	}

	count := 0
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(w.file, lenBuf[:]); err != nil {
			break // EOF or partial record
		}
		recLen := binary.BigEndian.Uint32(lenBuf[:])
		if recLen == 0 || recLen > maxWALRecordSize {
			break // corrupt
		}
		// Skip payload + CRC.
		if _, err := w.file.Seek(int64(recLen)+4, 1); err != nil {
			break
		}
		count++
	}
	return count
}

// Close flushes and closes the WAL file.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// AppendRecord writes a single record to the WAL and fsyncs.
func (w *WAL) AppendRecord(rec WALRecord) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return errors.New("wal: file is closed")
	}
	data := encodeWALRecord(rec)
	if _, err := w.file.Write(data); err != nil {
		return fmt.Errorf("wal: write: %w", err)
	}
	if err := w.file.Sync(); err != nil {
		return fmt.Errorf("wal: sync: %w", err)
	}
	w.recordCount++
	return nil
}

// RecordCount returns the number of records written since the last compaction.
// Used by the compaction threshold check.
func (w *WAL) RecordCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.recordCount
}

// Replay reads the WAL from the beginning and applies all records to the
// given PersistentState. This is called during startup to reconstruct
// the in-memory state from disk.
//
// If the WAL is corrupt (e.g., a torn write at the end), Replay stops at
// the last valid record and truncates the file there. This implements
// crash recovery: partial writes at the tail are discarded.
func (w *WAL) Replay(ps *PersistentState) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return errors.New("wal: file is closed")
	}

	// Rewind to the beginning.
	if _, err := w.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("wal: seek: %w", err)
	}

	// Read and validate magic header.
	header := make([]byte, len(magicWALHeader))
	if _, err := io.ReadFull(w.file, header); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// Empty or brand-new file — nothing to replay.
			return nil
		}
		return fmt.Errorf("wal: read header: %w", err)
	}
	if string(header) != magicWALHeader {
		return fmt.Errorf("wal: invalid header: %q", string(header))
	}

	reader := w.file
	validOffset := int64(len(magicWALHeader))
	var lastValidTerm uint64
	var lastValidVotedFor string

	for {
		rec, err := decodeWALRecord(reader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break // end of file or torn tail
			}
			// Any other decode error means corruption — stop replay here.
			break
		}

		switch rec.Type {
		case WALState:
			lastValidTerm = rec.Term
			lastValidVotedFor = rec.VotedFor
		case WALLog:
			// Append directly to the in-memory log without triggering the
			// persist callback (we're replaying from the WAL itself).
			ps.log.appendNoPersist(rec.Entry)
		case WALTruncate:
			ps.log.truncateNoPersist(rec.Index)
		case WALSnapshot:
			// A snapshot resets all accumulated state. Replace the log
			// and term/vote with the snapshot contents, then continue
			// replaying any records that follow the snapshot.
			ps.log.resetNoPersist()
			for _, e := range rec.Entries {
				ps.log.appendNoPersist(e)
			}
			lastValidTerm = rec.Term
			lastValidVotedFor = rec.VotedFor
			// Snapshot replaces all prior records — count is managed by
		// countRecords() in OpenWAL; Replay() only applies state.
		default:
		}

		off, _ := reader.Seek(0, io.SeekCurrent)
		validOffset = off
	}

	// Apply the last known term/vote (without persisting — it's already on disk).
	if lastValidTerm > 0 || lastValidVotedFor != "" {
		ps.setTermNoPersist(lastValidTerm, lastValidVotedFor)
	}

	// Truncate the file at the last valid offset to discard any torn tail.
	endOff, _ := w.file.Seek(0, io.SeekEnd)
	if validOffset < endOff {
		_ = w.file.Truncate(validOffset)
	}

	// Seek to end for future appends.
	_, _ = w.file.Seek(0, io.SeekEnd)

	return nil
}

// ShouldCompact returns true when the WAL has accumulated enough records
// to warrant a compaction. Compaction replaces the append-only WAL with a
// single snapshot record, keeping the file small.
func (w *WAL) ShouldCompact(threshold int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return threshold > 0 && w.recordCount >= threshold
}

// Compact writes a snapshot of the current persistent state to a temporary
// file, then atomically renames it over the live WAL. After compaction, the
// WAL contains exactly one record (the snapshot) plus any state mutations.
//
// The snapshot captures: currentTerm, votedFor, and all log entries.
func (w *WAL) Compact(ps *PersistentState) error {
	// Gather snapshot data under the PersistentState lock.
	ps.mu.RLock()
	term := ps.currentTerm
	votedFor := ps.votedFor
	entries := ps.log.AllEntries()
	ps.mu.RUnlock()

	rec := WALRecord{
		Type:     WALSnapshot,
		Term:     term,
		VotedFor: votedFor,
		Entries:  entries,
	}
	data := encodeWALRecord(rec)

	// Write the snapshot to a temporary file in the same directory.
	tmpPath := w.path + ".compact.tmp"
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- w.path is operator-configured
	if err != nil {
		return fmt.Errorf("wal compact: create temp file: %w", err)
	}

	// Write magic header + snapshot record.
	if _, err := tmpFile.Write([]byte(magicWALHeader)); err != nil {
		tmpFile.Close() // #nosec G104 -- best-effort cleanup
		_ = os.Remove(tmpPath)
		return fmt.Errorf("wal compact: write magic: %w", err)
	}

	// encodeWALRecord returns the full framed record: [4 len][payload][4 crc].
	// Write it directly — no additional framing needed.
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close() // #nosec G104 -- best-effort cleanup
		_ = os.Remove(tmpPath)
		return fmt.Errorf("wal compact: write snapshot: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close() // #nosec G104 -- best-effort cleanup
		_ = os.Remove(tmpPath)
		return fmt.Errorf("wal compact: fsync temp: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("wal compact: close temp: %w", err)
	}

	// Atomically replace the live WAL.
	if err := os.Rename(tmpPath, w.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("wal compact: rename: %w", err)
	}

	// Open the new file for appending.
	newFile, err := os.OpenFile(w.path, os.O_RDWR|os.O_APPEND, 0o600) // #nosec G304 -- operator-configured path
	if err != nil {
		return fmt.Errorf("wal compact: reopen: %w", err)
	}

	w.mu.Lock()
	_ = w.file.Close() // #nosec G104 -- old file is replaced
	w.file = newFile
	w.recordCount = 1
	w.mu.Unlock()

	return nil
}

// --- Encoding ---

// Wire format for each record:
//
//	[4 bytes] record length (uint32, big-endian) — excludes itself + CRC
//	[N bytes] payload (type-specific, see below)
//	[4 bytes] CRC32 of payload (uint32, big-endian)
//
// Payload layout by type:
//
//	WALState:    [1 type][8 term][2 votedForLen][votedFor bytes]
//	WALLog:      [1 type][8 term][8 index][4 cmdLen][cmd bytes]
//	WALTruncate: [1 type][8 index]

func encodeWALRecord(rec WALRecord) []byte {
	var payload []byte
	payload = append(payload, byte(rec.Type))

	switch rec.Type {
	case WALState:
		payload = binary.BigEndian.AppendUint64(payload, rec.Term)
		vf := []byte(rec.VotedFor)
		payload = binary.BigEndian.AppendUint16(payload, uint16(len(vf))) // #nosec G115 -- node IDs are short strings, well under 65535
		payload = append(payload, vf...)

	case WALLog:
		payload = binary.BigEndian.AppendUint64(payload, rec.Entry.Term)
		payload = binary.BigEndian.AppendUint64(payload, rec.Entry.Index)
		cmd := rec.Entry.Command
		if cmd == nil {
			cmd = []byte{}
		}
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(cmd))) // #nosec G115 -- command length is bounded by LogEntry.Command slice size
		payload = append(payload, cmd...)

	case WALTruncate:
		payload = binary.BigEndian.AppendUint64(payload, rec.Index)

	case WALSnapshot:
		// Snapshot payload: [8 term][2 votedForLen][votedFor][4 entryCount][entries...]
		payload = binary.BigEndian.AppendUint64(payload, rec.Term)
		vf := []byte(rec.VotedFor)
		payload = binary.BigEndian.AppendUint16(payload, uint16(len(vf))) // #nosec G115 -- node IDs are short
		payload = append(payload, vf...)
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(rec.Entries))) // #nosec G115 -- entry count bounded by log length
		for _, e := range rec.Entries {
			payload = binary.BigEndian.AppendUint64(payload, e.Term)
			payload = binary.BigEndian.AppendUint64(payload, e.Index)
			cmd := e.Command
			if cmd == nil {
				cmd = []byte{}
			}
			payload = binary.BigEndian.AppendUint32(payload, uint32(len(cmd))) // #nosec G115 -- command bounded
			payload = append(payload, cmd...)
		}

	default:
		payload = append(payload, 0) // unknown type — will be skipped on replay
	}

	// Build the full record: length + payload + CRC.
	crc := crc32sum(payload)
	buf := make([]byte, 4+len(payload)+4)
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(payload))) // #nosec G115 -- payload length is bounded by record size limit
	copy(buf[4:], payload)
	binary.BigEndian.PutUint32(buf[4+len(payload):], crc)
	return buf
}

func decodeWALRecord(r io.Reader) (WALRecord, error) {
	// Read length prefix.
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return WALRecord{}, err
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf[:])
	if payloadLen == 0 || payloadLen > 16*1024*1024 { // sanity: max 16 MB
		return WALRecord{}, fmt.Errorf("wal: invalid payload length %d", payloadLen)
	}

	// Read payload.
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return WALRecord{}, err
	}

	// Read CRC.
	var crcBuf [4]byte
	if _, err := io.ReadFull(r, crcBuf[:]); err != nil {
		return WALRecord{}, err
	}
	wantCRC := binary.BigEndian.Uint32(crcBuf[:])

	// Verify CRC.
	gotCRC := crc32sum(payload)
	if gotCRC != wantCRC {
		return WALRecord{}, fmt.Errorf("wal: CRC mismatch (got %d, want %d)", gotCRC, wantCRC)
	}

	// Decode payload.
	return decodeWALPayload(payload)
}

func decodeWALPayload(payload []byte) (WALRecord, error) {
	if len(payload) < 1 {
		return WALRecord{}, errors.New("wal: empty payload")
	}
	rec := WALRecord{Type: WALRecordType(payload[0])}
	p := payload[1:]

	switch rec.Type {
	case WALState:
		if len(p) < 10 {
			return WALRecord{}, errors.New("wal: short state record")
		}
		rec.Term = binary.BigEndian.Uint64(p[0:8])
		vfLen := binary.BigEndian.Uint16(p[8:10])
		if len(p) < 10+int(vfLen) {
			return WALRecord{}, errors.New("wal: short votedFor")
		}
		rec.VotedFor = string(p[10 : 10+int(vfLen)])

	case WALLog:
		if len(p) < 20 {
			return WALRecord{}, errors.New("wal: short log record")
		}
		rec.Entry.Term = binary.BigEndian.Uint64(p[0:8])
		rec.Entry.Index = binary.BigEndian.Uint64(p[8:16])
		cmdLen := binary.BigEndian.Uint32(p[16:20])
		if len(p) < 20+int(cmdLen) {
			return WALRecord{}, errors.New("wal: short command")
		}
		rec.Entry.Command = make([]byte, cmdLen)
		copy(rec.Entry.Command, p[20:20+int(cmdLen)])

	case WALTruncate:
		if len(p) < 8 {
			return WALRecord{}, errors.New("wal: short truncate record")
		}
		rec.Index = binary.BigEndian.Uint64(p[0:8])

	case WALSnapshot:
		// Snapshot payload: term(8) | votedFor_len(2) | votedFor(N) | entry_count(4) | entries...
		if len(p) < 10 {
			return WALRecord{}, errors.New("wal: short snapshot record")
		}
		rec.Term = binary.BigEndian.Uint64(p[0:8])
		vfLen := binary.BigEndian.Uint16(p[8:10])
		if len(p) < 10+int(vfLen)+4 {
			return WALRecord{}, errors.New("wal: short snapshot votedFor")
		}
		rec.VotedFor = string(p[10 : 10+int(vfLen)])
		off := 10 + int(vfLen)
		entryCount := binary.BigEndian.Uint32(p[off : off+4])
		off += 4
		rec.Entries = make([]LogEntry, 0, entryCount)
		for i := uint32(0); i < entryCount; i++ {
			if len(p) < off+20 {
				return WALRecord{}, fmt.Errorf("wal: short snapshot entry %d", i)
			}
			var e LogEntry
			e.Term = binary.BigEndian.Uint64(p[off : off+8])
			e.Index = binary.BigEndian.Uint64(p[off+8 : off+16])
			cmdLen := binary.BigEndian.Uint32(p[off+16 : off+20])
			if len(p) < off+20+int(cmdLen) {
				return WALRecord{}, fmt.Errorf("wal: short snapshot entry %d command", i)
			}
			e.Command = make([]byte, cmdLen)
			copy(e.Command, p[off+20:off+20+int(cmdLen)])
			rec.Entries = append(rec.Entries, e)
			off += 20 + int(cmdLen)
		}

	default:
		return WALRecord{}, fmt.Errorf("wal: unknown record type %d", rec.Type)
	}

	return rec, nil
}

// --- Internal helpers for replay ---

// appendNoPersist appends an entry to the log WITHOUT triggering the persist
// callback. Used during WAL replay to avoid recursive writes.
func (l *LogStore) appendNoPersist(entry LogEntry) {
	l.mu.Lock()
	l.entries = append(l.entries, entry)
	l.mu.Unlock()
}

// truncateNoPersist truncates the log WITHOUT triggering the persist callback.
func (l *LogStore) truncateNoPersist(index uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index == 0 || index > uint64(len(l.entries)) {
		return
	}
	l.entries = l.entries[:index-1]
}

// setTermNoPersist sets term and votedFor WITHOUT writing to the WAL.
// Used during WAL replay.
func (ps *PersistentState) setTermNoPersist(term uint64, votedFor string) {
	ps.mu.Lock()
	ps.currentTerm = term
	ps.votedFor = votedFor
	ps.mu.Unlock()
}

// crc32sum returns the IEEE CRC32 checksum of data.
func crc32sum(data []byte) uint32 {
	return crc32.ChecksumIEEE(data)
}
