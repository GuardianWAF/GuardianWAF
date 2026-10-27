package raft

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Snapshotter is implemented by state machines that support log compaction.
// Snapshot must capture exactly the effect of every entry applied so far;
// Restore replaces the state machine's contents with a prior Snapshot. Raft
// never calls Apply concurrently with either method.
//
// A state machine without Snapshotter keeps its full log (the WAL is still
// compacted into a single record, but log history is never discarded).
type Snapshotter interface {
	Snapshot() ([]byte, error)
	Restore(data []byte) error
}

// stateSnapshot is a state-machine snapshot covering the log up to Index.
type stateSnapshot struct {
	Index uint64
	Term  uint64
	Data  []byte
}

const (
	snapshotFileName = "raft.snapshot"
	magicSnapshot    = "GWAFSNP1"
	// maxSnapshotSize bounds the state-machine snapshot. It must fit a single
	// InstallSnapshot RPC frame (maxFrameSize, with JSON base64 overhead).
	maxSnapshotSize = 11 << 20
)

// errSnapshotTooLarge is returned when a state machine's snapshot exceeds
// maxSnapshotSize; the log is then left uncompacted.
var errSnapshotTooLarge = errors.New("raft: state machine snapshot exceeds the size limit")

// writeSnapshotFile durably replaces <dir>/raft.snapshot. Layout:
// [8 magic][8 index][8 term][4 dataLen][data][4 crc32(index|term|dataLen|data)].
func writeSnapshotFile(dir string, snap stateSnapshot) error {
	if len(snap.Data) > maxSnapshotSize {
		return errSnapshotTooLarge
	}
	body := make([]byte, 0, 20+len(snap.Data))
	body = binary.BigEndian.AppendUint64(body, snap.Index)
	body = binary.BigEndian.AppendUint64(body, snap.Term)
	body = binary.BigEndian.AppendUint32(body, uint32(len(snap.Data))) // #nosec G115 -- bounded by maxSnapshotSize
	body = append(body, snap.Data...)

	buf := make([]byte, 0, len(magicSnapshot)+len(body)+4)
	buf = append(buf, magicSnapshot...)
	buf = append(buf, body...)
	buf = binary.BigEndian.AppendUint32(buf, crc32sum(body))

	path := filepath.Join(dir, snapshotFileName)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- dir is operator-configured
	if err != nil {
		return fmt.Errorf("raft snapshot: create: %w", err)
	}
	if _, err = f.Write(buf); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("raft snapshot: write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("raft snapshot: rename: %w", err)
	}
	// Make the rename durable before the WAL is compacted against it.
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- dir is operator-configured
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// readSnapshotFile loads <dir>/raft.snapshot. ok is false when no snapshot
// exists. A present but corrupt snapshot is an error: the WAL may already have
// been compacted against it, so silently ignoring it would lose state.
func readSnapshotFile(dir string) (snap stateSnapshot, ok bool, err error) {
	f, err := os.Open(filepath.Join(dir, snapshotFileName)) // #nosec G304 -- dir is operator-configured
	if errors.Is(err, os.ErrNotExist) {
		return stateSnapshot{}, false, nil
	}
	if err != nil {
		return stateSnapshot{}, false, fmt.Errorf("raft snapshot: open: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, int64(len(magicSnapshot)+20+maxSnapshotSize+4+1)))
	if err != nil {
		return stateSnapshot{}, false, fmt.Errorf("raft snapshot: read: %w", err)
	}
	if len(data) < len(magicSnapshot)+24 || string(data[:len(magicSnapshot)]) != magicSnapshot {
		return stateSnapshot{}, false, errors.New("raft snapshot: invalid header")
	}
	body := data[len(magicSnapshot) : len(data)-4]
	if crc32sum(body) != binary.BigEndian.Uint32(data[len(data)-4:]) {
		return stateSnapshot{}, false, errors.New("raft snapshot: checksum mismatch")
	}
	n := binary.BigEndian.Uint32(body[16:20])
	if uint64(n) != uint64(len(body)-20) { // #nosec G115 -- len(body) >= 20 checked above
		return stateSnapshot{}, false, errors.New("raft snapshot: length mismatch")
	}
	return stateSnapshot{
		Index: binary.BigEndian.Uint64(body[0:8]),
		Term:  binary.BigEndian.Uint64(body[8:16]),
		Data:  append([]byte(nil), body[20:]...),
	}, true, nil
}
