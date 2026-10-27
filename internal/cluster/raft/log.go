package raft

import (
	"bytes"
	"fmt"
)

// resetNoPersist clears all entries and the snapshot base without invoking
// persist callbacks. Used during WAL replay when a snapshot record resets the
// log.
func (l *LogStore) resetNoPersist() {
	l.mu.Lock()
	l.entries = l.entries[:0]
	l.baseIndex, l.baseTerm = 0, 0
	l.mu.Unlock()
}

// NewLogStore creates a new empty in-memory log store.
func NewLogStore() *LogStore {
	return &LogStore{
		entries: make([]LogEntry, 0, 256),
	}
}

// lastIndexLocked returns the index of the last entry (or the snapshot base
// when no entries follow it). Caller holds l.mu.
func (l *LogStore) lastIndexLocked() uint64 {
	return l.baseIndex + lenToUint64(len(l.entries))
}

// posLocked maps a log index to its slice position. ok is false for indices
// at or below the snapshot base and beyond the last entry. Caller holds l.mu.
func (l *LogStore) posLocked(index uint64) (int, bool) {
	if index <= l.baseIndex || index > l.lastIndexLocked() {
		return 0, false
	}
	return uint64ToInt(index - l.baseIndex - 1), true
}

// Append adds a new entry to the log at the next sequential index.
// Returns the assigned index.
func (l *LogStore) Append(term uint64, command []byte) uint64 {
	l.mu.Lock()
	idx := l.lastIndexLocked() + 1
	entry := LogEntry{
		Term:    term,
		Index:   idx,
		Command: bytes.Clone(command),
	}
	l.entries = append(l.entries, entry)
	persist := l.persistEntry
	l.mu.Unlock()
	if persist != nil {
		persist(cloneLogEntry(entry))
	}
	return idx
}

// AppendEntry appends a pre-formed entry (used by followers replicating from
// the leader). The entry's Index must be LastIndex()+1.
func (l *LogStore) AppendEntry(entry LogEntry) uint64 {
	entry = cloneLogEntry(entry)
	l.mu.Lock()
	l.entries = append(l.entries, entry)
	persist := l.persistEntry
	l.mu.Unlock()
	if persist != nil {
		persist(cloneLogEntry(entry))
	}
	return entry.Index
}

// Get returns the entry at the given 1-based index. Entries compacted into a
// snapshot are not available.
func (l *LogStore) Get(index uint64) (LogEntry, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	pos, ok := l.posLocked(index)
	if !ok {
		return LogEntry{}, false
	}
	return cloneLogEntry(l.entries[pos]), true
}

// LastIndex returns the index of the last entry, or the snapshot base (0 for
// an empty, never-compacted log).
func (l *LogStore) LastIndex() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.lastIndexLocked()
}

// LastTerm returns the term of the last entry, or of the snapshot base.
func (l *LogStore) LastTerm() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if len(l.entries) == 0 {
		return l.baseTerm
	}
	return l.entries[len(l.entries)-1].Term
}

// Term returns the term of the entry at index, the snapshot base term for
// index == BaseIndex(), and 0 when unknown.
func (l *LogStore) Term(index uint64) uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if index != 0 && index == l.baseIndex {
		return l.baseTerm
	}
	pos, ok := l.posLocked(index)
	if !ok {
		return 0
	}
	return l.entries[pos].Term
}

// BaseIndex returns the index of the last entry folded into a snapshot.
func (l *LogStore) BaseIndex() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.baseIndex
}

// BaseTerm returns the term of the last entry folded into a snapshot.
func (l *LogStore) BaseTerm() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.baseTerm
}

// Len returns the number of retained (uncompacted) entries.
func (l *LogStore) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

// EntriesFrom returns all entries from the given index (inclusive) to the end.
// It returns nil when index is at or below the snapshot base (the caller must
// send a snapshot instead) or past LastIndex()+1, and an empty slice for
// index == LastIndex()+1.
func (l *LogStore) EntriesFrom(index uint64) []LogEntry {
	return l.EntriesFromLimit(index, 0, 0)
}

// EntriesFromLimit is EntriesFrom bounded to at most maxEntries entries and
// roughly maxBytes of command payload (0 = unlimited). At least one entry is
// returned when any are available, so a single oversized entry still makes
// progress.
func (l *LogStore) EntriesFromLimit(index uint64, maxEntries, maxBytes int) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if index == 0 || index <= l.baseIndex || index > l.lastIndexLocked()+1 {
		return nil
	}
	if index > l.lastIndexLocked() {
		return []LogEntry{}
	}
	start := uint64ToInt(index - l.baseIndex - 1)
	tail := l.entries[start:]
	n := len(tail)
	if maxEntries > 0 {
		n = min(n, maxEntries)
	}
	if maxBytes > 0 {
		size := 0
		for i := range n {
			size += len(tail[i].Command)
			if size > maxBytes && i > 0 {
				n = i
				break
			}
		}
	}
	result := make([]LogEntry, n)
	for i, entry := range tail[:n] {
		result[i] = cloneLogEntry(entry)
	}
	return result
}

// TruncateFrom removes all entries from the given index onward (1-based).
// Entries at or below the snapshot base are committed and cannot be removed.
// Returns true if any entries were removed.
func (l *LogStore) TruncateFrom(index uint64) bool {
	l.mu.Lock()
	pos, ok := l.posLocked(index)
	if !ok {
		l.mu.Unlock()
		return false
	}
	l.entries = l.entries[:pos]
	l.mu.Unlock()

	// Persist outside l.mu, mirroring Append: wal.Compact holds w.mu across
	// its gather and AllEntries takes l.mu, so persisting under l.mu could
	// deadlock against a concurrent compaction.
	if l.persistTrunc != nil {
		l.persistTrunc(index)
	}
	return true
}

// HasAt reports whether the log contains an entry at prevIndex with prevTerm.
// Indices at or below the snapshot base are committed and therefore match.
func (l *LogStore) HasAt(prevIndex, prevTerm uint64) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if prevIndex == 0 {
		return true // empty log prefix check always passes
	}
	if prevIndex < l.baseIndex {
		return true
	}
	if prevIndex == l.baseIndex {
		return prevTerm == l.baseTerm
	}
	pos, ok := l.posLocked(prevIndex)
	if !ok {
		return false
	}
	return l.entries[pos].Term == prevTerm
}

// CheckConflict checks log consistency at (prevIndex, prevTerm) and returns
// conflict information for fast backtracking (Raft thesis §7.5).
// Returns ConflictInfo{0,0} when there is no conflict; indices at or below the
// snapshot base never conflict.
func (l *LogStore) CheckConflict(prevIndex, prevTerm uint64) ConflictInfo {
	l.mu.RLock()
	defer l.mu.RUnlock()

	last := l.lastIndexLocked()
	if prevIndex > last {
		return ConflictInfo{ConflictTerm: 0, ConflictIndex: last + 1}
	}
	if prevIndex == 0 || prevIndex <= l.baseIndex {
		return ConflictInfo{}
	}

	pos, _ := l.posLocked(prevIndex)
	actualTerm := l.entries[pos].Term
	if actualTerm != prevTerm {
		idx := prevIndex
		for idx > l.baseIndex+1 && l.entries[uint64ToInt(idx-l.baseIndex-2)].Term == actualTerm {
			idx--
		}
		return ConflictInfo{ConflictTerm: actualTerm, ConflictIndex: idx}
	}

	return ConflictInfo{}
}

// AllEntries returns a copy of all retained log entries (those after the
// snapshot base). Used for WAL compaction.
func (l *LogStore) AllEntries() []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]LogEntry, len(l.entries))
	for i, entry := range l.entries {
		result[i] = cloneLogEntry(entry)
	}
	return result
}

// ResetNoPersist clears all entries and the snapshot base without persisting.
// Used during WAL replay when a snapshot record resets all prior state.
func (l *LogStore) ResetNoPersist() {
	l.mu.Lock()
	l.entries = nil
	l.baseIndex, l.baseTerm = 0, 0
	l.mu.Unlock()
}

// CompactTo folds entries up to and including index into the snapshot base,
// discarding them from memory. index must be a retained entry or the current
// base. The WAL is not rewritten here; see PersistentState.Snapshot.
func (l *LogStore) CompactTo(index uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index == l.baseIndex {
		return nil
	}
	pos, ok := l.posLocked(index)
	if !ok {
		return fmt.Errorf("raft log: cannot compact to %d (base %d, last %d)", index, l.baseIndex, l.lastIndexLocked())
	}
	l.baseTerm = l.entries[pos].Term
	l.baseIndex = index
	remaining := make([]LogEntry, len(l.entries)-pos-1, max(len(l.entries)-pos-1, 256))
	copy(remaining, l.entries[pos+1:])
	l.entries = remaining
	return nil
}

// ResetToSnapshot installs a snapshot ending at (index, term). Per Raft §7,
// if the log already holds that entry with the same term the suffix after it
// is retained; otherwise the whole log is discarded. Returns true when the
// suffix was retained. Persistence is the caller's responsibility.
func (l *LogStore) ResetToSnapshot(index, term uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if pos, ok := l.posLocked(index); ok && l.entries[pos].Term == term {
		remaining := make([]LogEntry, len(l.entries)-pos-1, max(len(l.entries)-pos-1, 256))
		copy(remaining, l.entries[pos+1:])
		l.entries = remaining
		l.baseIndex, l.baseTerm = index, term
		return true
	}
	l.entries = make([]LogEntry, 0, 256)
	l.baseIndex, l.baseTerm = index, term
	return false
}

// Slice returns entries in [start, end] (inclusive, 1-based), clamped to the
// retained range.
func (l *LogStore) Slice(start, end uint64) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	last := l.lastIndexLocked()
	if start <= l.baseIndex || start > end || start > last {
		return nil
	}
	if end > last {
		end = last // clamp to last available index
	}
	s := uint64ToInt(start - l.baseIndex - 1)
	e := uint64ToInt(end - l.baseIndex)
	result := make([]LogEntry, e-s)
	for i, entry := range l.entries[s:e] {
		result[i] = cloneLogEntry(entry)
	}
	return result
}

func cloneLogEntry(entry LogEntry) LogEntry {
	entry.Command = bytes.Clone(entry.Command)
	return entry
}
