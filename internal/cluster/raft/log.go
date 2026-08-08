package raft

// NewLogStore creates a new empty in-memory log store.
func NewLogStore() *LogStore {
	return &LogStore{
		entries: make([]LogEntry, 0, 256),
	}
}

// Append adds a new entry to the log at the next sequential index.
// Returns the assigned index.
func (l *LogStore) Append(term uint64, command []byte) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	idx := uint64(len(l.entries) + 1)
	l.entries = append(l.entries, LogEntry{
		Term:    term,
		Index:   idx,
		Command: command,
	})
	return idx
}

// AppendEntry adds a pre-constructed LogEntry to the log.
func (l *LogStore) AppendEntry(entry LogEntry) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, entry)
	return entry.Index
}

// Get returns the entry at the given index (1-based), or ok=false if the
// index is out of range.
func (l *LogStore) Get(index uint64) (LogEntry, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if index == 0 || index > uint64(len(l.entries)) {
		return LogEntry{}, false
	}
	return l.entries[index-1], true
}

// LastIndex returns the index of the last entry, or 0 if the log is empty.
func (l *LogStore) LastIndex() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return uint64(len(l.entries))
}

// LastTerm returns the term of the last entry, or 0 if the log is empty.
func (l *LogStore) LastTerm() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if len(l.entries) == 0 {
		return 0
	}
	return l.entries[len(l.entries)-1].Term
}

// Term returns the term of the entry at the given index, or 0 if out of range.
func (l *LogStore) Term(index uint64) uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if index == 0 || index > uint64(len(l.entries)) {
		return 0
	}
	return l.entries[index-1].Term
}

// Len returns the number of entries in the log.
func (l *LogStore) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}

// EntriesFrom returns a copy of all entries starting at the given index
// (1-based). If index > LastIndex+1, returns nil.
func (l *LogStore) EntriesFrom(index uint64) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if index == 0 || index > uint64(len(l.entries))+1 {
		return nil
	}
	if index > uint64(len(l.entries)) {
		return []LogEntry{}
	}
	start := int(index - 1)
	result := make([]LogEntry, len(l.entries)-start)
	copy(result, l.entries[start:])
	return result
}

// TruncateFrom removes all entries from the given index onward (1-based).
// Used by the follower when it receives a conflicting entry from the leader.
func (l *LogStore) TruncateFrom(index uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index == 0 || index > uint64(len(l.entries)) {
		return false
	}
	l.entries = l.entries[:index-1]
	return true
}

// HasAt returns true if the log has an entry at prevIndex with the given
// prevTerm. This implements the Raft log consistency check (§5.3).
func (l *LogStore) HasAt(prevIndex, prevTerm uint64) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if prevIndex == 0 {
		return true // empty log prefix check always passes
	}
	if prevIndex > uint64(len(l.entries)) {
		return false
	}
	return l.entries[prevIndex-1].Term == prevTerm
}

// CheckConflict checks log consistency at (prevIndex, prevTerm) and returns
// conflict information for fast backtracking (Raft thesis §7.5).
// Returns ConflictInfo{0,0} when there is no conflict.
func (l *LogStore) CheckConflict(prevIndex, prevTerm uint64) ConflictInfo {
	l.mu.RLock()
	defer l.mu.RUnlock()

	// Case 1: follower log is too short — no entry at prevIndex.
	if prevIndex > uint64(len(l.entries)) {
		return ConflictInfo{ConflictTerm: 0, ConflictIndex: uint64(len(l.entries)) + 1}
	}

	// No conflict at index 0 (empty prefix).
	if prevIndex == 0 {
		return ConflictInfo{}
	}

	// Case 2: term mismatch at prevIndex.
	actualTerm := l.entries[prevIndex-1].Term
	if actualTerm != prevTerm {
		// Find the first entry of the conflicting term for fast backtracking.
		idx := prevIndex
		for idx > 1 && l.entries[idx-2].Term == actualTerm {
			idx--
		}
		return ConflictInfo{ConflictTerm: actualTerm, ConflictIndex: idx}
	}

	// Case 3: no conflict.
	return ConflictInfo{}
}

// Slice returns a copy of entries [start, end] (1-based, inclusive).
// Used for snapshotting.
func (l *LogStore) Slice(start, end uint64) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	n := uint64(len(l.entries))
	if start == 0 || start > end || start > n {
		return nil
	}
	if end > n {
		end = n // clamp to last available index
	}
	s := int(start - 1)
	e := int(end)
	result := make([]LogEntry, e-s)
	copy(result, l.entries[s:e])
	return result
}
