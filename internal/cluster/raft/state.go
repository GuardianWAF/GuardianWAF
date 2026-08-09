package raft

import (
	"sync"
)

// PersistentState holds the Raft state that must survive restarts.
// In a production implementation this is persisted via WAL; for now it is
// in-memory (the first commit gate) with a locking API so the persistence
// layer can be layered underneath without changing callers.
type PersistentState struct {
	mu sync.RWMutex

	currentTerm uint64
	votedFor    string // "" means no vote cast this term
	log         *LogStore
	wal         *WAL // nil when persistence is disabled
}

// NewPersistentState creates a new persistent state container with an empty
// log and term 0.
func NewPersistentState() *PersistentState {
	return &PersistentState{
		log: NewLogStore(),
	}
}

// CurrentTerm returns the current term.
func (ps *PersistentState) CurrentTerm() uint64 {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.currentTerm
}

// SetCurrentTerm sets the current term and resets votedFor.
func (ps *PersistentState) SetCurrentTerm(term uint64) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.currentTerm = term
	ps.votedFor = "" // starting a new term resets the vote
	if ps.wal != nil {
		_ = ps.wal.AppendRecord(WALRecord{Type: WALState, Term: term, VotedFor: ""})
	}
}

// IncCurrentTerm increments the term and returns the new value.
func (ps *PersistentState) IncCurrentTerm() uint64 {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.currentTerm++
	ps.votedFor = ""
	if ps.wal != nil {
		_ = ps.wal.AppendRecord(WALRecord{Type: WALState, Term: ps.currentTerm, VotedFor: ""})
	}
	return ps.currentTerm
}

// VotedFor returns the candidate ID this node voted for in the current term
// ("" = no vote yet).
func (ps *PersistentState) VotedFor() string {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.votedFor
}

// SetVotedFor records a vote for the given candidate in the current term.
func (ps *PersistentState) SetVotedFor(candidateID string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.votedFor = candidateID
	if ps.wal != nil {
		_ = ps.wal.AppendRecord(WALRecord{Type: WALState, Term: ps.currentTerm, VotedFor: candidateID})
	}
}

// Log returns the log store. Callers must hold no other lock; the LogStore
// has its own internal locking.
func (ps *PersistentState) Log() *LogStore {
	return ps.log
}

// SetWAL attaches a Write-Ahead Log for persistence. Once set, all mutations
// to currentTerm, votedFor, and the log store are durably appended before
// the in-memory state is updated. Pass nil to disable persistence.
func (ps *PersistentState) SetWAL(w *WAL) {
	ps.mu.Lock()
	ps.wal = w
	ps.mu.Unlock()

	// Wire log persistence: every append and truncate is durably written
	// to the WAL before the in-memory log is modified.
	if w != nil {
		ps.log.SetPersistence(
			func(e LogEntry) { _ = w.AppendRecord(WALRecord{Type: WALLog, Entry: e}) },
			func(index uint64) { _ = w.AppendRecord(WALRecord{Type: WALTruncate, Index: index}) },
		)
	}
}

// Snapshot triggers a WAL compaction: writes the full current state
// (term, votedFor, all log entries) as a single snapshot record, then
// atomically rotates the WAL file. After compaction, the WAL contains
// exactly one record instead of thousands of incremental appends.
//
// Returns nil if persistence is disabled (no WAL attached).
func (ps *PersistentState) Snapshot() error {
	ps.mu.RLock()
	wal := ps.wal
	ps.mu.RUnlock()
	if wal == nil {
		return nil
	}
	return wal.Compact(ps)
}

// WALRef returns the attached WAL (nil when persistence is disabled).
func (ps *PersistentState) WALRef() *WAL {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.wal
}

// --- Volatile state (leader) ---

// LeaderState holds the volatile state that exists only on the leader.
// It is reset whenever a node becomes leader.
type LeaderState struct {
	mu sync.RWMutex

	// nextIndex[i] = next log index to send to peer i (initialized to
	// lastIndex + 1 on election).
	nextIndex map[string]uint64

	// matchIndex[i] = highest log index known to be replicated on peer i
	// (initialized to 0 on election).
	matchIndex map[string]uint64
}

// NewLeaderState creates a new leader state for the given set of peer IDs and
// the last log index. All nextIndex values are initialized to lastIndex+1.
func NewLeaderState(peerIDs []string, lastIndex uint64) *LeaderState {
	ls := &LeaderState{
		nextIndex:  make(map[string]uint64, len(peerIDs)),
		matchIndex: make(map[string]uint64, len(peerIDs)),
	}
	for _, id := range peerIDs {
		ls.nextIndex[id] = lastIndex + 1
		ls.matchIndex[id] = 0
	}
	return ls
}

// NextIndex returns the next index to send to the given peer.
func (ls *LeaderState) NextIndex(peerID string) uint64 {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	return ls.nextIndex[peerID]
}

// SetNextIndex sets the next index for a peer.
func (ls *LeaderState) SetNextIndex(peerID string, idx uint64) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.nextIndex[peerID] = idx
}

// DecrNextIndex decrements and returns the next index for a peer.
// This implements the fast backtracking optimization from the Raft thesis.
func (ls *LeaderState) DecrNextIndex(peerID string, conflictIndex uint64) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if conflictIndex > 0 {
		ls.nextIndex[peerID] = conflictIndex
	} else {
		if ls.nextIndex[peerID] > 1 {
			ls.nextIndex[peerID]--
		}
	}
}

// MatchIndex returns the highest log index known to be replicated on the peer.
func (ls *LeaderState) MatchIndex(peerID string) uint64 {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	return ls.matchIndex[peerID]
}

// SetMatchIndex sets the match index for a peer.
func (ls *LeaderState) SetMatchIndex(peerID string, idx uint64) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if idx > ls.matchIndex[peerID] {
		ls.matchIndex[peerID] = idx
	}
}

// PeerIDs returns the sorted list of peer IDs tracked by this leader state.
func (ls *LeaderState) PeerIDs() []string {
	ls.mu.RLock()
	defer ls.mu.RUnlock()
	ids := make([]string, 0, len(ls.nextIndex))
	for id := range ls.nextIndex {
		ids = append(ids, id)
	}
	return ids
}

// --- Commit index helpers (volatile state on all nodes) ---

// CommitTracker helps the leader compute the new commit index using the
// matchIndex values (Raft §5.4.2).
func (ls *LeaderState) ComputeCommitIndex(myLastIndex uint64) uint64 {
	ls.mu.RLock()
	defer ls.mu.RUnlock()

	if len(ls.matchIndex) == 0 {
		return 0
	}

	// Collect all matchIndex values plus our own lastIndex.
	counts := make([]uint64, 0, len(ls.matchIndex)+1)
	counts = append(counts, myLastIndex)
	for _, idx := range ls.matchIndex {
		counts = append(counts, idx)
	}

	// Sort descending.
	sortDesc(counts)

	// The majority index is the (N/2)-th element in descending order.
	// For N entries, the element at position floor(N/2) is replicated on
	// at least floor(N/2)+1 nodes (including the leader).
	mid := len(counts) / 2
	candidate := counts[mid]

	if candidate == 0 {
		return 0
	}

	// §5.4.1: only commit entries from the current term.
	// The caller (Raft struct) checks this against the log.
	return candidate
}

func sortDesc(v []uint64) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] > v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}
