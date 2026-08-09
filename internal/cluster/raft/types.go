// Package raft implements a minimal Raft consensus protocol for GuardianWAF
// cluster coordination. It provides leader election and log replication over
// TCP, using the gossip membership layer for peer discovery.
//
// This is NOT a full Raft implementation. It covers:
//   - Leader election (randomized timeout, RequestVote RPC)
//   - Log replication (AppendEntries RPC)
//   - In-memory log store (no persistence in this version)
//
// Out of scope (deferred):
//   - Log compaction / snapshots
//   - Dynamic membership changes
//   - Joint consensus
//   - Pre-vote optimization
//   - Read-only lease reads
//
// The implementation follows the Raft paper (Ongaro & Ousterhout, 2014).
package raft

import "sync"

// Role represents the current role of a Raft node.
type Role int

const (
	RoleFollower Role = iota
	RoleCandidate
	RoleLeader
)

// String returns the human-readable name of the role.
func (r Role) String() string {
	switch r {
	case RoleFollower:
		return "follower"
	case RoleCandidate:
		return "candidate"
	case RoleLeader:
		return "leader"
	default:
		return "unknown"
	}
}

// LogEntry is a single entry in the Raft log.
type LogEntry struct {
	Term    uint64 // The term in which this entry was created
	Index   uint64 // The 1-based log index
	Command []byte // The serialized command (opaque to Raft; interpreted by the state machine)
}

// ConflictInfo describes a log conflict found during AppendEntries consistency
// check. The leader uses ConflictIndex/ConflictTerm to optimize backtracking
// (Raft thesis §7.5 fast backtracking).
type ConflictInfo struct {
	ConflictTerm  uint64 // term of the conflicting entry (0 if follower log is too short)
	ConflictIndex uint64 // index to retry at
}

// LogStore is an in-memory Raft log. Index 0 is reserved (logs are 1-based).
type LogStore struct {
	mu      sync.RWMutex
	entries []LogEntry

	// persistEntry, if set, is called after every successful append/truncate.
	// It allows the WAL to durably record the change before the caller proceeds.
	persistEntry func(entry LogEntry)
	persistTrunc func(fromIndex uint64)
}

// SetPersistence wires durable persistence callbacks for the log store.
// persistEntry is called after each Append/AppendEntry; persistTrunc is
// called after each TruncateFrom. Pass nil for both to disable.
func (l *LogStore) SetPersistence(persistEntry func(LogEntry), persistTrunc func(uint64)) {
	l.mu.Lock()
	l.persistEntry = persistEntry
	l.persistTrunc = persistTrunc
	l.mu.Unlock()
}

// PeerInfo describes a cluster peer discovered via gossip.
type PeerInfo struct {
	ID   string
	Addr string // TCP address for Raft RPCs
}

// NodeStatus is a point-in-time snapshot of a Raft node's state for
// dashboard/reporting purposes.
type NodeStatus struct {
	ID          string
	Role        Role
	Term        uint64
	LeaderID    string
	CommitIndex uint64
	LastApplied uint64
	LogLength   int
	VotedFor    string
	Peers       []PeerInfo
}

// RPCType identifies the kind of Raft RPC.
type RPCType uint8

const (
	RPCError               RPCType = 0
	RPCRequestVote         RPCType = 1
	RPCRequestVoteResp     RPCType = 2
	RPCAppendEntries       RPCType = 3
	RPCAppendEntriesResp   RPCType = 4
	RPCInstallSnapshot     RPCType = 5 // reserved for future snapshot support
	RPCInstallSnapshotResp RPCType = 6 // reserved for future snapshot support
	RPCPropose             RPCType = 7 // internal: leader-forwarded proposal

	// Aliases used by the transport for request/response framing.
	RPCRequestVoteRequest    = RPCRequestVote
	RPCRequestVoteResponse   = RPCRequestVoteResp
	RPCAppendEntriesRequest  = RPCAppendEntries
	RPCAppendEntriesResponse = RPCAppendEntriesResp
)

// --- RequestVote RPC ---

// RequestVoteRequest is sent by candidates to solicit votes.
type RequestVoteRequest struct {
	Term         uint64 // Candidate's term
	CandidateID  string // Candidate requesting vote
	LastLogIndex uint64 // Index of candidate's last log entry
	LastLogTerm  uint64 // Term of candidate's last log entry
}

// RequestVoteResponse is the reply to a RequestVoteRequest.
type RequestVoteResponse struct {
	Term        uint64 // Responder's current term (for candidate to update itself)
	VoteGranted bool   // True means candidate received vote
}

// --- AppendEntries RPC ---

// AppendEntriesRequest is sent by the leader to replicate log entries and
// also serves as a heartbeat when Entries is empty.
type AppendEntriesRequest struct {
	Term         uint64     // Leader's term
	LeaderID     string     // So followers can redirect clients
	PrevLogIndex uint64     // Index of log entry immediately preceding new ones
	PrevLogTerm  uint64     // Term of PrevLogIndex entry
	Entries      []LogEntry // Log entries to store (empty for heartbeat)
	LeaderCommit uint64     // Leader's commitIndex
}

// AppendEntriesResponse is the reply to an AppendEntriesRequest.
type AppendEntriesResponse struct {
	Term    uint64 // Responder's current term
	Success bool   // True if follower contained entry matching PrevLogIndex and PrevLogTerm
	// ConflictIndex and ConflictTerm are used for fast log backtracking
	// (optimization from §5.3 of the Raft thesis).
	ConflictIndex uint64
	ConflictTerm  uint64
}

// --- Propose (internal leader-forwarded write) ---

// ProposeRequest is sent by a follower to the leader to propose a new
// command for the replicated log.
type ProposeRequest struct {
	Command []byte
}

// ProposeResponse indicates whether the proposal was accepted and committed.
type ProposeResponse struct {
	Term      uint64
	LeaderID  string
	Committed bool
	Index     uint64 // Log index assigned by the leader (0 if rejected)
}
