package raft

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"sync"
	"time"
)

// Config holds the configuration for a Raft node.
type Config struct {
	NodeID             string
	BindAddr           string // "127.0.0.1:0" for ephemeral
	Peers              []Peer // initial peer list
	ElectionTimeoutMin time.Duration
	ElectionTimeoutMax time.Duration
	HeartbeatInterval  time.Duration

	// DataDir is the directory for persistent Raft state (WAL + snapshots).
	// When empty (default), all state is in-memory and lost on restart.
	// When set, the WAL is created/opened in DataDir/raft.wal and replayed
	// on startup to restore the committed log and term/vote state.
	DataDir string

	// SnapshotThreshold controls log compaction. When the state machine
	// implements Snapshotter, a state-machine snapshot is taken once this
	// many entries have been applied since the last one; compacted entries
	// are discarded from memory and the WAL, and lagging followers receive
	// the snapshot via InstallSnapshot. Otherwise it is the number of WAL
	// records after which the WAL is rewritten as a single record (the log
	// itself is kept). Set to 0 to disable compaction. Default: 0.
	SnapshotThreshold int

	// Secret authenticates every RPC frame between peers. It is required:
	// the Raft log replicates IP bans and WAF rule mutations, so a node that
	// accepts unauthenticated AppendEntries hands an attacker control of the
	// fleet's enforcement state. Must be at least MinSecretLen bytes.
	Secret []byte
}

// Peer is a cluster node known to Raft.
type Peer struct {
	ID   string
	Addr string
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig(nodeID, bindAddr string) Config {
	return Config{
		NodeID:             nodeID,
		BindAddr:           bindAddr,
		ElectionTimeoutMin: 150 * time.Millisecond,
		ElectionTimeoutMax: 300 * time.Millisecond,
		HeartbeatInterval:  50 * time.Millisecond,
	}
}

// Bounds on a single AppendEntries batch.
const (
	maxAppendEntries = 512
	maxAppendBytes   = 4 << 20
)

// normalizeTimings replaces unset or inconsistent election/heartbeat timings
// with safe values. A zero election timeout made electionLoop start elections
// back to back, each spawning RequestVote goroutines with a zero transport
// timeout: an unbounded goroutine pile-up that consumed gigabytes in seconds.
func normalizeTimings(cfg Config) Config {
	def := DefaultConfig("", "")
	if cfg.ElectionTimeoutMin <= 0 {
		cfg.ElectionTimeoutMin = def.ElectionTimeoutMin
	}
	if cfg.ElectionTimeoutMax <= cfg.ElectionTimeoutMin {
		cfg.ElectionTimeoutMax = 2 * cfg.ElectionTimeoutMin
	}
	if cfg.HeartbeatInterval <= 0 || cfg.HeartbeatInterval >= cfg.ElectionTimeoutMin {
		cfg.HeartbeatInterval = cfg.ElectionTimeoutMin / 3
	}
	return cfg
}

// StateMachine applies committed log entries. Implementations must be
// idempotent and safe for concurrent access.
type StateMachine interface {
	Apply(entry LogEntry)
}

// ApplyFunc is a StateMachine backed by a function.
type ApplyFunc func(LogEntry)

func (f ApplyFunc) Apply(entry LogEntry) { f(entry) }

// Raft is a single Raft node.
type Raft struct {
	mu     sync.Mutex
	config Config

	transport *TCPTransport

	// Persistent state (survives restarts).
	persist *PersistentState

	// Volatile state on all nodes.
	commitIndex uint64
	lastApplied uint64

	// Volatile state on leader only. nil when not leader.
	leaderState *LeaderState

	// Current role.
	role Role

	// roleChangeCh is signalled when the role changes (e.g. becomeLeader),
	// so the election loop can break out of its wait immediately instead of
	// waiting for the full election timeout.
	roleChangeCh chan struct{}

	// Current leader ID ("" if unknown).
	leaderID string

	// Votes received in current election.
	votesReceived map[string]bool

	// State machine for applying committed entries. snapshotter is sm when
	// it supports log compaction, else nil.
	sm          StateMachine
	snapshotter Snapshotter

	// applyMu serializes state-machine access: the apply loop holds it per
	// entry and InstallSnapshot holds it while restoring. Lock order is
	// applyMu → mu → PersistentState.mu.
	applyMu sync.Mutex

	// snapshot is the latest state-machine snapshot (guarded by mu), sent to
	// followers whose next entry was compacted away.
	snapshot stateSnapshot
	// nextSnapshotAt suppresses retrying a failed snapshot on every apply.
	nextSnapshotAt uint64

	// Lifecycle.
	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once

	// electionResetTime is when the election timer was last reset.
	electionResetTime time.Time
}

// New creates a new Raft node with the given config.
func New(cfg Config, sm StateMachine) (*Raft, error) {
	cfg = normalizeTimings(cfg)
	tr, err := NewTCPTransport(cfg.BindAddr, cfg.NodeID, cfg.ElectionTimeoutMax*2, cfg.Secret)
	if err != nil {
		return nil, fmt.Errorf("raft: create transport: %w", err)
	}
	cfg.Peers = append([]Peer(nil), cfg.Peers...)

	snapshotter, _ := sm.(Snapshotter)
	r := &Raft{
		config:      cfg,
		transport:   tr,
		persist:     NewPersistentState(),
		sm:          sm,
		snapshotter: snapshotter,
		role:        RoleFollower,
		// Initialize the election-timer baseline so the FIRST election also
		// waits the randomized [Min, Max] window. A zero electionResetTime
		// made waitDuration <= 0 on every fresh node — all nodes started a
		// simultaneous candidacy the instant they joined, bypassing the
		// randomized tie-breaker entirely.
		electionResetTime: time.Now(),
		stopCh:            make(chan struct{}),
		roleChangeCh:      make(chan struct{}, 1),
		doneCh:            make(chan struct{}),
		votesReceived:     make(map[string]bool),
		leaderID:          "",
		commitIndex:       0,
		lastApplied:       0,
	}

	// If DataDir is set, create/open the WAL and replay persisted state.
	if cfg.DataDir != "" {
		wal, err := OpenWAL(cfg.DataDir)
		if err != nil {
			_ = tr.Close()
			return nil, fmt.Errorf("raft: open WAL: %w", err)
		}
		r.persist.SetWAL(wal)
		if err := wal.Replay(r.persist); err != nil {
			_ = wal.Close()
			_ = tr.Close()
			return nil, fmt.Errorf("raft: replay WAL: %w", err)
		}
		if err := r.restoreSnapshot(cfg.DataDir); err != nil {
			_ = wal.Close()
			_ = tr.Close()
			return nil, err
		}
	}

	tr.SetHandler(r.handleRPC)

	return r, nil
}

// Start begins the Raft loops: election timer, apply loop, and heartbeat (if leader).
func (r *Raft) Start() error {
	if err := r.transport.Start(); err != nil {
		return fmt.Errorf("raft: start transport: %w", err)
	}

	go r.electionLoop()
	go r.applyLoop()

	return nil
}

// Stop shuts down the Raft node. Safe to call multiple times.
func (r *Raft) Stop() {
	r.stopOnce.Do(func() {
		close(r.stopCh)
		_ = r.transport.Close()
		if wal := r.persist.WALRef(); wal != nil {
			_ = wal.Close()
		}
		close(r.doneCh)
	})
}

// Transport returns the underlying TCP transport (for tests and peer registration).
func (r *Raft) Transport() *TCPTransport {
	return r.transport
}

// UpdatePeers replaces the peer list. Safe to call at runtime.
func (r *Raft) UpdatePeers(peers []Peer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.config.Peers = append([]Peer(nil), peers...)
}

// Peers returns the current peer list.
func (r *Raft) Peers() []Peer {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Peer(nil), r.config.Peers...)
}

// Log returns the log store (for testing/inspection).
func (r *Raft) Log() *LogStore {
	return r.persist.Log()
}

// PersistentState returns the persistent state container (for testing/inspection).
func (r *Raft) PersistentState() *PersistentState {
	return r.persist
}

// Role returns the current role of this node.
func (r *Raft) Role() Role {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.role
}

// LeaderID returns the current leader's ID ("" if unknown).
func (r *Raft) LeaderID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.leaderID
}

// CommitIndex returns the current commit index.
func (r *Raft) CommitIndex() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.commitIndex
}

// LastApplied returns the last applied log index.
func (r *Raft) LastApplied() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastApplied
}

// CurrentTerm returns the current term.
func (r *Raft) CurrentTerm() uint64 {
	return r.persist.CurrentTerm()
}

// Term returns the current term (short alias for CurrentTerm).
func (r *Raft) Term() uint64 {
	return r.persist.CurrentTerm()
}

// ID returns this node's ID.
func (r *Raft) ID() string {
	return r.config.NodeID
}

// Propose submits a command to the Raft log. If this node is not the leader,
// returns ErrNotLeader.
func (r *Raft) Propose(data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.role != RoleLeader {
		return ErrNotLeader
	}

	r.persist.Log().Append(r.persist.CurrentTerm(), data)

	return nil
}

// ErrNotLeader is returned when a write operation is attempted on a non-leader.
var ErrNotLeader = errors.New("raft: not leader")

// --- Election ---

func (r *Raft) electionLoop() {
	for {
		select {
		case <-r.stopCh:
			return
		default:
		}

		r.mu.Lock()
		timeout := r.randomElectionTimeout()
		role := r.role
		resetTime := r.electionResetTime
		r.mu.Unlock()

		if role != RoleLeader {
			waitDuration := timeout - time.Since(resetTime)
			if waitDuration <= 0 {
				r.startElection()
				continue
			}

			select {
			case <-r.stopCh:
				return
			case <-r.roleChangeCh:
				// Role changed (e.g., became leader) — re-loop immediately.
				continue
			case <-time.After(waitDuration):
				// Check if we were reset (heartbeat received).
				r.mu.Lock()
				newReset := r.electionResetTime
				r.mu.Unlock()
				if newReset.Equal(resetTime) {
					r.startElection()
				}
			}
		} else {
			// Leader: sleep for heartbeat interval and send heartbeats.
			select {
			case <-r.stopCh:
				return
			case <-time.After(r.config.HeartbeatInterval):
				r.broadcastHeartbeat()
				// A leader with zero peers receives no AppendEntries
				// responses, so the response path can never advance the
				// commit index — re-evaluate it here on every heartbeat
				// (same locking contract as the response handler).
				r.mu.Lock()
				r.maybeAdvanceCommitIndex()
				r.mu.Unlock()
			}
		}
	}
}

func (r *Raft) randomElectionTimeout() time.Duration {
	min := r.config.ElectionTimeoutMin
	max := r.config.ElectionTimeoutMax
	if min >= max {
		return max
	}
	spread := max - min
	return min + time.Duration(rand.Int64N(int64(spread)))
}

func (r *Raft) resetElectionTimer() {
	r.electionResetTime = time.Now()
}

func (r *Raft) startElection() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.role = RoleCandidate
	r.persist.IncCurrentTerm()
	// §5.2: a candidate votes for itself and must PERSIST that vote before
	// answering vote requests — IncCurrentTerm clears votedFor, and without
	// recording the self-vote here the candidate would grant its vote to a
	// competing candidate in the same term (two votes in one term).
	r.persist.SetVotedFor(r.config.NodeID)
	r.leaderID = ""
	r.votesReceived = map[string]bool{r.config.NodeID: true}
	r.resetElectionTimer()

	term := r.persist.CurrentTerm()
	lastLogIndex := r.persist.Log().LastIndex()
	lastLogTerm := uint64(0)
	if lastLogIndex > 0 {
		entry, _ := r.persist.Log().Get(lastLogIndex)
		lastLogTerm = entry.Term
	}

	req := RequestVoteRequest{
		Term:         term,
		CandidateID:  r.config.NodeID,
		LastLogIndex: lastLogIndex,
		LastLogTerm:  lastLogTerm,
	}

	// Send RequestVote to all peers in parallel.
	for _, peer := range r.config.Peers {
		if peer.ID == r.config.NodeID {
			continue
		}
		go r.requestVote(peer, req)
	}

	// Single-node cluster: we already have quorum (just ourselves).
	if r.hasQuorum() {
		r.becomeLeader()
	}
}

func (r *Raft) requestVote(peer Peer, req RequestVoteRequest) {
	data, err := EncodeRequestVote(req)
	if err != nil {
		return
	}

	respType, respData, err := r.transport.SendRPC(peer.Addr, RPCRequestVoteRequest, data)
	if err != nil {
		_ = err // peer unreachable; skip
		return
	}
	if respType != RPCRequestVoteResponse {
		return
	}

	resp, err := DecodeRequestVoteResp(respData)
	if err != nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// If the response term is higher, step down.
	if resp.Term > r.persist.CurrentTerm() {
		r.becomeFollower(resp.Term)
		return
	}

	// Ignore stale responses.
	if r.role != RoleCandidate || r.persist.CurrentTerm() != req.Term {
		return
	}

	if resp.VoteGranted {
		r.votesReceived[peer.ID] = true
		if r.hasQuorum() {
			r.becomeLeader()
		}
	}
}

func (r *Raft) hasQuorum() bool {
	total := len(r.config.Peers) + 1 // peers + self
	majority := total/2 + 1
	return len(r.votesReceived) >= majority
}

func (r *Raft) becomeLeader() {
	r.role = RoleLeader
	r.leaderID = r.config.NodeID
	r.resetElectionTimer() // prevent electionLoop from re-triggering election

	peerIDs := make([]string, 0, len(r.config.Peers))
	for _, p := range r.config.Peers {
		peerIDs = append(peerIDs, p.ID)
	}
	r.leaderState = NewLeaderState(peerIDs, r.persist.Log().LastIndex())

	// Signal the election loop to break out of the non-leader wait
	// immediately so heartbeats start without delay.
	select {
	case r.roleChangeCh <- struct{}{}:
	default:
	}

	// Immediately send heartbeats to establish authority.
	for _, peer := range r.config.Peers {
		if peer.ID == r.config.NodeID {
			continue
		}
		go r.sendAppendEntries(peer)
	}
}

func (r *Raft) becomeFollower(term uint64) {
	r.role = RoleFollower
	r.persist.SetCurrentTerm(term)
	r.leaderState = nil
	r.leaderID = ""

	// Signal the election loop to re-check role.
	select {
	case r.roleChangeCh <- struct{}{}:
	default:
	}
}

// --- Heartbeat / AppendEntries ---

func (r *Raft) broadcastHeartbeat() {
	r.mu.Lock()
	if r.role != RoleLeader {
		r.mu.Unlock()
		return
	}
	peers := r.config.Peers
	r.mu.Unlock()

	for _, peer := range peers {
		if peer.ID == r.config.NodeID {
			continue
		}
		go r.sendAppendEntries(peer)
	}
}

func (r *Raft) sendAppendEntries(peer Peer) {
	r.mu.Lock()
	if r.role != RoleLeader {
		r.mu.Unlock()
		return
	}

	term := r.persist.CurrentTerm()
	nextIdx := r.leaderState.NextIndex(peer.ID)

	// The follower needs entries that were compacted into the snapshot.
	if nextIdx <= r.persist.Log().BaseIndex() {
		snap := r.snapshot
		r.mu.Unlock()
		r.sendInstallSnapshot(peer, term, snap)
		return
	}

	var prevLogIndex uint64
	var prevLogTerm uint64
	if nextIdx > 1 {
		prevLogIndex = nextIdx - 1
		prevLogTerm = r.persist.Log().Term(prevLogIndex)
	}

	// Bounded batches: a lagging follower is caught up over several RPCs
	// instead of one frame that could exceed maxFrameSize and fail forever.
	entries := r.persist.Log().EntriesFromLimit(nextIdx, maxAppendEntries, maxAppendBytes)
	if entries == nil {
		r.mu.Unlock()
		return
	}

	req := AppendEntriesRequest{
		Term:         term,
		LeaderID:     r.config.NodeID,
		PrevLogIndex: prevLogIndex,
		PrevLogTerm:  prevLogTerm,
		Entries:      entries,
		LeaderCommit: r.commitIndex,
	}
	r.mu.Unlock()

	data, err := EncodeAppendEntries(req)
	if err != nil {
		return
	}

	respType, respData, err := r.transport.SendRPC(peer.Addr, RPCAppendEntriesRequest, data)
	if err != nil {
		return
	}
	if respType != RPCAppendEntriesResponse {
		return
	}

	resp, err := DecodeAppendEntriesResp(respData)
	if err != nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if resp.Term > r.persist.CurrentTerm() {
		r.becomeFollower(resp.Term)
		return
	}

	if r.role != RoleLeader || r.persist.CurrentTerm() != term {
		return
	}

	if resp.Success {
		newMatch := req.PrevLogIndex + uint64(len(entries))
		r.leaderState.SetMatchIndex(peer.ID, newMatch)
		r.leaderState.SetNextIndex(peer.ID, newMatch+1)

		// Check if we can advance commitIndex.
		r.maybeAdvanceCommitIndex()
	} else {
		// Decrement nextIndex for this peer (fast backtracking).
		r.leaderState.DecrNextIndex(peer.ID, resp.ConflictIndex)
	}
}

func (r *Raft) maybeAdvanceCommitIndex() {
	if r.leaderState == nil {
		return
	}

	newCommit := r.leaderState.ComputeCommitIndex(r.persist.Log().LastIndex())
	if newCommit > r.commitIndex {
		// §5.4.1: only commit entries from the current term.
		entry, ok := r.persist.Log().Get(newCommit)
		if ok && entry.Term == r.persist.CurrentTerm() {
			r.commitIndex = newCommit
		}
	}
}

// sendInstallSnapshot sends the latest snapshot to a follower whose next
// entry has been compacted (Raft §7).
func (r *Raft) sendInstallSnapshot(peer Peer, term uint64, snap stateSnapshot) {
	if snap.Index == 0 {
		return
	}
	data, err := EncodeInstallSnapshot(InstallSnapshotRequest{
		Term:              term,
		LeaderID:          r.config.NodeID,
		LastIncludedIndex: snap.Index,
		LastIncludedTerm:  snap.Term,
		Data:              snap.Data,
	})
	if err != nil {
		return
	}
	respType, respData, err := r.transport.SendRPC(peer.Addr, RPCInstallSnapshot, data)
	if err != nil || respType != RPCInstallSnapshotResp {
		return
	}
	resp, err := DecodeInstallSnapshotResp(respData)
	if err != nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if resp.Term > r.persist.CurrentTerm() {
		r.becomeFollower(resp.Term)
		return
	}
	if r.role != RoleLeader || r.persist.CurrentTerm() != term {
		return
	}
	if snap.Index > r.leaderState.MatchIndex(peer.ID) {
		r.leaderState.SetMatchIndex(peer.ID, snap.Index)
	}
	r.leaderState.SetNextIndex(peer.ID, snap.Index+1)
	r.maybeAdvanceCommitIndex()
}

// --- Apply Loop ---

func (r *Raft) applyLoop() {
	for {
		select {
		case <-r.stopCh:
			return
		default:
		}

		if !r.applyNext() {
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// applyNext applies the next committed entry, if any, and compacts the log
// when due. It reports whether an entry was applied.
func (r *Raft) applyNext() bool {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()

	r.mu.Lock()
	if r.lastApplied >= r.commitIndex {
		r.mu.Unlock()
		return false
	}
	idx := r.lastApplied + 1
	r.mu.Unlock()

	entry, ok := r.persist.Log().Get(idx)
	if !ok {
		return false
	}
	if r.sm != nil {
		r.sm.Apply(entry)
	}
	r.mu.Lock()
	r.lastApplied = idx
	r.mu.Unlock()

	// Compaction is triggered after each apply so only committed+applied
	// entries are compacted.
	threshold := r.config.SnapshotThreshold
	if threshold <= 0 {
		return true
	}
	if r.snapshotter != nil {
		if idx-r.persist.Log().BaseIndex() >= uint64(threshold) && idx >= r.nextSnapshotAt { // #nosec G115 -- threshold > 0
			if err := r.takeSnapshot(idx); err != nil {
				// Non-fatal: the log keeps growing until the next attempt.
				fmt.Fprintf(os.Stderr, "guardianwaf: raft snapshot at %d failed: %v\n", idx, err)
				r.nextSnapshotAt = idx + uint64(threshold) // #nosec G115 -- threshold > 0
			}
		}
		return true
	}
	if wal := r.persist.WALRef(); wal != nil && wal.ShouldCompact(threshold) {
		if err := r.persist.Snapshot(); err != nil {
			// Compaction failures are non-fatal — the WAL grows
			// until the next successful compaction.
			fmt.Fprintf(os.Stderr, "guardianwaf: wal compaction failed: %v\n", err)
		}
	}
	return true
}

// takeSnapshot snapshots the state machine at idx (the last applied entry)
// and discards the log up to it. The snapshot file is written before the WAL
// is rewritten, so a crash in between leaves a WAL whose extra prefix is
// reconciled away by restoreSnapshot. Caller holds applyMu.
func (r *Raft) takeSnapshot(idx uint64) error {
	data, err := r.snapshotter.Snapshot()
	if err != nil {
		return err
	}
	if len(data) > maxSnapshotSize {
		return errSnapshotTooLarge
	}
	snap := stateSnapshot{Index: idx, Term: r.persist.Log().Term(idx), Data: data}
	if r.config.DataDir != "" {
		if err := writeSnapshotFile(r.config.DataDir, snap); err != nil {
			return err
		}
	}
	r.mu.Lock()
	r.snapshot = snap
	r.mu.Unlock()
	if err := r.persist.Log().CompactTo(idx); err != nil {
		return err
	}
	return r.persist.Snapshot()
}

// restoreSnapshot loads the persisted state-machine snapshot at startup and
// reconciles the replayed log with it.
func (r *Raft) restoreSnapshot(dir string) error {
	snap, ok, err := readSnapshotFile(dir)
	if err != nil {
		return fmt.Errorf("raft: load snapshot: %w", err)
	}
	if !ok {
		return nil
	}
	if r.snapshotter == nil {
		return errors.New("raft: a state-machine snapshot exists but the state machine cannot restore it")
	}
	if err := r.snapshotter.Restore(snap.Data); err != nil {
		return fmt.Errorf("raft: restore snapshot: %w", err)
	}
	log := r.persist.Log()
	if log.BaseIndex() < snap.Index {
		// The snapshot file is newer than the WAL's last compaction (a crash
		// between the two writes): fold the covered prefix away.
		if log.Term(snap.Index) == snap.Term {
			_ = log.CompactTo(snap.Index)
		} else {
			log.ResetToSnapshot(snap.Index, snap.Term)
		}
		if err := r.persist.Snapshot(); err != nil {
			return fmt.Errorf("raft: compact WAL to snapshot: %w", err)
		}
	}
	r.snapshot = snap
	r.commitIndex = snap.Index
	r.lastApplied = snap.Index
	return nil
}

// --- RPC Handlers ---

func (r *Raft) handleRPC(msgType RPCType, payload []byte) ([]byte, error) {
	switch msgType {
	case RPCRequestVoteRequest:
		return r.handleRequestVote(payload)
	case RPCAppendEntriesRequest:
		return r.handleAppendEntries(payload)
	case RPCInstallSnapshot:
		return r.handleInstallSnapshot(payload)
	default:
		return nil, errors.New("unknown RPC type")
	}
}

func (r *Raft) handleRequestVote(data []byte) ([]byte, error) {
	req, err := DecodeRequestVote(data)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	resp := RequestVoteResponse{
		Term:        r.persist.CurrentTerm(),
		VoteGranted: false,
	}

	// If the request term is higher, update our term and become follower.
	if req.Term > r.persist.CurrentTerm() {
		r.becomeFollower(req.Term)
		resp.Term = req.Term
	}

	// §5.2: a stale-term vote must never be granted — granting would also
	// persist the stale candidate into the current term (SetVotedFor below),
	// burning this node's vote for the legitimate candidate of that term.
	if req.Term < r.persist.CurrentTerm() {
		resp.Term = r.persist.CurrentTerm()
		return EncodeRequestVoteResp(resp)
	}

	// §5.4.1: grant vote if:
	// 1. We haven't voted this term (or already voted for this candidate).
	// 2. The candidate's log is at least as up-to-date as ours.
	if r.persist.VotedFor() == "" || r.persist.VotedFor() == req.CandidateID {
		if r.isLogUpToDate(req.LastLogIndex, req.LastLogTerm) {
			r.persist.SetVotedFor(req.CandidateID)
			resp.VoteGranted = true
			r.resetElectionTimer()
		}
	}

	return EncodeRequestVoteResp(resp)
}

func (r *Raft) isLogUpToDate(candidateLastIndex, candidateLastTerm uint64) bool {
	myLastIndex := r.persist.Log().LastIndex()
	myLastTerm := uint64(0)
	if myLastIndex > 0 {
		entry, _ := r.persist.Log().Get(myLastIndex)
		myLastTerm = entry.Term
	}

	if candidateLastTerm != myLastTerm {
		return candidateLastTerm > myLastTerm
	}
	return candidateLastIndex >= myLastIndex
}

func (r *Raft) handleAppendEntries(data []byte) ([]byte, error) {
	req, err := DecodeAppendEntries(data)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	resp := AppendEntriesResponse{
		Term:    r.persist.CurrentTerm(),
		Success: false,
	}

	// If the request term is higher, update our term.
	if req.Term > r.persist.CurrentTerm() {
		r.becomeFollower(req.Term)
		resp.Term = req.Term
	}

	// Reply false if term < currentTerm (§5.1).
	if req.Term < r.persist.CurrentTerm() {
		return EncodeAppendEntriesResp(resp)
	}

	// Accept the leader.
	r.role = RoleFollower
	r.leaderID = req.LeaderID
	r.resetElectionTimer()

	// Reply false if log doesn't contain an entry at prevLogIndex whose
	// term matches prevLogTerm (§5.3).
	// Indices at or below the snapshot base are committed, so they match.
	base := r.persist.Log().BaseIndex()
	if req.PrevLogIndex > base {
		entry, ok := r.persist.Log().Get(req.PrevLogIndex)
		if !ok {
			resp.ConflictIndex = r.persist.Log().LastIndex() + 1
			return EncodeAppendEntriesResp(resp)
		}
		if entry.Term != req.PrevLogTerm {
			// Fast backtracking: return the first index of the conflicting term.
			conflictTerm := entry.Term
			conflictIndex := req.PrevLogIndex
			for i := req.PrevLogIndex; i > 0; i-- {
				e, ok := r.persist.Log().Get(i)
				if !ok || e.Term != conflictTerm {
					break
				}
				conflictIndex = i
			}
			resp.ConflictIndex = conflictIndex
			return EncodeAppendEntriesResp(resp)
		}
	}

	// Append any new entries not already in the log.
	for i, entry := range req.Entries {
		entryIdx := req.PrevLogIndex + uint64(i) + 1
		if entryIdx <= base {
			continue // already folded into our snapshot
		}

		existing, ok := r.persist.Log().Get(entryIdx)
		if ok {
			if existing.Term != entry.Term {
				// Conflict: truncate from here.
				r.persist.Log().TruncateFrom(entryIdx)
				r.persist.Log().AppendEntry(entry)
			}
			// Otherwise, entry already matches — skip.
		} else {
			r.persist.Log().AppendEntry(entry)
		}
	}

	resp.Success = true

	// Advance commitIndex (§5.3).
	if req.LeaderCommit > r.commitIndex {
		lastNew := req.PrevLogIndex + uint64(len(req.Entries))
		if req.LeaderCommit < lastNew {
			r.commitIndex = req.LeaderCommit
		} else {
			r.commitIndex = lastNew
		}
	}

	return EncodeAppendEntriesResp(resp)
}

// handleInstallSnapshot replaces the follower's state with the leader's
// snapshot (Raft §7).
func (r *Raft) handleInstallSnapshot(data []byte) ([]byte, error) {
	req, err := DecodeInstallSnapshot(data)
	if err != nil {
		return nil, err
	}

	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()

	if req.Term > r.persist.CurrentTerm() {
		r.becomeFollower(req.Term)
	}
	resp := InstallSnapshotResponse{Term: r.persist.CurrentTerm()}
	if req.Term < r.persist.CurrentTerm() {
		return EncodeInstallSnapshotResp(resp)
	}
	r.role = RoleFollower
	r.leaderID = req.LeaderID
	r.resetElectionTimer()

	// Already covered by our own state.
	if req.LastIncludedIndex <= r.lastApplied {
		return EncodeInstallSnapshotResp(resp)
	}
	if r.snapshotter == nil {
		return nil, errors.New("raft: state machine does not support snapshots")
	}
	if len(req.Data) > maxSnapshotSize {
		return nil, errSnapshotTooLarge
	}

	snap := stateSnapshot{Index: req.LastIncludedIndex, Term: req.LastIncludedTerm, Data: req.Data}
	// Persist before mutating state: on failure the follower is unchanged
	// and the leader retries.
	if r.config.DataDir != "" {
		if err := writeSnapshotFile(r.config.DataDir, snap); err != nil {
			return nil, err
		}
	}
	if err := r.snapshotter.Restore(snap.Data); err != nil {
		return nil, fmt.Errorf("raft: restore snapshot: %w", err)
	}
	r.persist.Log().ResetToSnapshot(snap.Index, snap.Term)
	r.snapshot = snap
	r.lastApplied = snap.Index
	if r.commitIndex < snap.Index {
		r.commitIndex = snap.Index
	}
	if err := r.persist.Snapshot(); err != nil {
		fmt.Fprintf(os.Stderr, "guardianwaf: wal compaction after snapshot install failed: %v\n", err)
	}
	return EncodeInstallSnapshotResp(resp)
}

// Members returns the list of known peers. This is the integration point
// for the gossip membership layer — a future adapter will call this to
// provide dynamic peer discovery.
func (r *Raft) Members() []Peer {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]Peer, len(r.config.Peers))
	copy(result, r.config.Peers)
	return result
}

// AddPeer dynamically adds a peer. This is a config-only change — it does
// not go through Raft membership consensus (deferred to a future ADR).
func (r *Raft) AddPeer(peer Peer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.config.Peers {
		if p.ID == peer.ID {
			return
		}
	}
	r.config.Peers = append(r.config.Peers, peer)
}

// StateJSON returns the current state as a JSON snapshot (for debugging).
func (r *Raft) StateJSON() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	state := struct {
		Role        string `json:"role"`
		Term        uint64 `json:"term"`
		LeaderID    string `json:"leader_id"`
		CommitIndex uint64 `json:"commit_index"`
		LastApplied uint64 `json:"last_applied"`
		LogLength   int    `json:"log_length"`
	}{
		Role:        r.role.String(),
		Term:        r.persist.CurrentTerm(),
		LeaderID:    r.leaderID,
		CommitIndex: r.commitIndex,
		LastApplied: r.lastApplied,
		LogLength:   r.persist.Log().Len(),
	}

	return json.Marshal(state)
}
