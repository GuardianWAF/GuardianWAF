package raft

import (
	"testing"
)

// Round 86 fresh-eyes proofs over the follower-side consistency machinery
// (handleAppendEntries) and the §5.4.1 vote-safety check (isLogUpToDate) —
// the unpinned paths a network-partition-and-heal cycle exercises, where a
// defect would corrupt a follower's log.

// hr builds and runs a RequestVote through the handler; returns the decoded
// response.
func hr(t *testing.T, r *Raft, term uint64, candidateID string, lastIdx, lastTerm uint64) RequestVoteResponse {
	t.Helper()
	data, err := EncodeRequestVote(RequestVoteRequest{
		Term:         term,
		CandidateID:  candidateID,
		LastLogIndex: lastIdx,
		LastLogTerm:  lastTerm,
	})
	if err != nil {
		t.Fatalf("EncodeRequestVote: %v", err)
	}
	respData, err := r.handleRequestVote(data)
	if err != nil {
		t.Fatalf("handleRequestVote: %v", err)
	}
	resp, err := DecodeRequestVoteResp(respData)
	if err != nil {
		t.Fatalf("DecodeRequestVoteResp: %v", err)
	}
	return resp
}

// ae builds and runs an AppendEntries through the handler; returns the
// decoded response.
func ae(t *testing.T, r *Raft, term, prevIdx, prevTerm uint64, entries []LogEntry, leaderCommit uint64) AppendEntriesResponse {
	t.Helper()
	data, err := EncodeAppendEntries(AppendEntriesRequest{
		Term:         term,
		LeaderID:     "leader-x",
		PrevLogIndex: prevIdx,
		PrevLogTerm:  prevTerm,
		Entries:      entries,
		LeaderCommit: leaderCommit,
	})
	if err != nil {
		t.Fatalf("EncodeAppendEntries: %v", err)
	}
	respData, err := r.handleAppendEntries(data)
	if err != nil {
		t.Fatalf("handleAppendEntries: %v", err)
	}
	resp, err := DecodeAppendEntriesResp(respData)
	if err != nil {
		t.Fatalf("DecodeAppendEntriesResp: %v", err)
	}
	return resp
}

// §5.4.1 vote-safety matrix: a candidate whose last log term is OLDER must
// be denied even with votedFor empty; equal term + shorter log denied; equal
// term + equal-or-longer log granted.
func TestRound86RequestVoteLogUpToDateMatrix(t *testing.T) {
	cfg := DefaultConfig("node-a", "127.0.0.1:0")
	cfg.Secret = make([]byte, 32)
	r, err := New(cfg, ApplyFunc(func(LogEntry) {}))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()

	// Our log: terms [1, 1, 2] (indices 1..3). Seed directly under r.mu via
	// the same Append API the node uses.
	r.mu.Lock()
	r.persist.Log().Append(1, []byte("e1"))
	r.persist.Log().Append(1, []byte("e2"))
	r.persist.Log().Append(2, []byte("e3"))
	r.mu.Unlock()

	// Candidate with an older last term (1 < 2) but a LONGER log: denied.
	if resp := hr(t, r, 2, "node-b", 5, 1); resp.VoteGranted {
		t.Fatal("FAIL: candidate with an older last log term was granted (§5.4.1 requires the newer term)")
	}
	// Same last term (2), shorter index (2 < 3): denied.
	if resp := hr(t, r, 2, "node-b", 2, 2); resp.VoteGranted {
		t.Fatal("FAIL: candidate with a shorter log at equal last term was granted (§5.4.1)")
	}
	// Same last term (2), equal index (3): granted.
	if resp := hr(t, r, 2, "node-b", 3, 2); !resp.VoteGranted {
		t.Fatal("FAIL: candidate with an equal log was denied (§5.4.1 requires grant)")
	}
	// Higher last term (3) with a SHORTER index: granted (term dominates).
	r2 := DefaultConfig("node-a", "127.0.0.1:0")
	r2.Secret = make([]byte, 32)
	r2b, err := New(r2, ApplyFunc(func(LogEntry) {}))
	if err != nil {
		t.Fatal(err)
	}
	defer r2b.Stop()
	r2b.mu.Lock()
	r2b.persist.Log().Append(1, []byte("e1"))
	r2b.persist.Log().Append(1, []byte("e2"))
	r2b.persist.Log().Append(2, []byte("e3"))
	r2b.mu.Unlock()
	if resp := hr(t, r2b, 2, "node-b", 99, 3); !resp.VoteGranted {
		t.Fatal("FAIL: candidate with a higher last log term was denied (§5.4.1: term dominates)")
	}
}

// §5.3 prevLogIndex beyond the follower's log: Success=false and
// ConflictIndex = lastIndex+1 (the leader must backtrack).
func TestRound86AppendEntriesPrevLogBeyondLog(t *testing.T) {
	cfg := DefaultConfig("node-a", "127.0.0.1:0")
	cfg.Secret = make([]byte, 32)
	r, err := New(cfg, ApplyFunc(func(LogEntry) {}))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	r.mu.Lock()
	r.persist.Log().Append(1, []byte("e1"))
	r.persist.Log().Append(1, []byte("e2"))
	r.mu.Unlock()

	resp := ae(t, r, 1, 9, 1, nil, 0)
	if resp.Success {
		t.Fatal("FAIL: AppendEntries with prevLogIndex beyond the follower's log was accepted")
	}
	if resp.ConflictIndex != 3 {
		t.Fatalf("FAIL: ConflictIndex = %d, want lastIndex+1 = 3", resp.ConflictIndex)
	}
	if got := r.Log().Len(); got != 2 {
		t.Fatalf("FAIL: rejected AppendEntries mutated the log: len = %d, want 2", got)
	}
}

// §5.3 prevLogTerm mismatch: the backward walk must report the FIRST index
// of the conflicting term, so the leader backtracks to it in one step.
func TestRound86AppendEntriesPrevLogTermConflictWalk(t *testing.T) {
	cfg := DefaultConfig("node-a", "127.0.0.1:0")
	cfg.Secret = make([]byte, 32)
	r, err := New(cfg, ApplyFunc(func(LogEntry) {}))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	r.mu.Lock()
	// Terms [2, 2, 3, 3]: indices 1..4. A leader at prevLogIndex=4 with
	// prevLogTerm=9 mismatches; the conflicting term is 3, whose first index
	// is 3 — the walk must stop there.
	r.persist.Log().Append(2, []byte("e1"))
	r.persist.Log().Append(2, []byte("e2"))
	r.persist.Log().Append(3, []byte("e3"))
	r.persist.Log().Append(3, []byte("e4"))
	r.mu.Unlock()

	resp := ae(t, r, 4, 4, 9, nil, 0)
	if resp.Success {
		t.Fatal("FAIL: prevLogTerm mismatch accepted")
	}
	if resp.ConflictIndex != 3 {
		t.Fatalf("FAIL: ConflictIndex = %d, want 3 (first index of the conflicting term)", resp.ConflictIndex)
	}
}

// A conflicting entry truncates the follower's suffix and replaces it; the
// committed prefix survives.
func TestRound86AppendEntriesConflictTruncatesAndReplaces(t *testing.T) {
	cfg := DefaultConfig("node-a", "127.0.0.1:0")
	cfg.Secret = make([]byte, 32)
	var applied []LogEntry
	r, err := New(cfg, ApplyFunc(func(e LogEntry) { applied = append(applied, e) }))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	r.mu.Lock()
	r.persist.Log().Append(1, []byte("e1"))
	r.persist.Log().Append(1, []byte("e2"))
	r.persist.Log().Append(1, []byte("old-e3"))
	r.persist.Log().Append(1, []byte("old-e4"))
	r.mu.Unlock()

	// Leader (term 2) confirms 1..2 match, then sends conflicting entries at
	// indices 3 and 4.
	entries := []LogEntry{
		{Term: 2, Index: 3, Command: []byte("new-e3")},
		{Term: 2, Index: 4, Command: []byte("new-e4")},
	}
	resp := ae(t, r, 2, 2, 1, entries, 4)
	if !resp.Success {
		t.Fatal("FAIL: conflict-repair AppendEntries rejected")
	}
	if got := r.Log().Len(); got != 4 {
		t.Fatalf("FAIL: log has %d entries, want 4 after conflict repair", got)
	}
	e3, _ := r.Log().Get(3)
	e4, _ := r.Log().Get(4)
	if string(e3.Command) != "new-e3" || string(e4.Command) != "new-e4" {
		t.Fatalf("FAIL: conflicting entries not replaced: %q, %q", e3.Command, e4.Command)
	}
	_ = applied
}

// Duplicate delivery of the SAME AppendEntries must be idempotent: no
// duplicate entries, Success=true on both deliveries.
func TestRound86AppendEntriesDuplicateDeliveryIdempotent(t *testing.T) {
	cfg := DefaultConfig("node-a", "127.0.0.1:0")
	cfg.Secret = make([]byte, 32)
	r, err := New(cfg, ApplyFunc(func(LogEntry) {}))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()

	entries := []LogEntry{
		{Term: 1, Index: 1, Command: []byte("e1")},
		{Term: 1, Index: 2, Command: []byte("e2")},
	}
	first := ae(t, r, 1, 0, 0, entries, 2)
	if !first.Success {
		t.Fatal("FAIL: first delivery rejected")
	}
	second := ae(t, r, 1, 0, 0, entries, 2)
	if !second.Success {
		t.Fatal("FAIL: duplicate delivery rejected — retry after a lost response would never converge")
	}
	if got := r.Log().Len(); got != 2 {
		t.Fatalf("FAIL: duplicate delivery produced %d entries, want 2 (idempotence)", got)
	}
}

// commitIndex = min(LeaderCommit, lastNew): the follower's commit index must
// never exceed what its own log can satisfy.
func TestRound86AppendEntriesCommitIndexMinSemantics(t *testing.T) {
	cfg := DefaultConfig("node-a", "127.0.0.1:0")
	cfg.Secret = make([]byte, 32)
	r, err := New(cfg, ApplyFunc(func(LogEntry) {}))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()

	// Seed entries 1..2 (term 1) so the heartbeat's prevLogIndex=2 /
	// prevLogTerm=1 satisfies the §5.3 consistency check.
	r.mu.Lock()
	r.persist.Log().Append(1, []byte("e1"))
	r.persist.Log().Append(1, []byte("e2"))
	r.mu.Unlock()

	// Heartbeat (no entries) at prevLogIndex 2: lastNew = 2; LeaderCommit 9
	// must clamp to lastNew.
	resp := ae(t, r, 1, 2, 1, nil, 9)
	if !resp.Success {
		t.Fatal("FAIL: heartbeat rejected")
	}
	if got := r.CommitIndex(); got != 2 {
		t.Fatalf("FAIL: commitIndex = %d, want min(LeaderCommit 9, lastNew 2) = 2", got)
	}

	// Now entries extend the log to 4; LeaderCommit 4 and lastNew 4 → 4.
	entries := []LogEntry{
		{Term: 1, Index: 3, Command: []byte("e3")},
		{Term: 1, Index: 4, Command: []byte("e4")},
	}
	resp = ae(t, r, 1, 2, 1, entries, 4)
	if !resp.Success {
		t.Fatal("FAIL: entry delivery rejected")
	}
	if got := r.CommitIndex(); got != 4 {
		t.Fatalf("FAIL: commitIndex = %d, want 4", got)
	}
}

// §5.1: a stale-term AppendEntries is rejected with Success=false and the
// CURRENT term echoed — and the log is untouched.
func TestRound86AppendEntriesStaleTermRejected(t *testing.T) {
	cfg := DefaultConfig("node-a", "127.0.0.1:0")
	cfg.Secret = make([]byte, 32)
	r, err := New(cfg, ApplyFunc(func(LogEntry) {}))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	r.mu.Lock()
	for i := 0; i < 5; i++ {
		r.persist.IncCurrentTerm()
	}
	r.mu.Unlock()

	entries := []LogEntry{{Term: 1, Index: 1, Command: []byte("e1")}}
	resp := ae(t, r, 1, 0, 0, entries, 1)
	if resp.Success {
		t.Fatal("FAIL: stale-term AppendEntries accepted (§5.1 requires rejection)")
	}
	if resp.Term != 5 {
		t.Fatalf("FAIL: response term = %d, want current term 5", resp.Term)
	}
	if got := r.Log().Len(); got != 0 {
		t.Fatalf("FAIL: rejected stale-term AppendEntries mutated the log: len = %d", got)
	}
}
