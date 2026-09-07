package raft

// Regression: startElection counted its self-vote only in memory and never
// called persist.SetVotedFor — so after IncCurrentTerm cleared votedFor, a
// candidate would GRANT its vote to a competing candidate in the same term
// (two votes in one term: itself + the competitor). Raft §5.2 requires
// voting for self AND persisting it on conversion to candidate; the
// single-vote-per-term guarantee is what limits each term to one leader.

import (
	"testing"
	"time"
)

func TestCandidateRecordsSelfVoteAndDeniesCompetingCandidate(t *testing.T) {
	cfg := DefaultConfig("node-a", "127.0.0.1:0")
	cfg.ElectionTimeoutMin = 150 * time.Millisecond
	cfg.ElectionTimeoutMax = 300 * time.Millisecond
	cfg.Secret = make([]byte, 32)
	cfg.DataDir = "" // in-memory persistent state

	cfg.Peers = []Peer{{ID: "node-b", Addr: "127.0.0.1:1"}} // unreachable; no vote traffic needed

	r, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer r.Stop()

	// Conversion to candidate: term bumps, self-vote recorded, candidacy held
	// (quorum needs 2 of {node-a, node-b}; only the self-vote exists here).
	r.startElection()

	if got := r.Role(); got != RoleCandidate {
		t.Fatalf("role = %v, want candidate", got)
	}
	if got := r.CurrentTerm(); got != 1 {
		t.Fatalf("term = %d, want 1", got)
	}

	// THE FIX'S CONTRACT: the self-vote must be persisted.
	if got := r.persist.VotedFor(); got != "node-a" {
		t.Fatalf("FAIL: self-vote not persisted after startElection (votedFor=%q)", got)
	}

	// A competing candidate asks for our vote in the SAME term. With the
	// self-vote persisted this must be denied; the pre-fix code saw
	// votedFor=="" and granted — two votes in one term.
	req := RequestVoteRequest{
		Term:         r.CurrentTerm(),
		CandidateID:  "node-b",
		LastLogIndex: 0,
		LastLogTerm:  0,
	}
	encoded, err := EncodeRequestVote(req)
	if err != nil {
		t.Fatalf("EncodeRequestVote: %v", err)
	}
	respData, err := r.handleRPC(RPCRequestVote, encoded)
	if err != nil {
		t.Fatalf("handleRPC: %v", err)
	}
	resp, err := DecodeRequestVoteResp(respData)
	if err != nil {
		t.Fatalf("DecodeRequestVoteResp: %v", err)
	}
	if resp.VoteGranted {
		t.Fatalf("FAIL: granted a second vote in term %d to competing candidate %q", r.CurrentTerm(), "node-b")
	}
}
