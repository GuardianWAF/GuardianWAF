package raft

import (
	"bytes"
	"testing"
)

// §5.2: "If term < currentTerm, respond false." handleRequestVote lacks that
// guard (handleAppendEntries has the symmetric one), so a stale-term
// RequestVote is granted and SetVotedFor persists the stale candidate into
// the CURRENT term — burning this node's vote for the legitimate candidate of
// that term and delaying/stalling elections.
func TestHandleRequestVote_RejectsStaleTerm(t *testing.T) {
	cfg := DefaultConfig("node-a", "127.0.0.1:0")
	cfg.Secret = bytes.Repeat([]byte("k"), MinSecretLen)
	r, err := New(cfg, ApplyFunc(func(LogEntry) {}))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()

	// Drive the node to term 5 with NO vote recorded yet — IncCurrentTerm
	// clears votedFor, so this is the exact state of a node that just stepped
	// up in term without voting.
	r.mu.Lock()
	for i := 0; i < 5; i++ {
		r.persist.IncCurrentTerm()
	}
	r.mu.Unlock()

	// Stale-term RequestVote (term 3 < 5) from candidate node-b.
	reqData, err := EncodeRequestVote(RequestVoteRequest{
		Term:         3,
		CandidateID:  "node-b",
		LastLogIndex: 0,
		LastLogTerm:  0,
	})
	if err != nil {
		t.Fatal(err)
	}
	respData, err := r.handleRequestVote(reqData)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := DecodeRequestVoteResp(respData)
	if err != nil {
		t.Fatal(err)
	}

	// §5.2: the vote must NOT be granted for a stale term.
	if resp.VoteGranted {
		t.Fatalf("FAIL: stale-term RequestVote (term 3 < currentTerm 5) was granted — §5.2 requires rejection")
	}
	if resp.Term != 5 {
		t.Fatalf("response term = %d, want current term 5", resp.Term)
	}

	// The stale grant must not burn the current term's vote: a legitimate
	// same-term candidate must still be able to win it.
	r.mu.Lock()
	voted := r.persist.VotedFor()
	r.mu.Unlock()
	if voted == "node-b" {
		t.Fatalf("FAIL: stale-term grant overwrote the current term's vote: votedFor=%q", voted)
	}

	// A legitimate same-term candidate must now be grantable (the vote was
	// never burned by the stale-term request).
	legitData, err := EncodeRequestVote(RequestVoteRequest{
		Term:         5,
		CandidateID:  "node-c",
		LastLogIndex: 1,
		LastLogTerm:  5,
	})
	if err != nil {
		t.Fatal(err)
	}
	legitRespData, err := r.handleRequestVote(legitData)
	if err != nil {
		t.Fatal(err)
	}
	legitResp, err := DecodeRequestVoteResp(legitRespData)
	if err != nil {
		t.Fatal(err)
	}
	if !legitResp.VoteGranted {
		t.Fatalf("FAIL: legitimate same-term RequestVote rejected (vote burned by stale grant): votedFor=%q", voted)
	}
}
