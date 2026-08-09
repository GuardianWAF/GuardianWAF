// Package gossip implements a SWIM-style membership protocol for cluster
// node discovery and failure detection. It uses UDP for probe/gossip messages
// and requires zero external dependencies (Go standard library only).
//
// The protocol lifecycle is: Alive → Suspect → Dead, governed by incarnation
// numbers. Each node probes one random member per interval (direct ping with
// indirect-ping fallback) and piggybacks state changes on every message.
package gossip

import (
	"fmt"
	"math/rand/v2"
	"sync"
)

// globalRand is the package-level RNG for member selection.
// rand.Rand is not safe for concurrent use — guard it with a mutex.
var (
	globalRandMu sync.Mutex
	globalRand   = rand.New(rand.NewPCG(1, 1))
)

func randIntN(n int) int {
	globalRandMu.Lock()
	defer globalRandMu.Unlock()
	return globalRand.IntN(n)
}

// MemberState represents the lifecycle state of a cluster member.
type MemberState uint8

const (
	StateAlive MemberState = iota
	StateSuspect
	StateDead
)

// String returns a human-readable state name.
func (s MemberState) String() string {
	switch s {
	case StateAlive:
		return "alive"
	case StateSuspect:
		return "suspect"
	case StateDead:
		return "dead"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// Member describes a single cluster node.
type Member struct {
	ID          string      `json:"id"`
	Addr        string      `json:"addr"`                // host:port for UDP gossip
	RaftAddr    string      `json:"raft_addr,omitempty"` // host:port for TCP Raft consensus
	Tags        []string    `json:"tags,omitempty"`
	Incarnation uint64      `json:"incarnation"`
	State       MemberState `json:"state"`
}

// memberEntry is the internal bookkeeping record.
type memberEntry struct {
	Member
	failureTimer int64 // unix timestamp when suspicion started (0 = not suspected)
}

// MemberList manages the local view of cluster membership.
// It is safe for concurrent use.
type MemberList struct {
	mu      sync.Mutex
	localID string
	members map[string]*memberEntry // keyed by Member.ID
}

// NewMemberList creates an empty member list with the given local node ID.
func NewMemberList(localID string) *MemberList {
	return &MemberList{
		localID: localID,
		members: make(map[string]*memberEntry),
	}
}

// Add inserts or updates a member. Returns true if the member is new.
// An update is accepted only if the incarnation is higher than the current one,
// or the incarnation is equal and the state has advanced (alive < suspect < dead).
func (ml *MemberList) Add(m Member) bool {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	if existing, ok := ml.members[m.ID]; ok {
		if shouldReplace(existing.Member, m) {
			existing.Member = m
			existing.failureTimer = 0
			return false
		}
		return false
	}

	ml.members[m.ID] = &memberEntry{Member: m}
	return true
}

// Get returns a copy of a member by ID, or ok=false if not present.
func (ml *MemberList) Get(id string) (Member, bool) {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	e, ok := ml.members[id]
	if !ok {
		return Member{}, false
	}
	return e.Member, true
}

// AliveMembers returns IDs of all non-dead members (alive + suspect).
func (ml *MemberList) AliveMembers() []string {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	var ids []string
	for id, e := range ml.members {
		if e.State != StateDead {
			ids = append(ids, id)
		}
	}
	return ids
}

// AllMembers returns copies of all known members.
func (ml *MemberList) AllMembers() []Member {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	result := make([]Member, 0, len(ml.members))
	for _, e := range ml.members {
		result = append(result, e.Member)
	}
	return result
}

// RandomMember returns a random alive member (excluding localID), or
// ok=false if none are available.
func (ml *MemberList) RandomMember(localID string) (Member, bool) {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	var candidates []*memberEntry
	for _, e := range ml.members {
		if e.ID != localID && e.State != StateDead {
			candidates = append(candidates, e)
		}
	}
	if len(candidates) == 0 {
		return Member{}, false
	}
	pick := candidates[randIntN(len(candidates))]
	return pick.Member, true
}

// MarkSuspect transitions a member to Suspect, bumping its failure timer.
func (ml *MemberList) MarkSuspect(id string) bool {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	e, ok := ml.members[id]
	if !ok {
		return false
	}
	if e.State == StateAlive {
		e.State = StateSuspect
		e.failureTimer++
		return true
	}
	e.failureTimer++
	return false
}

// MarkDead transitions a member to Dead.
func (ml *MemberList) MarkDead(id string) bool {
	ml.mu.Lock()
	defer ml.mu.Unlock()

	e, ok := ml.members[id]
	if !ok {
		return false
	}
	if e.State == StateDead {
		return false
	}
	e.State = StateDead
	return true
}

// Contains returns true if a member with the given ID exists.
func (ml *MemberList) Contains(id string) bool {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	_, ok := ml.members[id]
	return ok
}

// Len returns the number of known members (including dead).
func (ml *MemberList) Len() int {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	return len(ml.members)
}

// PurgeDead removes all dead members from the list and returns the count removed.
func (ml *MemberList) PurgeDead() int {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	n := 0
	for id, e := range ml.members {
		if e.State == StateDead {
			delete(ml.members, id)
			n++
		}
	}
	return n
}

// shouldReplace decides whether `incoming` should replace `existing` in the
// member list. The rule is incarnation-based: a higher incarnation always wins;
// at equal incarnation, a more advanced state wins (suspect > alive, dead > suspect).
func shouldReplace(existing, incoming Member) bool {
	if incoming.Incarnation > existing.Incarnation {
		return true
	}
	if incoming.Incarnation < existing.Incarnation {
		return false
	}
	// Same incarnation — state advancement wins.
	return incoming.State > existing.State
}
