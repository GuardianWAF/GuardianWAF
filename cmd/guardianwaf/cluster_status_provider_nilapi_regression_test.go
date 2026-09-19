package main

// Regression (bug-hunt round 2026-09-18-r2, closing the parked note from the
// 2026-09-16-round2 hunt): NewClusterStatusProvider documents that the api
// "may be nil for read-only providers", and every other documented-nilable
// field's nil-ness is handled (gossip in Peers/IsIsolated/MemberCount) —
// except the write path: ProposeBan/ProposeUnban dereferenced p.api
// unguarded, so calling either on the documented read-only configuration
// panicked with a nil pointer dereference instead of returning an error.
//
// The fix guards both writes with a dedicated sentinel that is deliberately
// NOT clustersync.ErrRaftNotLeader: the dashboard maps ErrRaftNotLeader to a
// 307 leader-redirect, and a read-only node has no leader to redirect to —
// a generic error (→ 503) is the honest response.

import (
	"testing"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/cluster/raft"
	"github.com/guardianwaf/guardianwaf/internal/clustersync"
)

// mustNotPanicNilAPI converts a nil-dereference panic into an explicit test
// failure, so the report shows the defect rather than a crashed binary.
func mustNotPanicNilAPI(t *testing.T, name string, fn func() error) error {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("FAIL: %s on a documented read-only provider (api == nil) panicked instead of returning an error: %v", name, r)
		}
	}()
	return fn()
}

func TestClusterStatusProvider_ProposeBan_ReadOnlyProviderReturnsError(t *testing.T) {
	// The constructor's own contract: api may be nil for read-only providers.
	p := NewClusterStatusProvider(nil, nil, nil, nil)

	err := mustNotPanicNilAPI(t, "ProposeBan", func() error {
		return p.ProposeBan("203.0.113.7", time.Minute)
	})
	if err == nil {
		t.Fatalf("FAIL: ProposeBan on a read-only provider returned nil — a cluster-wide ban cannot be proposed without the sync API; want a descriptive error")
	}
	if p.IsNotLeader(err) {
		t.Fatalf("FAIL: read-only ProposeBan error (%v) maps to not-leader — the dashboard would 307-redirect to a leader that does not exist; want a generic error (→ 503)", err)
	}
}

func TestClusterStatusProvider_ProposeUnban_ReadOnlyProviderReturnsError(t *testing.T) {
	p := NewClusterStatusProvider(nil, nil, nil, nil)

	err := mustNotPanicNilAPI(t, "ProposeUnban", func() error {
		return p.ProposeUnban("203.0.113.7")
	})
	if err == nil {
		t.Fatalf("FAIL: ProposeUnban on a read-only provider returned nil; want a descriptive error")
	}
	if p.IsNotLeader(err) {
		t.Fatalf("FAIL: read-only ProposeUnban error (%v) maps to not-leader; want a generic error", err)
	}
}

// Control: the not-leader mapping itself must stay intact — the sentinel
// returned for read-only providers must remain distinct from the errors the
// dashboard redirects on.
func TestClusterStatusProvider_IsNotLeader_Mapping(t *testing.T) {
	p := NewClusterStatusProvider(nil, nil, nil, nil)
	if !p.IsNotLeader(clustersync.ErrRaftNotLeader) {
		t.Fatalf("FAIL: harness control — clustersync.ErrRaftNotLeader must map to not-leader")
	}
	if !p.IsNotLeader(raft.ErrNotLeader) {
		t.Fatalf("FAIL: harness control — raft.ErrNotLeader must map to not-leader")
	}
}
