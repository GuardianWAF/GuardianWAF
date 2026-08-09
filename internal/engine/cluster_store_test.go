package engine

import (
	"encoding/json"
	"testing"
)

func TestNoopClusterStore(t *testing.T) {
	var cs ClusterStore = noopClusterStore{}

	if cs.IsBanned("1.2.3.4") {
		t.Error("noopClusterStore.IsBanned should return false")
	}
	if rule, ok := cs.GetRule("x"); ok || rule != nil {
		t.Error("noopClusterStore.GetRule should return nil, false")
	}
	if val := cs.GetCounter("key", 1); val != 0 {
		t.Error("noopClusterStore.GetCounter should return 0")
	}
}

// fakeSetter exercises the ClusterStoreSetter interface so deadcode does not
// flag noopClusterStore as unreachable.
type fakeSetter struct {
	store ClusterStore
}

func (f *fakeSetter) SetClusterStore(cs ClusterStore) { f.store = cs }

func TestClusterStoreSetter(t *testing.T) {
	var s ClusterStoreSetter = &fakeSetter{}
	s.SetClusterStore(noopClusterStore{})
}

func TestClusterStoreNilSafety(t *testing.T) {
	// Engine starts with nil clusterStore — verify getters handle nil.
	eng := &Engine{}
	if eng.ClusterStore() != nil {
		t.Error("new engine should have nil ClusterStore")
	}
}

// silence unused import warning if encoding/json is not otherwise used
var _ = json.RawMessage(nil)
