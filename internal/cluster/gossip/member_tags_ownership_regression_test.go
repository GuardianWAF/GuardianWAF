package gossip

import "testing"

func TestMemberListOwnsTagSnapshots(t *testing.T) {
	for _, mode := range []string{"input", "get", "all", "random", "replace"} {
		ml := NewMemberList("self")
		input := Member{ID: "one", Addr: "original", Incarnation: 1, Tags: []string{"stable"}}
		ml.Add(input)
		var snapshot Member
		switch mode {
		case "input":
			snapshot = input
		case "get", "replace":
			snapshot, _ = ml.Get("one")
		case "all":
			snapshot = ml.AllMembers()[0]
		case "random":
			snapshot, _ = ml.RandomMember("self")
		}
		release := make(chan struct{})
		done := make(chan struct{})
		go func() { <-release; snapshot.Tags[0] = "external"; snapshot.Addr = "external"; close(done) }()
		if mode == "replace" {
			replacement := snapshot
			replacement.Incarnation++
			ml.Add(replacement)
		}
		close(release)
		<-done
		got, _ := ml.Get("one")
		if got.Tags[0] != "stable" || got.Addr != "original" {
			t.Fatalf("%s changed stored member: %+v", mode, got)
		}
	}
	for _, tags := range [][]string{nil, {}} {
		ml := NewMemberList("self")
		ml.Add(Member{ID: "one", Tags: tags})
		got, _ := ml.Get("one")
		if len(got.Tags) != 0 {
			t.Fatal("empty tags changed")
		}
	}
	t.Log("FIX VERIFIED")
}
