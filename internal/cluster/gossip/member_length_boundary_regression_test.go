package gossip

import (
	"reflect"
	"strings"
	"testing"
)

func TestEncodeMembersChecksEveryFieldLength(t *testing.T) {
	for field := 0; field < 4; field++ {
		for _, size := range []int{0, 254, 255, 256, 257} {
			m := Member{ID: "test", Addr: "addr", RaftAddr: "raft", DashboardAddr: "dashboard", Incarnation: 1}
			v := strings.Repeat("a", size)
			switch field {
			case 0:
				m.ID = v
			case 1:
				m.Addr = v
			case 2:
				m.RaftAddr = v
			case 3:
				m.DashboardAddr = v
			}
			good := Member{ID: "neighbor"}
			got, err := DecodeMembers(EncodeMembers([]Member{good, m, good}))
			if err != nil {
				t.Fatal(err)
			}
			if size > 255 {
				if len(got) != 2 || got[0].ID != "neighbor" || got[1].ID != "neighbor" {
					t.Fatalf("field=%d size=%d got=%+v", field, size, got)
				}
			} else {
				if len(got) != 3 || !reflect.DeepEqual(got[1], m) {
					t.Fatalf("field=%d size=%d got=%+v", field, size, got)
				}
			}
		}
	}
	got, err := DecodeMembers(EncodeMembers(nil))
	if err != nil || len(got) != 0 {
		t.Fatal("empty roundtrip")
	}
	t.Log("FIX VERIFIED")
}
